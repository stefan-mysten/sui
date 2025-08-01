// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    cmp::max,
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::Bound::{Excluded, Included, Unbounded},
    panic,
    sync::Arc,
    time::Duration,
    vec,
};

use consensus_config::AuthorityIndex;
use consensus_types::block::{BlockDigest, BlockRef, BlockTimestampMs, Round, TransactionIndex};
use itertools::Itertools as _;
use tokio::time::Instant;
use tracing::{debug, error, info, trace};

use crate::{
    block::{genesis_blocks, BlockAPI, Slot, VerifiedBlock, GENESIS_ROUND},
    commit::{
        load_committed_subdag_from_store, CommitAPI as _, CommitDigest, CommitIndex, CommitInfo,
        CommitRef, CommitVote, TrustedCommit, GENESIS_COMMIT_INDEX,
    },
    context::Context,
    leader_scoring::{ReputationScores, ScoringSubdag},
    storage::{Store, WriteBatch},
    threshold_clock::ThresholdClock,
    CommittedSubDag,
};

/// DagState provides the API to write and read accepted blocks from the DAG.
/// Only uncommitted and last committed blocks are cached in memory.
/// The rest of blocks are stored on disk.
/// Refs to cached blocks and additional refs are cached as well, to speed up existence checks.
///
/// Note: DagState should be wrapped with Arc<parking_lot::RwLock<_>>, to allow
/// concurrent access from multiple components.
pub struct DagState {
    context: Arc<Context>,

    // The genesis blocks
    genesis: BTreeMap<BlockRef, VerifiedBlock>,

    // Contains recent blocks within CACHED_ROUNDS from the last committed round per authority.
    // Note: all uncommitted blocks are kept in memory.
    //
    // When GC is enabled, this map has a different semantic. It holds all the recent data for each authority making sure that it always have available
    // CACHED_ROUNDS worth of data. The entries are evicted based on the latest GC round, however the eviction process will respect the CACHED_ROUNDS.
    // For each authority, blocks are only evicted when their round is less than or equal to both `gc_round`, and `highest authority round - cached rounds`.
    // This ensures that the GC requirements are respected (we never clean up any block above `gc_round`), and there are enough blocks cached.
    recent_blocks: BTreeMap<BlockRef, BlockInfo>,

    // Indexes recent block refs by their authorities.
    // Vec position corresponds to the authority index.
    recent_refs_by_authority: Vec<BTreeSet<BlockRef>>,

    // Keeps track of the threshold clock for proposing blocks.
    threshold_clock: ThresholdClock,

    // Keeps track of the highest round that has been evicted for each authority. Any blocks that are of round <= evict_round
    // should be considered evicted, and if any exist we should not consider the causauly complete in the order they appear.
    // The `evicted_rounds` size should be the same as the committee size.
    evicted_rounds: Vec<Round>,

    // Highest round of blocks accepted.
    highest_accepted_round: Round,

    // Last consensus commit of the dag.
    last_commit: Option<TrustedCommit>,

    // Last wall time when commit round advanced. Does not persist across restarts.
    last_commit_round_advancement_time: Option<std::time::Instant>,

    // Last committed rounds per authority.
    last_committed_rounds: Vec<Round>,

    /// The committed subdags that have been scored but scores have not been used
    /// for leader schedule yet.
    scoring_subdag: ScoringSubdag,

    // Commit votes pending to be included in new blocks.
    // TODO: limit to 1st commit per round with multi-leader.
    // TODO: recover unproposed pending commit votes at startup.
    pending_commit_votes: VecDeque<CommitVote>,

    // Blocks and commits must be buffered for persistence before they can be
    // inserted into the local DAG or sent to output.
    blocks_to_write: Vec<VerifiedBlock>,
    commits_to_write: Vec<TrustedCommit>,

    // Buffers the reputation scores & last_committed_rounds to be flushed with the
    // next dag state flush. Not writing eagerly is okay because we can recover reputation scores
    // & last_committed_rounds from the commits as needed.
    commit_info_to_write: Vec<(CommitRef, CommitInfo)>,

    // Buffers finalized commits and their rejected transactions to be written to storage.
    finalized_commits_to_write: Vec<(CommitRef, BTreeMap<BlockRef, Vec<TransactionIndex>>)>,

    // Persistent storage for blocks, commits and other consensus data.
    store: Arc<dyn Store>,

    // The number of cached rounds
    cached_rounds: Round,
}

impl DagState {
    /// Initializes DagState from storage.
    pub fn new(context: Arc<Context>, store: Arc<dyn Store>) -> Self {
        let cached_rounds = context.parameters.dag_state_cached_rounds as Round;
        let num_authorities = context.committee.size();

        let genesis = genesis_blocks(context.as_ref())
            .into_iter()
            .map(|block| (block.reference(), block))
            .collect();

        let threshold_clock = ThresholdClock::new(1, context.clone());

        let last_commit = store
            .read_last_commit()
            .unwrap_or_else(|e| panic!("Failed to read from storage: {:?}", e));

        let commit_info = store
            .read_last_commit_info()
            .unwrap_or_else(|e| panic!("Failed to read from storage: {:?}", e));
        let (mut last_committed_rounds, commit_recovery_start_index) =
            if let Some((commit_ref, commit_info)) = commit_info {
                tracing::info!("Recovering committed state from {commit_ref} {commit_info:?}");
                (commit_info.committed_rounds, commit_ref.index + 1)
            } else {
                tracing::info!("Found no stored CommitInfo to recover from");
                (vec![0; num_authorities], GENESIS_COMMIT_INDEX + 1)
            };

        let mut unscored_committed_subdags = Vec::new();
        let mut scoring_subdag = ScoringSubdag::new(context.clone());

        if let Some(last_commit) = last_commit.as_ref() {
            store
                .scan_commits((commit_recovery_start_index..=last_commit.index()).into())
                .unwrap_or_else(|e| panic!("Failed to read from storage: {:?}", e))
                .iter()
                .for_each(|commit| {
                    for block_ref in commit.blocks() {
                        last_committed_rounds[block_ref.author] =
                            max(last_committed_rounds[block_ref.author], block_ref.round);
                    }
                    let committed_subdag =
                        load_committed_subdag_from_store(store.as_ref(), commit.clone(), vec![]);
                    // We don't need to recover reputation scores for unscored_committed_subdags
                    unscored_committed_subdags.push(committed_subdag);
                });
        }

        tracing::info!(
            "DagState was initialized with the following state: \
            {last_commit:?}; {last_committed_rounds:?}; {} unscored committed subdags;",
            unscored_committed_subdags.len()
        );

        scoring_subdag.add_subdags(std::mem::take(&mut unscored_committed_subdags));

        let mut state = Self {
            context: context.clone(),
            genesis,
            recent_blocks: BTreeMap::new(),
            recent_refs_by_authority: vec![BTreeSet::new(); num_authorities],
            threshold_clock,
            highest_accepted_round: 0,
            last_commit: last_commit.clone(),
            last_commit_round_advancement_time: None,
            last_committed_rounds: last_committed_rounds.clone(),
            pending_commit_votes: VecDeque::new(),
            blocks_to_write: vec![],
            commits_to_write: vec![],
            commit_info_to_write: vec![],
            finalized_commits_to_write: vec![],
            scoring_subdag,
            store: store.clone(),
            cached_rounds,
            evicted_rounds: vec![0; num_authorities],
        };

        for (authority_index, _) in context.committee.authorities() {
            let (blocks, eviction_round) = {
                // Find the latest block for the authority to calculate the eviction round. Then we want to scan and load the blocks from the eviction round and onwards only.
                // As reminder, the eviction round is taking into account the gc_round.
                let last_block = state
                    .store
                    .scan_last_blocks_by_author(authority_index, 1, None)
                    .expect("Database error");
                let last_block_round = last_block
                    .last()
                    .map(|b| b.round())
                    .unwrap_or(GENESIS_ROUND);

                let eviction_round =
                    Self::eviction_round(last_block_round, state.gc_round(), state.cached_rounds);
                let blocks = state
                    .store
                    .scan_blocks_by_author(authority_index, eviction_round + 1)
                    .expect("Database error");

                (blocks, eviction_round)
            };

            state.evicted_rounds[authority_index] = eviction_round;

            // Update the block metadata for the authority.
            for block in &blocks {
                state.update_block_metadata(block);
            }

            debug!(
                "Recovered blocks {}: {:?}",
                authority_index,
                blocks
                    .iter()
                    .map(|b| b.reference())
                    .collect::<Vec<BlockRef>>()
            );
        }

        if let Some(last_commit) = last_commit {
            let mut index = last_commit.index();
            let gc_round = state.gc_round();
            info!("Recovering block commit statuses from commit index {} and backwards until leader of round <= gc_round {:?}", index, gc_round);

            loop {
                let commits = store
                    .scan_commits((index..=index).into())
                    .unwrap_or_else(|e| panic!("Failed to read from storage: {:?}", e));
                let Some(commit) = commits.first() else {
                    info!("Recovering finished up to index {index}, no more commits to recover");
                    break;
                };

                // Check the commit leader round to see if it is within the gc_round. If it is not then we can stop the recovery process.
                if gc_round > 0 && commit.leader().round <= gc_round {
                    info!(
                        "Recovering finished, reached commit leader round {} <= gc_round {}",
                        commit.leader().round,
                        gc_round
                    );
                    break;
                }

                commit.blocks().iter().filter(|b| b.round > gc_round).for_each(|block_ref|{
                    debug!(
                        "Setting block {:?} as committed based on commit {:?}",
                        block_ref,
                        commit.index()
                    );
                    assert!(state.set_committed(block_ref), "Attempted to set again a block {:?} as committed when recovering commit {:?}", block_ref, commit);
                });

                // All commits are indexed starting from 1, so one reach zero exit.
                index = index.saturating_sub(1);
                if index == 0 {
                    break;
                }
            }
        }

        // Recover hard linked statuses for blocks within GC round.
        let proposed_blocks = store
            .scan_blocks_by_author(context.own_index, state.gc_round() + 1)
            .expect("Database error");
        for block in proposed_blocks {
            state.link_causal_history(block.reference());
        }

        state
    }

    /// Accepts a block into DagState and keeps it in memory.
    pub(crate) fn accept_block(&mut self, block: VerifiedBlock) {
        assert_ne!(
            block.round(),
            0,
            "Genesis block should not be accepted into DAG."
        );

        let block_ref = block.reference();
        if self.contains_block(&block_ref) {
            return;
        }

        let now = self.context.clock.timestamp_utc_ms();
        if block.timestamp_ms() > now {
            trace!(
                "Block {:?} with timestamp {} is greater than local timestamp {}.",
                block,
                block.timestamp_ms(),
                now,
            );
        }
        let hostname = &self.context.committee.authority(block_ref.author).hostname;
        self.context
            .metrics
            .node_metrics
            .accepted_block_time_drift_ms
            .with_label_values(&[hostname])
            .inc_by(block.timestamp_ms().saturating_sub(now));

        // TODO: Move this check to core
        // Ensure we don't write multiple blocks per slot for our own index
        if block_ref.author == self.context.own_index {
            let existing_blocks = self.get_uncommitted_blocks_at_slot(block_ref.into());
            assert!(
                existing_blocks.is_empty(),
                "Block Rejected! Attempted to add block {block:#?} to own slot where \
                block(s) {existing_blocks:#?} already exists."
            );
        }
        self.update_block_metadata(&block);
        self.blocks_to_write.push(block);
        let source = if self.context.own_index == block_ref.author {
            "own"
        } else {
            "others"
        };
        self.context
            .metrics
            .node_metrics
            .accepted_blocks
            .with_label_values(&[source])
            .inc();
    }

    /// Updates internal metadata for a block.
    fn update_block_metadata(&mut self, block: &VerifiedBlock) {
        let block_ref = block.reference();
        self.recent_blocks
            .insert(block_ref, BlockInfo::new(block.clone()));
        self.recent_refs_by_authority[block_ref.author].insert(block_ref);

        if self.threshold_clock.add_block(block_ref) {
            // Do not measure quorum delay when no local block is proposed in the round.
            let last_proposed_block = self.get_last_proposed_block();
            if last_proposed_block.round() == block_ref.round {
                let quorum_delay_ms = self
                    .context
                    .clock
                    .timestamp_utc_ms()
                    .saturating_sub(self.get_last_proposed_block().timestamp_ms());
                self.context
                    .metrics
                    .node_metrics
                    .quorum_receive_latency
                    .observe(Duration::from_millis(quorum_delay_ms).as_secs_f64());
            }
        }

        self.highest_accepted_round = max(self.highest_accepted_round, block.round());
        self.context
            .metrics
            .node_metrics
            .highest_accepted_round
            .set(self.highest_accepted_round as i64);

        let highest_accepted_round_for_author = self.recent_refs_by_authority[block_ref.author]
            .last()
            .map(|block_ref| block_ref.round)
            .expect("There should be by now at least one block ref");
        let hostname = &self.context.committee.authority(block_ref.author).hostname;
        self.context
            .metrics
            .node_metrics
            .highest_accepted_authority_round
            .with_label_values(&[hostname])
            .set(highest_accepted_round_for_author as i64);
    }

    /// Accepts a blocks into DagState and keeps it in memory.
    pub(crate) fn accept_blocks(&mut self, blocks: Vec<VerifiedBlock>) {
        debug!(
            "Accepting blocks: {}",
            blocks.iter().map(|b| b.reference().to_string()).join(",")
        );
        for block in blocks {
            self.accept_block(block);
        }
    }

    /// Gets a block by checking cached recent blocks then storage.
    /// Returns None when the block is not found.
    pub(crate) fn get_block(&self, reference: &BlockRef) -> Option<VerifiedBlock> {
        self.get_blocks(&[*reference])
            .pop()
            .expect("Exactly one element should be returned")
    }

    /// Gets blocks by checking genesis, cached recent blocks in memory, then storage.
    /// An element is None when the corresponding block is not found.
    pub(crate) fn get_blocks(&self, block_refs: &[BlockRef]) -> Vec<Option<VerifiedBlock>> {
        let mut blocks = vec![None; block_refs.len()];
        let mut missing = Vec::new();

        for (index, block_ref) in block_refs.iter().enumerate() {
            if block_ref.round == GENESIS_ROUND {
                // Allow the caller to handle the invalid genesis ancestor error.
                if let Some(block) = self.genesis.get(block_ref) {
                    blocks[index] = Some(block.clone());
                }
                continue;
            }
            if let Some(block_info) = self.recent_blocks.get(block_ref) {
                blocks[index] = Some(block_info.block.clone());
                continue;
            }
            missing.push((index, block_ref));
        }

        if missing.is_empty() {
            return blocks;
        }

        let missing_refs = missing
            .iter()
            .map(|(_, block_ref)| **block_ref)
            .collect::<Vec<_>>();
        let store_results = self
            .store
            .read_blocks(&missing_refs)
            .unwrap_or_else(|e| panic!("Failed to read from storage: {:?}", e));
        self.context
            .metrics
            .node_metrics
            .dag_state_store_read_count
            .with_label_values(&["get_blocks"])
            .inc();

        for ((index, _), result) in missing.into_iter().zip(store_results.into_iter()) {
            blocks[index] = result;
        }

        blocks
    }

    /// Gets all uncommitted blocks in a slot.
    /// Uncommitted blocks must exist in memory, so only in-memory blocks are checked.
    pub(crate) fn get_uncommitted_blocks_at_slot(&self, slot: Slot) -> Vec<VerifiedBlock> {
        // TODO: either panic below when the slot is at or below the last committed round,
        // or support reading from storage while limiting storage reads to edge cases.

        let mut blocks = vec![];
        for (_block_ref, block_info) in self.recent_blocks.range((
            Included(BlockRef::new(slot.round, slot.authority, BlockDigest::MIN)),
            Included(BlockRef::new(slot.round, slot.authority, BlockDigest::MAX)),
        )) {
            blocks.push(block_info.block.clone())
        }
        blocks
    }

    /// Gets all uncommitted blocks in a round.
    /// Uncommitted blocks must exist in memory, so only in-memory blocks are checked.
    pub(crate) fn get_uncommitted_blocks_at_round(&self, round: Round) -> Vec<VerifiedBlock> {
        if round <= self.last_commit_round() {
            panic!("Round {} have committed blocks!", round);
        }

        let mut blocks = vec![];
        for (_block_ref, block_info) in self.recent_blocks.range((
            Included(BlockRef::new(round, AuthorityIndex::ZERO, BlockDigest::MIN)),
            Excluded(BlockRef::new(
                round + 1,
                AuthorityIndex::ZERO,
                BlockDigest::MIN,
            )),
        )) {
            blocks.push(block_info.block.clone())
        }
        blocks
    }

    /// Gets all ancestors in the history of a block at a certain round.
    pub(crate) fn ancestors_at_round(
        &self,
        later_block: &VerifiedBlock,
        earlier_round: Round,
    ) -> Vec<VerifiedBlock> {
        // Iterate through ancestors of later_block in round descending order.
        let mut linked: BTreeSet<BlockRef> = later_block.ancestors().iter().cloned().collect();
        while !linked.is_empty() {
            let round = linked.last().unwrap().round;
            // Stop after finishing traversal for ancestors above earlier_round.
            if round <= earlier_round {
                break;
            }
            let block_ref = linked.pop_last().unwrap();
            let Some(block) = self.get_block(&block_ref) else {
                panic!("Block {:?} should exist in DAG!", block_ref);
            };
            linked.extend(block.ancestors().iter().cloned());
        }
        linked
            .range((
                Included(BlockRef::new(
                    earlier_round,
                    AuthorityIndex::ZERO,
                    BlockDigest::MIN,
                )),
                Unbounded,
            ))
            .map(|r| {
                self.get_block(r)
                    .unwrap_or_else(|| panic!("Block {:?} should exist in DAG!", r))
                    .clone()
            })
            .collect()
    }

    /// Gets the last proposed block from this authority.
    /// If no block is proposed yet, returns the genesis block.
    pub(crate) fn get_last_proposed_block(&self) -> VerifiedBlock {
        self.get_last_block_for_authority(self.context.own_index)
    }

    /// Retrieves the last accepted block from the specified `authority`. If no block is found in cache
    /// then the genesis block is returned as no other block has been received from that authority.
    pub(crate) fn get_last_block_for_authority(&self, authority: AuthorityIndex) -> VerifiedBlock {
        if let Some(last) = self.recent_refs_by_authority[authority].last() {
            return self
                .recent_blocks
                .get(last)
                .expect("Block should be found in recent blocks")
                .block
                .clone();
        }

        // if none exists, then fallback to genesis
        let (_, genesis_block) = self
            .genesis
            .iter()
            .find(|(block_ref, _)| block_ref.author == authority)
            .expect("Genesis should be found for authority {authority_index}");
        genesis_block.clone()
    }

    /// Returns cached recent blocks from the specified authority.
    /// Blocks returned are limited to round >= `start`, and cached.
    /// NOTE: caller should not assume returned blocks are always chained.
    /// "Disconnected" blocks can be returned when there are byzantine blocks,
    /// or a previously evicted block is accepted again.
    pub(crate) fn get_cached_blocks(
        &self,
        authority: AuthorityIndex,
        start: Round,
    ) -> Vec<VerifiedBlock> {
        self.get_cached_blocks_in_range(authority, start, Round::MAX, usize::MAX)
    }

    // Retrieves the cached block within the range [start_round, end_round) from a given authority,
    // limited in total number of blocks.
    pub(crate) fn get_cached_blocks_in_range(
        &self,
        authority: AuthorityIndex,
        start_round: Round,
        end_round: Round,
        limit: usize,
    ) -> Vec<VerifiedBlock> {
        if start_round >= end_round || limit == 0 {
            return vec![];
        }

        let mut blocks = vec![];
        for block_ref in self.recent_refs_by_authority[authority].range((
            Included(BlockRef::new(start_round, authority, BlockDigest::MIN)),
            Excluded(BlockRef::new(
                end_round,
                AuthorityIndex::MIN,
                BlockDigest::MIN,
            )),
        )) {
            let block_info = self
                .recent_blocks
                .get(block_ref)
                .expect("Block should exist in recent blocks");
            blocks.push(block_info.block.clone());
            if blocks.len() >= limit {
                break;
            }
        }
        blocks
    }

    // Retrieves the last cached block within the range [start_round, end_round) from a given authority.
    pub(crate) fn get_last_cached_block_in_range(
        &self,
        authority: AuthorityIndex,
        start_round: Round,
        end_round: Round,
    ) -> Option<VerifiedBlock> {
        if start_round >= end_round {
            return None;
        }

        let block_ref = self.recent_refs_by_authority[authority]
            .range((
                Included(BlockRef::new(start_round, authority, BlockDigest::MIN)),
                Excluded(BlockRef::new(
                    end_round,
                    AuthorityIndex::MIN,
                    BlockDigest::MIN,
                )),
            ))
            .last()?;

        self.recent_blocks
            .get(block_ref)
            .map(|block_info| block_info.block.clone())
    }

    /// Returns the last block proposed per authority with `evicted round < round < end_round`.
    /// The method is guaranteed to return results only when the `end_round` is not earlier of the
    /// available cached data for each authority (evicted round + 1), otherwise the method will panic.
    /// It's the caller's responsibility to ensure that is not requesting for earlier rounds.
    /// In case of equivocation for an authority's last slot, one block will be returned (the last in order)
    /// and the other equivocating blocks will be returned.
    pub(crate) fn get_last_cached_block_per_authority(
        &self,
        end_round: Round,
    ) -> Vec<(VerifiedBlock, Vec<BlockRef>)> {
        // Initialize with the genesis blocks as fallback
        let mut blocks = self.genesis.values().cloned().collect::<Vec<_>>();
        let mut equivocating_blocks = vec![vec![]; self.context.committee.size()];

        if end_round == GENESIS_ROUND {
            panic!(
                "Attempted to retrieve blocks earlier than the genesis round which is not possible"
            );
        }

        if end_round == GENESIS_ROUND + 1 {
            return blocks.into_iter().map(|b| (b, vec![])).collect();
        }

        for (authority_index, block_refs) in self.recent_refs_by_authority.iter().enumerate() {
            let authority_index = self
                .context
                .committee
                .to_authority_index(authority_index)
                .unwrap();

            let last_evicted_round = self.evicted_rounds[authority_index];
            if end_round.saturating_sub(1) <= last_evicted_round {
                panic!("Attempted to request for blocks of rounds < {end_round}, when the last evicted round is {last_evicted_round} for authority {authority_index}", );
            }

            let block_ref_iter = block_refs
                .range((
                    Included(BlockRef::new(
                        last_evicted_round + 1,
                        authority_index,
                        BlockDigest::MIN,
                    )),
                    Excluded(BlockRef::new(end_round, authority_index, BlockDigest::MIN)),
                ))
                .rev();

            let mut last_round = 0;
            for block_ref in block_ref_iter {
                if last_round == 0 {
                    last_round = block_ref.round;
                    let block_info = self
                        .recent_blocks
                        .get(block_ref)
                        .expect("Block should exist in recent blocks");
                    blocks[authority_index] = block_info.block.clone();
                    continue;
                }
                if block_ref.round < last_round {
                    break;
                }
                equivocating_blocks[authority_index].push(*block_ref);
            }
        }

        blocks.into_iter().zip(equivocating_blocks).collect()
    }

    /// Checks whether a block exists in the slot. The method checks only against the cached data.
    /// If the user asks for a slot that is not within the cached data then a panic is thrown.
    pub(crate) fn contains_cached_block_at_slot(&self, slot: Slot) -> bool {
        // Always return true for genesis slots.
        if slot.round == GENESIS_ROUND {
            return true;
        }

        let eviction_round = self.evicted_rounds[slot.authority];
        if slot.round <= eviction_round {
            panic!("{}", format!("Attempted to check for slot {slot} that is <= the last evicted round {eviction_round}"));
        }

        let mut result = self.recent_refs_by_authority[slot.authority].range((
            Included(BlockRef::new(slot.round, slot.authority, BlockDigest::MIN)),
            Included(BlockRef::new(slot.round, slot.authority, BlockDigest::MAX)),
        ));
        result.next().is_some()
    }

    /// Checks whether the required blocks are in cache, if exist, or otherwise will check in store. The method is not caching
    /// back the results, so its expensive if keep asking for cache missing blocks.
    pub(crate) fn contains_blocks(&self, block_refs: Vec<BlockRef>) -> Vec<bool> {
        let mut exist = vec![false; block_refs.len()];
        let mut missing = Vec::new();

        for (index, block_ref) in block_refs.into_iter().enumerate() {
            let recent_refs = &self.recent_refs_by_authority[block_ref.author];
            if recent_refs.contains(&block_ref) || self.genesis.contains_key(&block_ref) {
                exist[index] = true;
            } else if recent_refs.is_empty() || recent_refs.last().unwrap().round < block_ref.round
            {
                // Optimization: recent_refs contain the most recent blocks known to this authority.
                // If a block ref is not found there and has a higher round, it definitely is
                // missing from this authority and there is no need to check disk.
                exist[index] = false;
            } else {
                missing.push((index, block_ref));
            }
        }

        if missing.is_empty() {
            return exist;
        }

        let missing_refs = missing
            .iter()
            .map(|(_, block_ref)| *block_ref)
            .collect::<Vec<_>>();
        let store_results = self
            .store
            .contains_blocks(&missing_refs)
            .unwrap_or_else(|e| panic!("Failed to read from storage: {:?}", e));
        self.context
            .metrics
            .node_metrics
            .dag_state_store_read_count
            .with_label_values(&["contains_blocks"])
            .inc();

        for ((index, _), result) in missing.into_iter().zip(store_results.into_iter()) {
            exist[index] = result;
        }

        exist
    }

    pub(crate) fn contains_block(&self, block_ref: &BlockRef) -> bool {
        let blocks = self.contains_blocks(vec![*block_ref]);
        blocks.first().cloned().unwrap()
    }

    // Sets the block as committed in the cache. If the block is set as committed for first time, then true is returned, otherwise false is returned instead.
    // Method will panic if the block is not found in the cache.
    pub(crate) fn set_committed(&mut self, block_ref: &BlockRef) -> bool {
        if let Some(block_info) = self.recent_blocks.get_mut(block_ref) {
            if !block_info.committed {
                block_info.committed = true;
                return true;
            }
            false
        } else {
            panic!(
                "Block {:?} not found in cache to set as committed.",
                block_ref
            );
        }
    }

    /// Returns true if the block is committed. Only valid for blocks above the GC round.
    pub(crate) fn is_committed(&self, block_ref: &BlockRef) -> bool {
        self.recent_blocks
            .get(block_ref)
            .unwrap_or_else(|| panic!("Attempted to query for commit status for a block not in cached data {block_ref}"))
            .committed
    }

    /// Recursively sets blocks in the causal history of the root block as hard linked, including the root block itself.
    /// Returns the list of blocks that are newly linked.
    /// The returned blocks are guaranteed to be above the GC round.
    pub(crate) fn link_causal_history(&mut self, root_block: BlockRef) -> Vec<BlockRef> {
        let gc_round = self.gc_round();
        let mut linked_blocks = vec![];
        let mut targets = VecDeque::new();
        targets.push_back(root_block);
        while let Some(block_ref) = targets.pop_front() {
            // This is only correct with GC enabled.
            if block_ref.round <= gc_round {
                continue;
            }
            let block_info = self
                .recent_blocks
                .get_mut(&block_ref)
                .unwrap_or_else(|| panic!("Block {:?} is not in DAG state", block_ref));
            if block_info.hard_linked {
                continue;
            }
            linked_blocks.push(block_ref);
            block_info.hard_linked = true;
            targets.extend(block_info.block.ancestors().iter());
        }
        linked_blocks
    }

    /// Returns true if the block is hard linked by a proposed block.
    pub(crate) fn is_hard_linked(&self, block_ref: &BlockRef) -> bool {
        self.recent_blocks
            .get(block_ref)
            .unwrap_or_else(|| panic!("Attempted to query for hard link status for a block not in cached data {block_ref}"))
            .hard_linked
    }

    pub(crate) fn threshold_clock_round(&self) -> Round {
        self.threshold_clock.get_round()
    }

    // The timestamp of when quorum threshold was last reached in the threshold clock.
    pub(crate) fn threshold_clock_quorum_ts(&self) -> Instant {
        self.threshold_clock.get_quorum_ts()
    }

    pub(crate) fn highest_accepted_round(&self) -> Round {
        self.highest_accepted_round
    }

    // Buffers a new commit in memory and updates last committed rounds.
    // REQUIRED: must not skip over any commit index.
    pub(crate) fn add_commit(&mut self, commit: TrustedCommit) {
        let time_diff = if let Some(last_commit) = &self.last_commit {
            if commit.index() <= last_commit.index() {
                error!(
                    "New commit index {} <= last commit index {}!",
                    commit.index(),
                    last_commit.index()
                );
                return;
            }
            assert_eq!(commit.index(), last_commit.index() + 1);

            if commit.timestamp_ms() < last_commit.timestamp_ms() {
                panic!("Commit timestamps do not monotonically increment, prev commit {:?}, new commit {:?}", last_commit, commit);
            }
            commit
                .timestamp_ms()
                .saturating_sub(last_commit.timestamp_ms())
        } else {
            assert_eq!(commit.index(), 1);
            0
        };

        self.context
            .metrics
            .node_metrics
            .last_commit_time_diff
            .observe(time_diff as f64);

        let commit_round_advanced = if let Some(previous_commit) = &self.last_commit {
            previous_commit.round() < commit.round()
        } else {
            true
        };

        self.last_commit = Some(commit.clone());

        if commit_round_advanced {
            let now = std::time::Instant::now();
            if let Some(previous_time) = self.last_commit_round_advancement_time {
                self.context
                    .metrics
                    .node_metrics
                    .commit_round_advancement_interval
                    .observe(now.duration_since(previous_time).as_secs_f64())
            }
            self.last_commit_round_advancement_time = Some(now);
        }

        for block_ref in commit.blocks().iter() {
            self.last_committed_rounds[block_ref.author] = max(
                self.last_committed_rounds[block_ref.author],
                block_ref.round,
            );
        }

        for (i, round) in self.last_committed_rounds.iter().enumerate() {
            let index = self.context.committee.to_authority_index(i).unwrap();
            let hostname = &self.context.committee.authority(index).hostname;
            self.context
                .metrics
                .node_metrics
                .last_committed_authority_round
                .with_label_values(&[hostname])
                .set((*round).into());
        }

        self.pending_commit_votes.push_back(commit.reference());
        self.commits_to_write.push(commit);
    }

    /// Recovers commits to write from storage, at startup.
    pub(crate) fn recover_commits_to_write(&mut self, commits: Vec<TrustedCommit>) {
        self.commits_to_write.extend(commits);
    }

    pub(crate) fn ensure_commits_to_write_is_empty(&self) {
        assert!(
            self.commits_to_write.is_empty(),
            "Commits to write should be empty. {:?}",
            self.commits_to_write,
        );
    }

    pub(crate) fn add_commit_info(&mut self, reputation_scores: ReputationScores) {
        // We create an empty scoring subdag once reputation scores are calculated.
        // Note: It is okay for this to not be gated by protocol config as the
        // scoring_subdag should be empty in either case at this point.
        assert!(self.scoring_subdag.is_empty());

        let commit_info = CommitInfo {
            committed_rounds: self.last_committed_rounds.clone(),
            reputation_scores,
        };
        let last_commit = self
            .last_commit
            .as_ref()
            .expect("Last commit should already be set.");
        self.commit_info_to_write
            .push((last_commit.reference(), commit_info));
    }

    pub(crate) fn add_finalized_commit(
        &mut self,
        commit_ref: CommitRef,
        rejected_transactions: BTreeMap<BlockRef, Vec<TransactionIndex>>,
    ) {
        self.finalized_commits_to_write
            .push((commit_ref, rejected_transactions));
    }

    pub(crate) fn take_commit_votes(&mut self, limit: usize) -> Vec<CommitVote> {
        let mut votes = Vec::new();
        while !self.pending_commit_votes.is_empty() && votes.len() < limit {
            votes.push(self.pending_commit_votes.pop_front().unwrap());
        }
        votes
    }

    /// Index of the last commit.
    pub(crate) fn last_commit_index(&self) -> CommitIndex {
        match &self.last_commit {
            Some(commit) => commit.index(),
            None => 0,
        }
    }

    /// Digest of the last commit.
    pub(crate) fn last_commit_digest(&self) -> CommitDigest {
        match &self.last_commit {
            Some(commit) => commit.digest(),
            None => CommitDigest::MIN,
        }
    }

    /// Timestamp of the last commit.
    pub(crate) fn last_commit_timestamp_ms(&self) -> BlockTimestampMs {
        match &self.last_commit {
            Some(commit) => commit.timestamp_ms(),
            None => 0,
        }
    }

    /// Leader slot of the last commit.
    pub(crate) fn last_commit_leader(&self) -> Slot {
        match &self.last_commit {
            Some(commit) => commit.leader().into(),
            None => self
                .genesis
                .iter()
                .next()
                .map(|(genesis_ref, _)| *genesis_ref)
                .expect("Genesis blocks should always be available.")
                .into(),
        }
    }

    /// Highest round where a block is committed, which is last commit's leader round.
    pub(crate) fn last_commit_round(&self) -> Round {
        match &self.last_commit {
            Some(commit) => commit.leader().round,
            None => 0,
        }
    }

    /// Last committed round per authority.
    pub(crate) fn last_committed_rounds(&self) -> Vec<Round> {
        self.last_committed_rounds.clone()
    }

    /// The GC round is the highest round that blocks of equal or lower round are considered obsolete and no longer possible to be committed.
    /// There is no meaning accepting any blocks with round <= gc_round. The Garbage Collection (GC) round is calculated based on the latest
    /// committed leader round. When GC is disabled that will return the genesis round.
    pub(crate) fn gc_round(&self) -> Round {
        self.calculate_gc_round(self.last_commit_round())
    }

    /// Calculates the GC round from the input leader round, which can be different
    /// from the last committed leader round.
    pub(crate) fn calculate_gc_round(&self, commit_round: Round) -> Round {
        commit_round.saturating_sub(self.context.protocol_config.gc_depth())
    }

    /// Flushes unpersisted blocks, commits and commit info to storage.
    ///
    /// REQUIRED: when buffering a block, all of its ancestors and the latest commit which sets the GC round
    /// must also be buffered.
    /// REQUIRED: when buffering a commit, all of its included blocks and the previous commits must also be buffered.
    /// REQUIRED: when flushing, all of the buffered blocks and commits must be flushed together to ensure consistency.
    ///
    /// After each flush, DagState becomes persisted in storage and it expected to recover
    /// all internal states from storage after restarts.
    pub(crate) fn flush(&mut self) {
        let _s = self
            .context
            .metrics
            .node_metrics
            .scope_processing_time
            .with_label_values(&["DagState::flush"])
            .start_timer();

        // Flush buffered data to storage.
        let pending_blocks = std::mem::take(&mut self.blocks_to_write);
        let pending_commits = std::mem::take(&mut self.commits_to_write);
        let pending_commit_info = std::mem::take(&mut self.commit_info_to_write);
        let pending_finalized_commits = std::mem::take(&mut self.finalized_commits_to_write);
        if pending_blocks.is_empty()
            && pending_commits.is_empty()
            && pending_commit_info.is_empty()
            && pending_finalized_commits.is_empty()
        {
            return;
        }

        debug!(
            "Flushing {} blocks ({}), {} commits ({}), {} commit infos ({}), {} finalized commits ({}) to storage.",
            pending_blocks.len(),
            pending_blocks
                .iter()
                .map(|b| b.reference().to_string())
                .join(","),
            pending_commits.len(),
            pending_commits
                .iter()
                .map(|c| c.reference().to_string())
                .join(","),
            pending_commit_info.len(),
            pending_commit_info
                .iter()
                .map(|(commit_ref, _)| commit_ref.to_string())
                .join(","),
            pending_finalized_commits.len(),
            pending_finalized_commits
                .iter()
                .map(|(commit_ref, _)| commit_ref.to_string())
                .join(","),
        );
        self.store
            .write(WriteBatch::new(
                pending_blocks,
                pending_commits,
                pending_commit_info,
                pending_finalized_commits,
            ))
            .unwrap_or_else(|e| panic!("Failed to write to storage: {:?}", e));
        self.context
            .metrics
            .node_metrics
            .dag_state_store_write_count
            .inc();

        // Clean up old cached data. After flushing, all cached blocks are guaranteed to be persisted.
        for (authority_index, _) in self.context.committee.authorities() {
            let eviction_round = self.calculate_authority_eviction_round(authority_index);
            while let Some(block_ref) = self.recent_refs_by_authority[authority_index].first() {
                if block_ref.round <= eviction_round {
                    self.recent_blocks.remove(block_ref);
                    self.recent_refs_by_authority[authority_index].pop_first();
                } else {
                    break;
                }
            }
            self.evicted_rounds[authority_index] = eviction_round;
        }

        let metrics = &self.context.metrics.node_metrics;
        metrics
            .dag_state_recent_blocks
            .set(self.recent_blocks.len() as i64);
        metrics.dag_state_recent_refs.set(
            self.recent_refs_by_authority
                .iter()
                .map(BTreeSet::len)
                .sum::<usize>() as i64,
        );
    }

    pub(crate) fn recover_last_commit_info(&self) -> Option<(CommitRef, CommitInfo)> {
        self.store
            .read_last_commit_info()
            .unwrap_or_else(|e| panic!("Failed to read from storage: {:?}", e))
    }

    pub(crate) fn add_scoring_subdags(&mut self, scoring_subdags: Vec<CommittedSubDag>) {
        self.scoring_subdag.add_subdags(scoring_subdags);
    }

    pub(crate) fn clear_scoring_subdag(&mut self) {
        self.scoring_subdag.clear();
    }

    pub(crate) fn scoring_subdags_count(&self) -> usize {
        self.scoring_subdag.scored_subdags_count()
    }

    pub(crate) fn is_scoring_subdag_empty(&self) -> bool {
        self.scoring_subdag.is_empty()
    }

    pub(crate) fn calculate_scoring_subdag_scores(&self) -> ReputationScores {
        self.scoring_subdag.calculate_distributed_vote_scores()
    }

    pub(crate) fn scoring_subdag_commit_range(&self) -> CommitIndex {
        self.scoring_subdag
            .commit_range
            .as_ref()
            .expect("commit range should exist for scoring subdag")
            .end()
    }

    /// The last round that should get evicted after a cache clean up operation. After this round we are
    /// guaranteed to have all the produced blocks from that authority. For any round that is
    /// <= `last_evicted_round` we don't have such guarantees as out of order blocks might exist.
    fn calculate_authority_eviction_round(&self, authority_index: AuthorityIndex) -> Round {
        let last_round = self.recent_refs_by_authority[authority_index]
            .last()
            .map(|block_ref| block_ref.round)
            .unwrap_or(GENESIS_ROUND);

        Self::eviction_round(last_round, self.gc_round(), self.cached_rounds)
    }

    /// Calculates the eviction round for the given authority. The goal is to keep at least `cached_rounds`
    /// of the latest blocks in the cache (if enough data is available), while evicting blocks with rounds <= `gc_round` when possible.
    fn eviction_round(last_round: Round, gc_round: Round, cached_rounds: u32) -> Round {
        gc_round.min(last_round.saturating_sub(cached_rounds))
    }

    /// Returns the underlying store.
    pub(crate) fn store(&self) -> Arc<dyn Store> {
        self.store.clone()
    }

    /// Detects and returns the blocks of the round that forms the last quorum. The method will return
    /// the quorum even if that's genesis.
    #[cfg(test)]
    pub(crate) fn last_quorum(&self) -> Vec<VerifiedBlock> {
        // the quorum should exist either on the highest accepted round or the one before. If we fail to detect
        // a quorum then it means that our DAG has advanced with missing causal history.
        for round in
            (self.highest_accepted_round.saturating_sub(1)..=self.highest_accepted_round).rev()
        {
            if round == GENESIS_ROUND {
                return self.genesis_blocks();
            }
            use crate::stake_aggregator::{QuorumThreshold, StakeAggregator};
            let mut quorum = StakeAggregator::<QuorumThreshold>::new();

            // Since the minimum wave length is 3 we expect to find a quorum in the uncommitted rounds.
            let blocks = self.get_uncommitted_blocks_at_round(round);
            for block in &blocks {
                if quorum.add(block.author(), &self.context.committee) {
                    return blocks;
                }
            }
        }

        panic!("Fatal error, no quorum has been detected in our DAG on the last two rounds.");
    }

    #[cfg(test)]
    pub(crate) fn genesis_blocks(&self) -> Vec<VerifiedBlock> {
        self.genesis.values().cloned().collect()
    }

    #[cfg(test)]
    pub(crate) fn set_last_commit(&mut self, commit: TrustedCommit) {
        self.last_commit = Some(commit);
    }
}

struct BlockInfo {
    block: VerifiedBlock,
    // Whether the block has been committed
    committed: bool,
    // Whether the block has been hard linked by a proposed block.
    hard_linked: bool,
}

impl BlockInfo {
    fn new(block: VerifiedBlock) -> Self {
        Self {
            block,
            committed: false,
            hard_linked: false,
        }
    }
}

#[cfg(test)]
mod test {
    use std::vec;

    use consensus_types::block::{BlockDigest, BlockRef, BlockTimestampMs};
    use parking_lot::RwLock;

    use super::*;
    use crate::{
        block::{TestBlock, VerifiedBlock},
        storage::{mem_store::MemStore, WriteBatch},
        test_dag_builder::DagBuilder,
        test_dag_parser::parse_dag,
        CommitRange,
    };

    #[tokio::test]
    async fn test_get_blocks() {
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());
        let own_index = AuthorityIndex::new_for_test(0);

        // Populate test blocks for round 1 ~ 10, authorities 0 ~ 2.
        let num_rounds: u32 = 10;
        let non_existent_round: u32 = 100;
        let num_authorities: u32 = 3;
        let num_blocks_per_slot: usize = 3;
        let mut blocks = BTreeMap::new();
        for round in 1..=num_rounds {
            for author in 0..num_authorities {
                // Create 3 blocks per slot, with different timestamps and digests.
                let base_ts = round as BlockTimestampMs * 1000;
                for timestamp in base_ts..base_ts + num_blocks_per_slot as u64 {
                    let block = VerifiedBlock::new_for_test(
                        TestBlock::new(round, author)
                            .set_timestamp_ms(timestamp)
                            .build(),
                    );
                    dag_state.accept_block(block.clone());
                    blocks.insert(block.reference(), block);

                    // Only write one block per slot for own index
                    if AuthorityIndex::new_for_test(author) == own_index {
                        break;
                    }
                }
            }
        }

        // Check uncommitted blocks that exist.
        for (r, block) in &blocks {
            assert_eq!(&dag_state.get_block(r).unwrap(), block);
        }

        // Check uncommitted blocks that do not exist.
        let last_ref = blocks.keys().last().unwrap();
        assert!(dag_state
            .get_block(&BlockRef::new(
                last_ref.round,
                last_ref.author,
                BlockDigest::MIN
            ))
            .is_none());

        // Check slots with uncommitted blocks.
        for round in 1..=num_rounds {
            for author in 0..num_authorities {
                let slot = Slot::new(
                    round,
                    context
                        .committee
                        .to_authority_index(author as usize)
                        .unwrap(),
                );
                let blocks = dag_state.get_uncommitted_blocks_at_slot(slot);

                // We only write one block per slot for own index
                if AuthorityIndex::new_for_test(author) == own_index {
                    assert_eq!(blocks.len(), 1);
                } else {
                    assert_eq!(blocks.len(), num_blocks_per_slot);
                }

                for b in blocks {
                    assert_eq!(b.round(), round);
                    assert_eq!(
                        b.author(),
                        context
                            .committee
                            .to_authority_index(author as usize)
                            .unwrap()
                    );
                }
            }
        }

        // Check slots without uncommitted blocks.
        let slot = Slot::new(non_existent_round, AuthorityIndex::ZERO);
        assert!(dag_state.get_uncommitted_blocks_at_slot(slot).is_empty());

        // Check rounds with uncommitted blocks.
        for round in 1..=num_rounds {
            let blocks = dag_state.get_uncommitted_blocks_at_round(round);
            // Expect 3 blocks per authority except for own authority which should
            // have 1 block.
            assert_eq!(
                blocks.len(),
                (num_authorities - 1) as usize * num_blocks_per_slot + 1
            );
            for b in blocks {
                assert_eq!(b.round(), round);
            }
        }

        // Check rounds without uncommitted blocks.
        assert!(dag_state
            .get_uncommitted_blocks_at_round(non_existent_round)
            .is_empty());
    }

    #[tokio::test]
    async fn test_ancestors_at_uncommitted_round() {
        // Initialize DagState.
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // Populate DagState.

        // Round 10 refs will not have their blocks in DagState.
        let round_10_refs: Vec<_> = (0..4)
            .map(|a| {
                VerifiedBlock::new_for_test(TestBlock::new(10, a).set_timestamp_ms(1000).build())
                    .reference()
            })
            .collect();

        // Round 11 blocks.
        let round_11 = vec![
            // This will connect to round 12.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 0)
                    .set_timestamp_ms(1100)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
            // Slot(11, 1) has 3 blocks.
            // This will connect to round 12.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 1)
                    .set_timestamp_ms(1110)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
            // This will connect to round 13.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 1)
                    .set_timestamp_ms(1111)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
            // This will not connect to any block.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 1)
                    .set_timestamp_ms(1112)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
            // This will not connect to any block.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 2)
                    .set_timestamp_ms(1120)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
            // This will connect to round 12.
            VerifiedBlock::new_for_test(
                TestBlock::new(11, 3)
                    .set_timestamp_ms(1130)
                    .set_ancestors(round_10_refs.clone())
                    .build(),
            ),
        ];

        // Round 12 blocks.
        let ancestors_for_round_12 = vec![
            round_11[0].reference(),
            round_11[1].reference(),
            round_11[5].reference(),
        ];
        let round_12 = vec![
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 0)
                    .set_timestamp_ms(1200)
                    .set_ancestors(ancestors_for_round_12.clone())
                    .build(),
            ),
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 2)
                    .set_timestamp_ms(1220)
                    .set_ancestors(ancestors_for_round_12.clone())
                    .build(),
            ),
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 3)
                    .set_timestamp_ms(1230)
                    .set_ancestors(ancestors_for_round_12.clone())
                    .build(),
            ),
        ];

        // Round 13 blocks.
        let ancestors_for_round_13 = vec![
            round_12[0].reference(),
            round_12[1].reference(),
            round_12[2].reference(),
            round_11[2].reference(),
        ];
        let round_13 = vec![
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 1)
                    .set_timestamp_ms(1300)
                    .set_ancestors(ancestors_for_round_13.clone())
                    .build(),
            ),
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 2)
                    .set_timestamp_ms(1320)
                    .set_ancestors(ancestors_for_round_13.clone())
                    .build(),
            ),
            VerifiedBlock::new_for_test(
                TestBlock::new(12, 3)
                    .set_timestamp_ms(1330)
                    .set_ancestors(ancestors_for_round_13.clone())
                    .build(),
            ),
        ];

        // Round 14 anchor block.
        let ancestors_for_round_14 = round_13.iter().map(|b| b.reference()).collect();
        let anchor = VerifiedBlock::new_for_test(
            TestBlock::new(14, 1)
                .set_timestamp_ms(1410)
                .set_ancestors(ancestors_for_round_14)
                .build(),
        );

        // Add all blocks (at and above round 11) to DagState.
        for b in round_11
            .iter()
            .chain(round_12.iter())
            .chain(round_13.iter())
            .chain([anchor.clone()].iter())
        {
            dag_state.accept_block(b.clone());
        }

        // Check ancestors connected to anchor.
        let ancestors = dag_state.ancestors_at_round(&anchor, 11);
        let mut ancestors_refs: Vec<BlockRef> = ancestors.iter().map(|b| b.reference()).collect();
        ancestors_refs.sort();
        let mut expected_refs = vec![
            round_11[0].reference(),
            round_11[1].reference(),
            round_11[2].reference(),
            round_11[5].reference(),
        ];
        expected_refs.sort(); // we need to sort as blocks with same author and round of round 11 (position 1 & 2) might not be in right lexicographical order.
        assert_eq!(
            ancestors_refs, expected_refs,
            "Expected round 11 ancestors: {:?}. Got: {:?}",
            expected_refs, ancestors_refs
        );
    }

    #[tokio::test]
    async fn test_link_causal_history() {
        let (mut context, _) = Context::new_for_test(4);
        context.parameters.dag_state_cached_rounds = 10;
        context
            .protocol_config
            .set_consensus_gc_depth_for_testing(3);
        let context = Arc::new(context);

        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // Create for rounds 1..=6. Skip creating blocks for authority 0 for rounds 4 - 6.
        let mut dag_builder = DagBuilder::new(context.clone());
        dag_builder.layers(1..=3).build();
        dag_builder
            .layers(4..=6)
            .authorities(vec![AuthorityIndex::new_for_test(0)])
            .skip_block()
            .build();

        // Accept all blocks
        let all_blocks = dag_builder.all_blocks();
        dag_state.accept_blocks(all_blocks.clone());

        // No block is linked yet.
        for block in &all_blocks {
            assert!(!dag_state.is_hard_linked(&block.reference()));
        }

        // Link causal history from a round 1 block.
        let round_1_block = &all_blocks[1];
        assert_eq!(round_1_block.round(), 1);
        let linked_blocks = dag_state.link_causal_history(round_1_block.reference());

        // Check that the block is linked.
        assert_eq!(linked_blocks.len(), 1);
        assert_eq!(linked_blocks[0], round_1_block.reference());
        for block_ref in linked_blocks {
            assert!(dag_state.is_hard_linked(&block_ref));
        }

        // Link causal history from a round 2 block.
        let round_2_block = &all_blocks[4];
        assert_eq!(round_2_block.round(), 2);
        let linked_blocks = dag_state.link_causal_history(round_2_block.reference());

        // Check the linked blocks.
        assert_eq!(linked_blocks.len(), 4);
        for block_ref in linked_blocks {
            assert!(block_ref == round_2_block.reference() || block_ref.round == 1);
        }

        // Check linked status in dag state.
        for block in &all_blocks {
            if block.round() == 1 || block.reference() == round_2_block.reference() {
                assert!(dag_state.is_hard_linked(&block.reference()));
            } else {
                assert!(!dag_state.is_hard_linked(&block.reference()));
            }
        }

        // Select round 6 block.
        let round_6_block = all_blocks.last().unwrap();
        assert_eq!(round_6_block.round(), 6);

        // Get GC round to 3.
        let last_commit = TrustedCommit::new_for_test(
            6,
            CommitDigest::MIN,
            context.clock.timestamp_utc_ms(),
            round_6_block.reference(),
            vec![],
        );
        dag_state.set_last_commit(last_commit);
        assert_eq!(
            dag_state.gc_round(),
            3,
            "GC round should have moved to round 3"
        );

        // Link causal history from a round 6 block.
        let linked_blocks = dag_state.link_causal_history(round_6_block.reference());

        // Check the linked blocks. They should not include GC'ed blocks.
        assert_eq!(linked_blocks.len(), 7, "Linked blocks: {:?}", linked_blocks);
        for block_ref in linked_blocks {
            assert!(
                block_ref.round == 4
                    || block_ref.round == 5
                    || block_ref == round_6_block.reference()
            );
        }

        // Check linked status in dag state.
        for block in &all_blocks {
            let block_ref = block.reference();
            if block.round() == 1
                || block_ref == round_2_block.reference()
                || block_ref.round == 4
                || block_ref.round == 5
                || block_ref == round_6_block.reference()
            {
                assert!(dag_state.is_hard_linked(&block.reference()));
            } else {
                assert!(!dag_state.is_hard_linked(&block.reference()));
            }
        }
    }

    #[tokio::test]
    async fn test_contains_blocks_in_cache_or_store() {
        /// Only keep elements up to 2 rounds before the last committed round
        const CACHED_ROUNDS: Round = 2;

        let (mut context, _) = Context::new_for_test(4);
        context.parameters.dag_state_cached_rounds = CACHED_ROUNDS;

        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // Create test blocks for round 1 ~ 10
        let num_rounds: u32 = 10;
        let num_authorities: u32 = 4;
        let mut blocks = Vec::new();

        for round in 1..=num_rounds {
            for author in 0..num_authorities {
                let block = VerifiedBlock::new_for_test(TestBlock::new(round, author).build());
                blocks.push(block);
            }
        }

        // Now write in store the blocks from first 4 rounds and the rest to the dag state
        blocks.clone().into_iter().for_each(|block| {
            if block.round() <= 4 {
                store
                    .write(WriteBatch::default().blocks(vec![block]))
                    .unwrap();
            } else {
                dag_state.accept_blocks(vec![block]);
            }
        });

        // Now when trying to query whether we have all the blocks, we should successfully retrieve a positive answer
        // where the blocks of first 4 round should be found in DagState and the rest in store.
        let mut block_refs = blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let result = dag_state.contains_blocks(block_refs.clone());

        // Ensure everything is found
        let mut expected = vec![true; (num_rounds * num_authorities) as usize];
        assert_eq!(result, expected);

        // Now try to ask also for one block ref that is neither in cache nor in store
        block_refs.insert(
            3,
            BlockRef::new(11, AuthorityIndex::new_for_test(3), BlockDigest::default()),
        );
        let result = dag_state.contains_blocks(block_refs.clone());

        // Then all should be found apart from the last one
        expected.insert(3, false);
        assert_eq!(result, expected.clone());
    }

    #[tokio::test]
    async fn test_contains_cached_block_at_slot() {
        /// Only keep elements up to 2 rounds before the last committed round
        const CACHED_ROUNDS: Round = 2;

        let num_authorities: u32 = 4;
        let (mut context, _) = Context::new_for_test(num_authorities as usize);
        context.parameters.dag_state_cached_rounds = CACHED_ROUNDS;

        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // Create test blocks for round 1 ~ 10
        let num_rounds: u32 = 10;
        let mut blocks = Vec::new();

        for round in 1..=num_rounds {
            for author in 0..num_authorities {
                let block = VerifiedBlock::new_for_test(TestBlock::new(round, author).build());
                blocks.push(block.clone());
                dag_state.accept_block(block);
            }
        }

        // Query for genesis round 0, genesis blocks should be returned
        for (author, _) in context.committee.authorities() {
            assert!(
                dag_state.contains_cached_block_at_slot(Slot::new(GENESIS_ROUND, author)),
                "Genesis should always be found"
            );
        }

        // Now when trying to query whether we have all the blocks, we should successfully retrieve a positive answer
        // where the blocks of first 4 round should be found in DagState and the rest in store.
        let mut block_refs = blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();

        for block_ref in block_refs.clone() {
            let slot = block_ref.into();
            let found = dag_state.contains_cached_block_at_slot(slot);
            assert!(found, "A block should be found at slot {}", slot);
        }

        // Now try to ask also for one block ref that is not in cache
        // Then all should be found apart from the last one
        block_refs.insert(
            3,
            BlockRef::new(11, AuthorityIndex::new_for_test(3), BlockDigest::default()),
        );
        let mut expected = vec![true; (num_rounds * num_authorities) as usize];
        expected.insert(3, false);

        // Attempt to check the same for via the contains slot method
        for block_ref in block_refs {
            let slot = block_ref.into();
            let found = dag_state.contains_cached_block_at_slot(slot);

            assert_eq!(expected.remove(0), found);
        }
    }

    #[tokio::test]
    #[ignore]
    #[should_panic(
        expected = "Attempted to check for slot [1]3 that is <= the last gc evicted round 3"
    )]
    async fn test_contains_cached_block_at_slot_panics_when_ask_out_of_range() {
        /// Keep 2 rounds from the highest committed round. This is considered universal and minimum necessary blocks to hold
        /// for the correct node operation.
        const GC_DEPTH: u32 = 2;
        /// Keep at least 3 rounds in cache for each authority.
        const CACHED_ROUNDS: Round = 3;

        let (mut context, _) = Context::new_for_test(4);
        context
            .protocol_config
            .set_consensus_gc_depth_for_testing(GC_DEPTH);
        context.parameters.dag_state_cached_rounds = CACHED_ROUNDS;

        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // Create for rounds 1..=6. Skip creating blocks for authority 0 for rounds 4 - 6.
        let mut dag_builder = DagBuilder::new(context.clone());
        dag_builder.layers(1..=3).build();
        dag_builder
            .layers(4..=6)
            .authorities(vec![AuthorityIndex::new_for_test(0)])
            .skip_block()
            .build();

        // Accept all blocks
        dag_builder
            .all_blocks()
            .into_iter()
            .for_each(|block| dag_state.accept_block(block));

        // Now add a commit for leader round 5 to trigger an eviction
        dag_state.add_commit(TrustedCommit::new_for_test(
            1 as CommitIndex,
            CommitDigest::MIN,
            0,
            dag_builder.leader_block(5).unwrap().reference(),
            vec![],
        ));
        // Flush the DAG state to storage.
        dag_state.flush();

        // Ensure that gc round has been updated
        assert_eq!(dag_state.gc_round(), 3, "GC round should be 3");

        // Now what we expect to happen is for:
        // * Nodes 1 - 3 should have in cache blocks from gc_round (3) and onwards.
        // * Node 0 should have in cache blocks from it's latest round, 3, up to round 1, which is the number of cached_rounds.
        for authority_index in 1..=3 {
            for round in 4..=6 {
                assert!(dag_state.contains_cached_block_at_slot(Slot::new(
                    round,
                    AuthorityIndex::new_for_test(authority_index)
                )));
            }
        }

        for round in 1..=3 {
            assert!(dag_state
                .contains_cached_block_at_slot(Slot::new(round, AuthorityIndex::new_for_test(0))));
        }

        // When trying to request for authority 1 at block slot 3 it should panic, as anything
        // that is <= 3 should be evicted
        let _ =
            dag_state.contains_cached_block_at_slot(Slot::new(3, AuthorityIndex::new_for_test(1)));
    }

    #[tokio::test]
    async fn test_get_blocks_in_cache_or_store() {
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // Create test blocks for round 1 ~ 10
        let num_rounds: u32 = 10;
        let num_authorities: u32 = 4;
        let mut blocks = Vec::new();

        for round in 1..=num_rounds {
            for author in 0..num_authorities {
                let block = VerifiedBlock::new_for_test(TestBlock::new(round, author).build());
                blocks.push(block);
            }
        }

        // Now write in store the blocks from first 4 rounds and the rest to the dag state
        blocks.clone().into_iter().for_each(|block| {
            if block.round() <= 4 {
                store
                    .write(WriteBatch::default().blocks(vec![block]))
                    .unwrap();
            } else {
                dag_state.accept_blocks(vec![block]);
            }
        });

        // Now when trying to query whether we have all the blocks, we should successfully retrieve a positive answer
        // where the blocks of first 4 round should be found in DagState and the rest in store.
        let mut block_refs = blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let result = dag_state.get_blocks(&block_refs);

        let mut expected = blocks
            .into_iter()
            .map(Some)
            .collect::<Vec<Option<VerifiedBlock>>>();

        // Ensure everything is found
        assert_eq!(result, expected.clone());

        // Now try to ask also for one block ref that is neither in cache nor in store
        block_refs.insert(
            3,
            BlockRef::new(11, AuthorityIndex::new_for_test(3), BlockDigest::default()),
        );
        let result = dag_state.get_blocks(&block_refs);

        // Then all should be found apart from the last one
        expected.insert(3, None);
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_flush_and_recovery() {
        telemetry_subscribers::init_for_testing();

        const GC_DEPTH: u32 = 3;
        const CACHED_ROUNDS: u32 = 4;

        let num_authorities: u32 = 4;
        let (mut context, _) = Context::new_for_test(num_authorities as usize);
        context.parameters.dag_state_cached_rounds = CACHED_ROUNDS;
        context
            .protocol_config
            .set_consensus_gc_depth_for_testing(GC_DEPTH);

        let context = Arc::new(context);

        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        const NUM_ROUNDS: Round = 20;
        let mut dag_builder = DagBuilder::new(context.clone());
        dag_builder.layers(1..=5).build();
        dag_builder
            .layers(6..=8)
            .authorities(vec![AuthorityIndex::new_for_test(0)])
            .skip_block()
            .build();
        dag_builder.layers(9..=NUM_ROUNDS).build();

        // Get all commits from the DAG builder.
        const LAST_COMMIT_ROUND: Round = 16;
        const LAST_COMMIT_INDEX: CommitIndex = 15;
        let commits = dag_builder
            .get_sub_dag_and_commits(1..=NUM_ROUNDS)
            .into_iter()
            .map(|(_subdag, commit)| commit)
            .take(LAST_COMMIT_INDEX as usize)
            .collect::<Vec<_>>();
        assert_eq!(commits.len(), LAST_COMMIT_INDEX as usize);
        assert_eq!(commits.last().unwrap().round(), LAST_COMMIT_ROUND);

        // Add the blocks from first 11 rounds and first 8 commits to the dag state
        // Note that the commit of round 8 is missing because where authority 0 is the leader but produced no block.
        // So commit 8 has leader round 9.
        const PERSISTED_BLOCK_ROUNDS: u32 = 12;
        const NUM_PERSISTED_COMMITS: usize = 8;
        const LAST_PERSISTED_COMMIT_ROUND: Round = 9;
        const LAST_PERSISTED_COMMIT_INDEX: CommitIndex = 8;
        dag_state.accept_blocks(dag_builder.blocks(1..=PERSISTED_BLOCK_ROUNDS));
        let mut finalized_commits = vec![];
        for commit in commits.iter().take(NUM_PERSISTED_COMMITS).cloned() {
            finalized_commits.push(commit.clone());
            dag_state.add_commit(commit);
        }
        let last_finalized_commit = finalized_commits.last().unwrap();
        assert_eq!(last_finalized_commit.round(), LAST_PERSISTED_COMMIT_ROUND);
        assert_eq!(last_finalized_commit.index(), LAST_PERSISTED_COMMIT_INDEX);

        // Collect finalized blocks.
        let finalized_blocks = finalized_commits
            .iter()
            .flat_map(|commit| commit.blocks())
            .collect::<BTreeSet<_>>();

        // Flush commits from the dag state
        dag_state.flush();

        // Verify the store has blocks up to round 12, and commits up to index 8.
        let store_blocks = store
            .scan_blocks_by_author(AuthorityIndex::new_for_test(1), 1)
            .unwrap();
        assert_eq!(store_blocks.last().unwrap().round(), PERSISTED_BLOCK_ROUNDS);
        let store_commits = store.scan_commits((0..=CommitIndex::MAX).into()).unwrap();
        assert_eq!(store_commits.len(), NUM_PERSISTED_COMMITS);
        assert_eq!(
            store_commits.last().unwrap().index(),
            LAST_PERSISTED_COMMIT_INDEX
        );
        assert_eq!(
            store_commits.last().unwrap().round(),
            LAST_PERSISTED_COMMIT_ROUND
        );

        // Add the rest of the blocks and commits to the dag state
        dag_state.accept_blocks(dag_builder.blocks(PERSISTED_BLOCK_ROUNDS + 1..=NUM_ROUNDS));
        for commit in commits.iter().skip(NUM_PERSISTED_COMMITS).cloned() {
            dag_state.add_commit(commit);
        }

        // All blocks should be found in DagState.
        let all_blocks = dag_builder.blocks(1..=NUM_ROUNDS);
        let block_refs = all_blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let result = dag_state
            .get_blocks(&block_refs)
            .into_iter()
            .map(|b| b.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(result, all_blocks);

        // Last commit index from DagState should now be 15
        assert_eq!(dag_state.last_commit_index(), LAST_COMMIT_INDEX);

        // Destroy the dag state without flushing additional data.
        drop(dag_state);

        // Recover the state from the store
        let dag_state = DagState::new(context.clone(), store.clone());

        // Persisted blocks rounds should be found in DagState.
        let all_blocks = dag_builder.blocks(1..=PERSISTED_BLOCK_ROUNDS);
        let block_refs = all_blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let result = dag_state
            .get_blocks(&block_refs)
            .into_iter()
            .map(|b| b.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(result, all_blocks);

        // Unpersisted blocks should not be in DagState, because they are not flushed.
        let missing_blocks = dag_builder.blocks(PERSISTED_BLOCK_ROUNDS + 1..=NUM_ROUNDS);
        let block_refs = missing_blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let retrieved_blocks = dag_state
            .get_blocks(&block_refs)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert!(retrieved_blocks.is_empty());

        // Recovered last commit index and round should be 8 and 9.
        assert_eq!(dag_state.last_commit_index(), LAST_PERSISTED_COMMIT_INDEX);
        assert_eq!(dag_state.last_commit_round(), LAST_PERSISTED_COMMIT_ROUND);

        // The last_commit_rounds of the finalized commits should have been recovered.
        let expected_last_committed_rounds = vec![5, 9, 8, 8];
        assert_eq!(
            dag_state.last_committed_rounds(),
            expected_last_committed_rounds
        );
        // Unscored subdags will be recovered based on the flushed commits and no commit info.
        assert_eq!(dag_state.scoring_subdags_count(), NUM_PERSISTED_COMMITS);

        // Ensure that cached blocks exist only for specific rounds per authority
        for (authority_index, _) in context.committee.authorities() {
            let blocks = dag_state.get_cached_blocks(authority_index, 1);

            // Ensure that eviction rounds have been properly recovered.
            // For every authority, the gc round is 9 - 3 = 6, and cached round is 12-5 = 7.
            // So eviction round is the min which is 6.
            if authority_index == AuthorityIndex::new_for_test(0) {
                assert_eq!(blocks.len(), 4);
                assert_eq!(dag_state.evicted_rounds[authority_index.value()], 6);
                assert!(blocks
                    .into_iter()
                    .all(|block| block.round() >= 7 && block.round() <= 12));
            } else {
                assert_eq!(blocks.len(), 6);
                assert_eq!(dag_state.evicted_rounds[authority_index.value()], 6);
                assert!(blocks
                    .into_iter()
                    .all(|block| block.round() >= 7 && block.round() <= 12));
            }
        }

        // Ensure that committed blocks from > gc_round have been correctly recovered as committed according to committed sub dags.
        let gc_round = dag_state.gc_round();
        assert_eq!(gc_round, 6);
        dag_state
            .recent_blocks
            .iter()
            .for_each(|(block_ref, block_info)| {
                if block_ref.round > gc_round && finalized_blocks.contains(block_ref) {
                    assert!(
                        block_info.committed,
                        "Block {:?} should be set as committed",
                        block_ref
                    );
                }
            });

        // Ensure the hard linked status of blocks are recovered.
        // All blocks below highest accepted round, or authority 0 round 12 block, should be hard linked.
        // Other blocks (round 12 but not from authority 0) should not be hard linked.
        // This is because authority 0 blocks are considered proposed blocks.
        dag_state
            .recent_blocks
            .iter()
            .for_each(|(block_ref, block_info)| {
                if block_ref.round < PERSISTED_BLOCK_ROUNDS || block_ref.author.value() == 0 {
                    assert!(block_info.hard_linked);
                } else {
                    assert!(!block_info.hard_linked);
                }
            });
    }

    #[tokio::test]
    async fn test_block_info_as_committed() {
        let num_authorities: u32 = 4;
        let (context, _) = Context::new_for_test(num_authorities as usize);
        let context = Arc::new(context);

        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // Accept a block
        let block = VerifiedBlock::new_for_test(
            TestBlock::new(1, 0)
                .set_timestamp_ms(1000)
                .set_ancestors(vec![])
                .build(),
        );

        dag_state.accept_block(block.clone());

        // Query is committed
        assert!(!dag_state.is_committed(&block.reference()));

        // Set block as committed for first time should return true
        assert!(
            dag_state.set_committed(&block.reference()),
            "Block should be successfully set as committed for first time"
        );

        // Now it should appear as committed
        assert!(dag_state.is_committed(&block.reference()));

        // Trying to set the block as committed again, it should return false.
        assert!(
            !dag_state.set_committed(&block.reference()),
            "Block should not be successfully set as committed"
        );
    }

    #[tokio::test]
    async fn test_get_cached_blocks() {
        let (mut context, _) = Context::new_for_test(4);
        context.parameters.dag_state_cached_rounds = 5;

        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // Create no blocks for authority 0
        // Create one block (round 10) for authority 1
        // Create two blocks (rounds 10,11) for authority 2
        // Create three blocks (rounds 10,11,12) for authority 3
        let mut all_blocks = Vec::new();
        for author in 1..=3 {
            for round in 10..(10 + author) {
                let block = VerifiedBlock::new_for_test(TestBlock::new(round, author).build());
                all_blocks.push(block.clone());
                dag_state.accept_block(block);
            }
        }

        // Test get_cached_blocks()

        let cached_blocks =
            dag_state.get_cached_blocks(context.committee.to_authority_index(0).unwrap(), 0);
        assert!(cached_blocks.is_empty());

        let cached_blocks =
            dag_state.get_cached_blocks(context.committee.to_authority_index(1).unwrap(), 10);
        assert_eq!(cached_blocks.len(), 1);
        assert_eq!(cached_blocks[0].round(), 10);

        let cached_blocks =
            dag_state.get_cached_blocks(context.committee.to_authority_index(2).unwrap(), 10);
        assert_eq!(cached_blocks.len(), 2);
        assert_eq!(cached_blocks[0].round(), 10);
        assert_eq!(cached_blocks[1].round(), 11);

        let cached_blocks =
            dag_state.get_cached_blocks(context.committee.to_authority_index(2).unwrap(), 11);
        assert_eq!(cached_blocks.len(), 1);
        assert_eq!(cached_blocks[0].round(), 11);

        let cached_blocks =
            dag_state.get_cached_blocks(context.committee.to_authority_index(3).unwrap(), 10);
        assert_eq!(cached_blocks.len(), 3);
        assert_eq!(cached_blocks[0].round(), 10);
        assert_eq!(cached_blocks[1].round(), 11);
        assert_eq!(cached_blocks[2].round(), 12);

        let cached_blocks =
            dag_state.get_cached_blocks(context.committee.to_authority_index(3).unwrap(), 12);
        assert_eq!(cached_blocks.len(), 1);
        assert_eq!(cached_blocks[0].round(), 12);

        // Test get_cached_blocks_in_range()

        // Start == end
        let cached_blocks = dag_state.get_cached_blocks_in_range(
            context.committee.to_authority_index(3).unwrap(),
            10,
            10,
            1,
        );
        assert!(cached_blocks.is_empty());

        // Start > end
        let cached_blocks = dag_state.get_cached_blocks_in_range(
            context.committee.to_authority_index(3).unwrap(),
            11,
            10,
            1,
        );
        assert!(cached_blocks.is_empty());

        // Empty result.
        let cached_blocks = dag_state.get_cached_blocks_in_range(
            context.committee.to_authority_index(0).unwrap(),
            9,
            10,
            1,
        );
        assert!(cached_blocks.is_empty());

        // Single block, one round before the end.
        let cached_blocks = dag_state.get_cached_blocks_in_range(
            context.committee.to_authority_index(1).unwrap(),
            9,
            11,
            1,
        );
        assert_eq!(cached_blocks.len(), 1);
        assert_eq!(cached_blocks[0].round(), 10);

        // Respect end round.
        let cached_blocks = dag_state.get_cached_blocks_in_range(
            context.committee.to_authority_index(2).unwrap(),
            9,
            12,
            5,
        );
        assert_eq!(cached_blocks.len(), 2);
        assert_eq!(cached_blocks[0].round(), 10);
        assert_eq!(cached_blocks[1].round(), 11);

        // Respect start round.
        let cached_blocks = dag_state.get_cached_blocks_in_range(
            context.committee.to_authority_index(3).unwrap(),
            11,
            20,
            5,
        );
        assert_eq!(cached_blocks.len(), 2);
        assert_eq!(cached_blocks[0].round(), 11);
        assert_eq!(cached_blocks[1].round(), 12);

        // Respect limit
        let cached_blocks = dag_state.get_cached_blocks_in_range(
            context.committee.to_authority_index(3).unwrap(),
            10,
            20,
            1,
        );
        assert_eq!(cached_blocks.len(), 1);
        assert_eq!(cached_blocks[0].round(), 10);
    }

    #[tokio::test]
    async fn test_get_last_cached_block() {
        // GIVEN
        const CACHED_ROUNDS: Round = 2;
        const GC_DEPTH: u32 = 1;
        let (mut context, _) = Context::new_for_test(4);
        context.parameters.dag_state_cached_rounds = CACHED_ROUNDS;
        context
            .protocol_config
            .set_consensus_gc_depth_for_testing(GC_DEPTH);

        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // Create no blocks for authority 0
        // Create one block (round 1) for authority 1
        // Create two blocks (rounds 1,2) for authority 2
        // Create three blocks (rounds 1,2,3) for authority 3
        let dag_str = "DAG {
            Round 0 : { 4 },
            Round 1 : {
                B -> [*],
                C -> [*],
                D -> [*],
            },
            Round 2 : {
                C -> [*],
                D -> [*],
            },
            Round 3 : {
                D -> [*],
            },
        }";

        let (_, dag_builder) = parse_dag(dag_str).expect("Invalid dag");

        // Add equivocating block for round 2 authority 3
        let block = VerifiedBlock::new_for_test(TestBlock::new(2, 2).build());

        // Accept all blocks
        for block in dag_builder
            .all_blocks()
            .into_iter()
            .chain(std::iter::once(block))
        {
            dag_state.accept_block(block);
        }

        dag_state.add_commit(TrustedCommit::new_for_test(
            1 as CommitIndex,
            CommitDigest::MIN,
            context.clock.timestamp_utc_ms(),
            dag_builder.leader_block(3).unwrap().reference(),
            vec![],
        ));

        // WHEN search for the latest blocks
        let end_round = 4;
        let expected_rounds = vec![0, 1, 2, 3];
        let expected_excluded_and_equivocating_blocks = vec![0, 0, 1, 0];
        // THEN
        let last_blocks = dag_state.get_last_cached_block_per_authority(end_round);
        assert_eq!(
            last_blocks.iter().map(|b| b.0.round()).collect::<Vec<_>>(),
            expected_rounds
        );
        assert_eq!(
            last_blocks.iter().map(|b| b.1.len()).collect::<Vec<_>>(),
            expected_excluded_and_equivocating_blocks
        );

        // THEN
        for (i, expected_round) in expected_rounds.iter().enumerate() {
            let round = dag_state
                .get_last_cached_block_in_range(
                    context.committee.to_authority_index(i).unwrap(),
                    0,
                    end_round,
                )
                .map(|b| b.round())
                .unwrap_or_default();
            assert_eq!(round, *expected_round, "Authority {i}");
        }

        // WHEN starting from round 2
        let start_round = 2;
        let expected_rounds = [0, 0, 2, 3];

        // THEN
        for (i, expected_round) in expected_rounds.iter().enumerate() {
            let round = dag_state
                .get_last_cached_block_in_range(
                    context.committee.to_authority_index(i).unwrap(),
                    start_round,
                    end_round,
                )
                .map(|b| b.round())
                .unwrap_or_default();
            assert_eq!(round, *expected_round, "Authority {i}");
        }

        // WHEN we flush the DagState - after adding a commit with all the blocks, we expect this to trigger
        // a clean up in the internal cache. That will keep the all the blocks with rounds >= authority_commit_round - CACHED_ROUND.
        //
        // When GC is enabled then we'll keep all the blocks that are > gc_round (2) and for those who don't have blocks > gc_round, we'll keep
        // all their highest round blocks for CACHED_ROUNDS.
        dag_state.flush();

        // AND we request before round 3
        let end_round = 3;
        let expected_rounds = vec![0, 1, 2, 2];

        // THEN
        let last_blocks = dag_state.get_last_cached_block_per_authority(end_round);
        assert_eq!(
            last_blocks.iter().map(|b| b.0.round()).collect::<Vec<_>>(),
            expected_rounds
        );

        // THEN
        for (i, expected_round) in expected_rounds.iter().enumerate() {
            let round = dag_state
                .get_last_cached_block_in_range(
                    context.committee.to_authority_index(i).unwrap(),
                    0,
                    end_round,
                )
                .map(|b| b.round())
                .unwrap_or_default();
            assert_eq!(round, *expected_round, "Authority {i}");
        }
    }

    #[tokio::test]
    #[should_panic(
        expected = "Attempted to request for blocks of rounds < 2, when the last evicted round is 1 for authority [2]"
    )]
    async fn test_get_cached_last_block_per_authority_requesting_out_of_round_range() {
        // GIVEN
        const CACHED_ROUNDS: Round = 1;
        const GC_DEPTH: u32 = 1;
        let (mut context, _) = Context::new_for_test(4);
        context.parameters.dag_state_cached_rounds = CACHED_ROUNDS;
        context
            .protocol_config
            .set_consensus_gc_depth_for_testing(GC_DEPTH);

        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // Create no blocks for authority 0
        // Create one block (round 1) for authority 1
        // Create two blocks (rounds 1,2) for authority 2
        // Create three blocks (rounds 1,2,3) for authority 3
        let mut dag_builder = DagBuilder::new(context.clone());
        dag_builder
            .layers(1..=1)
            .authorities(vec![AuthorityIndex::new_for_test(0)])
            .skip_block()
            .build();
        dag_builder
            .layers(2..=2)
            .authorities(vec![
                AuthorityIndex::new_for_test(0),
                AuthorityIndex::new_for_test(1),
            ])
            .skip_block()
            .build();
        dag_builder
            .layers(3..=3)
            .authorities(vec![
                AuthorityIndex::new_for_test(0),
                AuthorityIndex::new_for_test(1),
                AuthorityIndex::new_for_test(2),
            ])
            .skip_block()
            .build();

        // Accept all blocks
        for block in dag_builder.all_blocks() {
            dag_state.accept_block(block);
        }

        dag_state.add_commit(TrustedCommit::new_for_test(
            1 as CommitIndex,
            CommitDigest::MIN,
            0,
            dag_builder.leader_block(3).unwrap().reference(),
            vec![],
        ));

        // Flush the store so we update the evict rounds
        dag_state.flush();

        // THEN the method should panic, as some authorities have already evicted rounds <= round 2
        dag_state.get_last_cached_block_per_authority(2);
    }

    #[tokio::test]
    async fn test_last_quorum() {
        // GIVEN
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let dag_state = Arc::new(RwLock::new(DagState::new(context.clone(), store.clone())));

        // WHEN no blocks exist then genesis should be returned
        {
            let genesis = genesis_blocks(context.as_ref());

            assert_eq!(dag_state.read().last_quorum(), genesis);
        }

        // WHEN a fully connected DAG up to round 4 is created, then round 4 blocks should be returned as quorum
        {
            let mut dag_builder = DagBuilder::new(context.clone());
            dag_builder
                .layers(1..=4)
                .build()
                .persist_layers(dag_state.clone());
            let round_4_blocks: Vec<_> = dag_builder
                .blocks(4..=4)
                .into_iter()
                .map(|block| block.reference())
                .collect();

            let last_quorum = dag_state.read().last_quorum();

            assert_eq!(
                last_quorum
                    .into_iter()
                    .map(|block| block.reference())
                    .collect::<Vec<_>>(),
                round_4_blocks
            );
        }

        // WHEN adding one more block at round 5, still round 4 should be returned as quorum
        {
            let block = VerifiedBlock::new_for_test(TestBlock::new(5, 0).build());
            dag_state.write().accept_block(block);

            let round_4_blocks = dag_state.read().get_uncommitted_blocks_at_round(4);

            let last_quorum = dag_state.read().last_quorum();

            assert_eq!(last_quorum, round_4_blocks);
        }
    }

    #[tokio::test]
    async fn test_last_block_for_authority() {
        // GIVEN
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let dag_state = Arc::new(RwLock::new(DagState::new(context.clone(), store.clone())));

        // WHEN no blocks exist then genesis should be returned
        {
            let genesis = genesis_blocks(context.as_ref());
            let my_genesis = genesis
                .into_iter()
                .find(|block| block.author() == context.own_index)
                .unwrap();

            assert_eq!(dag_state.read().get_last_proposed_block(), my_genesis);
        }

        // WHEN adding some blocks for authorities, only the last ones should be returned
        {
            // add blocks up to round 4
            let mut dag_builder = DagBuilder::new(context.clone());
            dag_builder
                .layers(1..=4)
                .build()
                .persist_layers(dag_state.clone());

            // add block 5 for authority 0
            let block = VerifiedBlock::new_for_test(TestBlock::new(5, 0).build());
            dag_state.write().accept_block(block);

            let block = dag_state
                .read()
                .get_last_block_for_authority(AuthorityIndex::new_for_test(0));
            assert_eq!(block.round(), 5);

            for (authority_index, _) in context.committee.authorities() {
                let block = dag_state
                    .read()
                    .get_last_block_for_authority(authority_index);

                if authority_index.value() == 0 {
                    assert_eq!(block.round(), 5);
                } else {
                    assert_eq!(block.round(), 4);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_accept_block_not_panics_when_timestamp_is_ahead_and_median_timestamp() {
        // GIVEN
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // Set a timestamp for the block that is ahead of the current time
        let block_timestamp = context.clock.timestamp_utc_ms() + 5_000;

        let block = VerifiedBlock::new_for_test(
            TestBlock::new(10, 0)
                .set_timestamp_ms(block_timestamp)
                .build(),
        );

        // Try to accept the block - it should not panic
        dag_state.accept_block(block);
    }

    #[tokio::test]
    async fn test_last_finalized_commit() {
        // GIVEN
        let (context, _) = Context::new_for_test(4);
        let context = Arc::new(context);
        let store = Arc::new(MemStore::new());
        let mut dag_state = DagState::new(context.clone(), store.clone());

        // WHEN adding a finalized commit
        let commit_ref = CommitRef::new(1, CommitDigest::MIN);
        let rejected_transactions = BTreeMap::new();
        dag_state.add_finalized_commit(commit_ref, rejected_transactions.clone());

        // THEN the commit should be added to the buffer
        assert_eq!(dag_state.finalized_commits_to_write.len(), 1);
        assert_eq!(
            dag_state.finalized_commits_to_write[0],
            (commit_ref, rejected_transactions.clone())
        );

        // WHEN flushing the DAG state
        dag_state.flush();

        // THEN the commit and rejected transactions should be written to storage
        let last_finalized_commit = store.read_last_finalized_commit().unwrap();
        assert_eq!(last_finalized_commit, Some(commit_ref));
        let commits = store
            .scan_finalized_commits(CommitRange::new(1..=1))
            .unwrap();
        assert_eq!(commits, vec![(commit_ref, rejected_transactions.clone())]);
    }
}
