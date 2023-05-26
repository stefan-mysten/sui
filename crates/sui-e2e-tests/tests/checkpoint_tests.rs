// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;
use sui_core::authority::epoch_start_configuration::EpochFlag;
use sui_core::authority::epoch_start_configuration::EpochStartConfigTrait;
use sui_macros::sim_test;
use test_utils::network::TestClusterBuilder;

#[sim_test]
async fn basic_checkpoints_integration_test() {
    let test_cluster = TestClusterBuilder::new().build().await.unwrap();
    let tx = test_cluster
        .wallet
        .make_transfer_sui_transaction(None, None)
        .await;
    let digest = *tx.digest();
    test_cluster.execute_transaction(tx).await.unwrap();

    for _ in 0..600 {
        let all_included = test_cluster
            .swarm
            .validator_node_handles()
            .into_iter()
            .all(|handle| {
                handle.with(|node| {
                    let epoch_store = node.state().epoch_store_for_testing();
                    if epoch_store
                        .epoch_start_config()
                        .flags()
                        .contains(&EpochFlag::PerEpochFinalizedTransactions)
                    {
                        epoch_store
                            .is_transaction_executed_in_checkpoint(&digest)
                            .unwrap()
                    } else {
                        node.state()
                            .database
                            .is_transaction_executed_in_checkpoint(&digest)
                            .unwrap()
                    }
                })
            });
        if all_included {
            // success
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("Did not include transaction in checkpoint in 60 seconds");
}
