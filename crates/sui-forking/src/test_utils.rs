// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use sui_types::message_envelope::Envelope;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use sui_types::messages_checkpoint::VerifiedCheckpoint;
use sui_types::test_checkpoint_data_builder::TestCheckpointBuilder;

pub fn verified_checkpoint(sequence_number: CheckpointSequenceNumber) -> VerifiedCheckpoint {
    let mut builder = TestCheckpointBuilder::new(sequence_number);
    let checkpoint = builder.build_checkpoint();
    VerifiedCheckpoint::new_unchecked(Envelope::new_from_data_and_sig(
        checkpoint.summary.data().clone(),
        checkpoint.summary.auth_sig().clone(),
    ))
}
