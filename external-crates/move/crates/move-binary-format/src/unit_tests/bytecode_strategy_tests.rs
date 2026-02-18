// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::file_format::{Bytecode, bytecode_strategy_variant_count};
use proptest::{
    arbitrary::any,
    collection::vec,
    strategy::{Strategy, ValueTree},
    test_runner::TestRunner,
};

#[test]
fn bytecode_strategy_matches_variant_count() {
    assert_eq!(bytecode_strategy_variant_count(), Bytecode::VARIANT_COUNT);
}

#[test]
fn bytecode_vector_generation_smoke() {
    let strategy = vec(any::<Bytecode>(), 0..=16);
    let mut runner = TestRunner::default();

    for _ in 0..1024 {
        let tree = strategy
            .new_tree(&mut runner)
            .expect("bytecode vector generation should work");
        let _ = tree.current();
    }
}
