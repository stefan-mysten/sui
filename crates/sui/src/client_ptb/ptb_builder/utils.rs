// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

// This lint is is disabled because it's not good and doesn't look at what you're actually
// iterating over. This seems to be a common problem with this lint.
// See e.g., https://github.com/rust-lang/rust-clippy/issues/6075
#[allow(clippy::needless_range_loop)]
pub fn edit_distance(a: &str, b: &str) -> usize {
    let mut cache = vec![vec![0; b.len() + 1]; a.len() + 1];

    for i in 0..=a.len() {
        cache[i][0] = i;
    }

    for j in 0..=b.len() {
        cache[0][j] = j;
    }

    for (i, char_a) in a.chars().enumerate().map(|(i, c)| (i + 1, c)) {
        for (j, char_b) in b.chars().enumerate().map(|(j, c)| (j + 1, c)) {
            if char_a == char_b {
                cache[i][j] = cache[i - 1][j - 1];
            } else {
                let insert = cache[i][j - 1];
                let delete = cache[i - 1][j];
                let replace = cache[i - 1][j - 1];

                cache[i][j] = 1 + std::cmp::min(insert, std::cmp::min(delete, replace));
            }
        }
    }

    cache[a.len()][b.len()]
}

pub fn find_did_you_means<'a>(
    needle: &str,
    haystack: impl IntoIterator<Item = &'a str>,
) -> Vec<&'a str> {
    let mut results = Vec::new();
    let mut best_distance = usize::MAX;

    for item in haystack {
        let distance = edit_distance(needle, item);

        match distance.cmp(&best_distance) {
            std::cmp::Ordering::Less => {
                best_distance = distance;
                results.clear();
                results.push(item);
            }
            std::cmp::Ordering::Equal => {
                results.push(item);
            }
            std::cmp::Ordering::Greater => {}
        }
    }

    results
}

pub fn display_did_you_mean(possibles: Vec<&str>) -> Option<String> {
    if possibles.is_empty() {
        return None;
    }

    let mut strs = vec![];

    let preposition = if possibles.len() == 1 {
        "Did you mean "
    } else {
        "Did you mean one of "
    };

    let len = possibles.len();
    for (i, possible) in possibles.into_iter().enumerate() {
        if i == len - 1 && len > 1 {
            strs.push(format!("or '{}'", possible));
        } else {
            strs.push(format!("'{}'", possible));
        }
    }

    Some(format!("{preposition}{}?", strs.join(", ")))
}

pub fn to_ordinal_contraction(num: usize) -> String {
    let suffix = match num % 100 {
        // exceptions
        11..=13 => "th",
        _ => match num % 10 {
            1 => "st",
            2 => "nd",
            3 => "rd",
            _ => "th",
        },
    };
    format!("{}{}", num, suffix)
}

// Handle escaping quotes in the file contents
// Non-escaped quotes in PTB files are stripped out -- this is to allow for
// similar syntax with the CLI args (i.e., allow copy-pasting from the CLI to a
// PTB file).
pub fn read_ptb_file(path: &Path) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path).map(|s| {
        s.replace("\\\"", "%__REPLACE_ME__%")
            .replace("\"", "")
            .replace("%__REPLACE_ME__%", "\"")
    })
}
