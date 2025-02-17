// Copyright 2019-2023 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use ahash::HashSet;
use cid::Cid;

#[derive(Default)]
pub struct CidHashSet(HashSet<u64>);

impl CidHashSet {
    pub fn insert(&mut self, cid: &Cid, on_inserted: &impl Fn(usize)) -> bool {
        let hash = self.0.hasher().hash_one(cid);
        if self.0.insert(hash) {
            on_inserted(self.0.len());
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
