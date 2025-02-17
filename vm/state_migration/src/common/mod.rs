// Copyright 2019-2023 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

//! Common code that's shared across all migration code.
//! Each network upgrade / state migration code lives in their own module.

use std::sync::Arc;

use cid::Cid;
use forest_shim::{address::Address, clock::ChainEpoch, econ::TokenAmount, state_tree::StateTree};
use fvm_ipld_blockstore::Blockstore;

mod macros;
mod migration_job;
pub(crate) mod migrators;
mod state_migration;
pub(crate) mod verifier;

pub(crate) use state_migration::StateMigration;
pub(crate) type Migrator<BS> = Arc<dyn ActorMigration<BS> + Send + Sync>;

#[allow(dead_code)] // future migrations might need the fields.
pub(crate) struct ActorMigrationInput {
    /// Actor's address
    pub address: Address,
    /// Actor's balance
    pub balance: TokenAmount,
    /// Actor's state head CID
    pub head: Cid,
    /// Epoch of last state transition prior to migration
    pub prior_epoch: ChainEpoch,
}

/// Output of actor migration job.
pub(crate) struct ActorMigrationOutput {
    /// New CID for the actor
    pub new_code_cid: Cid,
    /// New state head CID
    pub new_head: Cid,
}

/// Trait that defines the interface for actor migration job.
pub(crate) trait ActorMigration<BS: Blockstore + Clone + Send + Sync> {
    fn migrate_state(
        &self,
        store: BS,
        input: ActorMigrationInput,
    ) -> anyhow::Result<ActorMigrationOutput>;
}

/// Trait that defines the interface for actor migration job to be executed after the state migration.
pub(crate) trait PostMigrator<BS: Blockstore>: Send + Sync {
    fn post_migrate_state(&self, store: &BS, actors_out: &mut StateTree<BS>) -> anyhow::Result<()>;
}

/// Sized wrapper of [`PostMigrator`].
pub(crate) type PostMigratorArc<BS> = Arc<dyn PostMigrator<BS>>;

/// Trait that migrates from one data structure to another, similar to
/// [`std::convert::TryInto`] trait but taking an extra block store parameter
pub(crate) trait TypeMigration<From, To> {
    fn migrate_type(from: From, store: &impl Blockstore) -> anyhow::Result<To>;
}

/// Type that implements [`TypeMigration`] for different type pairs. Prefer
/// using a single `struct` so that the compiler could catch duplicate
/// implementations
pub(crate) struct TypeMigrator;
