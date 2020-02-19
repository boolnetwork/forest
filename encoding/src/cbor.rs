// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use super::errors::Error;
use crate::{de::DeserializeOwned, from_slice, ser::Serialize, to_vec};
use cid::{multihash::Hash::Blake2b256, Cid};

/// Cbor utility functions for serializable objects
pub trait Cbor: Serialize + DeserializeOwned {
    /// Marshalls cbor encodable object into cbor bytes
    fn marshal_cbor(&self) -> Result<Vec<u8>, Error> {
        Ok(to_vec(&self)?)
    }

    /// Unmarshals cbor encoded bytes to object
    fn unmarshal_cbor(bz: &[u8]) -> Result<Self, Error> {
        Ok(from_slice(bz)?)
    }

    /// Returns the content identifier of the raw block of data
    /// Default is Blake2b256 hash
    fn cid(&self) -> Result<Cid, Error> {
        Ok(Cid::from_bytes(&self.marshal_cbor()?, Blake2b256)?)
    }
}
