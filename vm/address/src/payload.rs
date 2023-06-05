// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use super::{from_leb_bytes, to_leb_bytes, Error, Protocol, BLS_PUB_LEN, PAYLOAD_HASH_LEN, MAX_SUBADDRESS_LEN, ActorID};
use std::convert::TryInto;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::u64;

/// Public key struct used as BLS Address data.
/// This type is only needed to be able to implement traits on it due to limitations on
/// arrays within Rust that are greater than 32 length. Can be dereferenced into `[u8; 48]`.
#[derive(Copy, Clone)]
pub struct BLSPublicKey(pub [u8; BLS_PUB_LEN]);

impl Hash for BLSPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}

impl Eq for BLSPublicKey {}
impl PartialEq for BLSPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0[..].eq(&other.0[..])
    }
}

impl fmt::Debug for BLSPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.0[..].fmt(formatter)
    }
}

impl From<[u8; BLS_PUB_LEN]> for BLSPublicKey {
    fn from(pk: [u8; BLS_PUB_LEN]) -> Self {
        BLSPublicKey(pk)
    }
}

impl Deref for BLSPublicKey {
    type Target = [u8; BLS_PUB_LEN];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A "delegated" (f4) address.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DelegatedAddress {
    namespace: ActorID,
    length: usize,
    buffer: [u8; MAX_SUBADDRESS_LEN],
}

// impl quickcheck::Arbitrary for DelegatedAddress {
//     fn arbitrary(g: &mut quickcheck::Gen) -> Self {
//         Self {
//             namespace: ActorID::arbitrary(g),
//             length: usize::arbitrary(g) % (MAX_SUBADDRESS_LEN + 1),
//             buffer: from_fn(|_| u8::arbitrary(g)),
//         }
//     }
// }
//
// impl<'a> arbitrary::Arbitrary<'a> for DelegatedAddress {
//     fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
//         Ok(DelegatedAddress {
//             namespace: arbitrary::Arbitrary::arbitrary(u)?,
//             length: u.int_in_range(0usize..=MAX_SUBADDRESS_LEN)?,
//             buffer: arbitrary::Arbitrary::arbitrary(u)?,
//         })
//     }
// }

impl DelegatedAddress {
    /// Construct a new delegated address from the namespace (actor id) and subaddress.
    pub fn new(namespace: ActorID, subaddress: &[u8]) -> Result<Self, Error> {
        let length = subaddress.len();
        if length > MAX_SUBADDRESS_LEN {
            return Err(Error::InvalidPayloadLength(length));
        }
        let mut addr = DelegatedAddress {
            namespace,
            length,
            buffer: [0u8; MAX_SUBADDRESS_LEN],
        };
        addr.buffer[..length].copy_from_slice(&subaddress[..length]);
        Ok(addr)
    }

    /// Returns the delegated address's namespace .
    #[inline]
    pub fn namespace(&self) -> ActorID {
        self.namespace
    }

    /// Returns the delegated address's subaddress .
    #[inline]
    pub fn subaddress(&self) -> &[u8] {
        &self.buffer[..self.length]
    }
}

/// Payload is the data of the Address. Variants are the supported Address protocols.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum Payload {
    /// ID protocol address.
    ID(u64),
    /// SECP256K1 key address, 20 byte hash of PublicKey
    Secp256k1([u8; PAYLOAD_HASH_LEN]),
    /// Actor protocol address, 20 byte hash of actor data
    Actor([u8; PAYLOAD_HASH_LEN]),
    /// BLS key address, full 48 byte public key
    BLS(BLSPublicKey),
    /// f4: Delegated address, a namespace with an arbitrary subaddress.
    Delegated(DelegatedAddress),
}

impl Payload {
    /// Returns encoded bytes of Address without the protocol byte.
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        use Payload::*;
        match self {
            ID(i) => to_leb_bytes(*i).unwrap(),
            Secp256k1(arr) => arr.to_vec(),
            Actor(arr) => arr.to_vec(),
            BLS(arr) => arr.to_vec(),
            Delegated(addr) => {
                let mut buf = to_leb_bytes(addr.namespace()).unwrap();
                buf.extend(addr.subaddress());
                buf
            }
        }
    }

    /// Returns encoded bytes of Address including the protocol byte.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bz = self.to_raw_bytes();
        bz.insert(0, Protocol::from(self) as u8);
        bz
    }

    /// Generates payload from raw bytes and protocol.
    pub fn new(protocol: Protocol, payload: &[u8]) -> Result<Self, Error> {
        let payload = match protocol {
            Protocol::ID => Self::ID(from_leb_bytes(payload)?),
            Protocol::Secp256k1 => Self::Secp256k1(
                payload
                    .try_into()
                    .map_err(|_| Error::InvalidPayloadLength(payload.len()))?,
            ),
            Protocol::Actor => Self::Actor(
                payload
                    .try_into()
                    .map_err(|_| Error::InvalidPayloadLength(payload.len()))?,
            ),
            Protocol::BLS => {
                if payload.len() != BLS_PUB_LEN {
                    return Err(Error::InvalidBLSLength(payload.len()));
                }
                let mut pk = [0u8; BLS_PUB_LEN];
                pk.copy_from_slice(payload);
                Self::BLS(pk.into())
            },
            Protocol::Delegated => {
                let (id, remaining) = unsigned_varint::decode::u64(payload)?;
                Self::Delegated(DelegatedAddress::new(id, remaining)?)
            }
        };
        Ok(payload)
    }
}

impl From<Payload> for Protocol {
    fn from(pl: Payload) -> Self {
        match pl {
            Payload::ID(_) => Self::ID,
            Payload::Secp256k1(_) => Self::Secp256k1,
            Payload::Actor(_) => Self::Actor,
            Payload::BLS(_) => Self::BLS,
            Payload::Delegated { .. } => Self::Delegated,
        }
    }
}

impl From<&Payload> for Protocol {
    fn from(pl: &Payload) -> Self {
        match pl {
            Payload::ID(_) => Self::ID,
            Payload::Secp256k1(_) => Self::Secp256k1,
            Payload::Actor(_) => Self::Actor,
            Payload::BLS(_) => Self::BLS,
            Payload::Delegated { .. } => Self::Delegated,
        }
    }
}
