//! `merkle_sigs` implements Merkle signatures in Rust.

#[doc(no_inline)]
extern crate lamport_sigs;
extern crate merkle;
extern crate ring;

mod signatures;
pub use signatures::{MerkleSignature, MerkleSignedData, verify_data_vec_signature, sign_data_vec};
pub use merkle::Proof;
pub use lamport_sigs::PublicKey;

#[cfg(test)]
mod tests;
