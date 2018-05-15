use lamport_sigs::{LamportSignatureData, PrivateKey, PublicKey};
use merkle::{Hashable, MerkleTree, Proof};
use ring::digest::{Algorithm, Context};
use std::io;
use std::io::{Error, ErrorKind};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// A wrapper struct around a Lamport public key that implements Hashable.
pub struct MerklePublicKey {
    /// The wrapped Lamport public key.
    pub key: PublicKey,
}

impl MerklePublicKey {
    /// Convenience method to wrap a Lamport `PublicKey` into a `MerklePublicKey`
    pub fn new(pk: PublicKey) -> MerklePublicKey {
        MerklePublicKey { key: pk }
    }
}

impl Hashable for MerklePublicKey {
    fn update_context(&self, context: &mut Context) {
        context.update(&self.key.to_bytes());
    }
}

impl Into<Vec<u8>> for MerklePublicKey {
    fn into(self) -> Vec<u8> {
        self.key.to_bytes()
    }
}

/// A type alias defining a Merkle signature. That includes both the Lamport leaf signature and inclusion proof.
pub type MerkleSignature = (LamportSignatureData, Proof<MerklePublicKey>);

/// A type alias defining Merkle signed data. That includes the data being signed along with the signature.
pub type MerkleSignedData<T> = (Vec<T>, MerkleSignature);

fn signing_error(reason: &str) -> Error {
    Error::new(
        ErrorKind::Other,
        format!("A signature could not be produced because {}", reason),
    )
}

/// Signs the entries of the data vector
pub fn sign_data_vec<T>(
    data: &[T],
    algorithm: &'static Algorithm,
) -> io::Result<Vec<MerkleSignature>>
where
    T: AsRef<[u8]>,
{
    let mut leaf_keys = (0..data.len())
        .map(|_| PrivateKey::new(algorithm))
        .collect::<Vec<_>>();

    debug_assert!(data.len() == leaf_keys.len());

    let leaf_pub_keys = leaf_keys
        .iter()
        .map(|priv_key| priv_key.public_key())
        .collect::<Vec<_>>();

    let wrapped_leafs = leaf_pub_keys
        .clone()
        .into_iter()
        .map(MerklePublicKey::new)
        .collect::<Vec<_>>();

    let tree = MerkleTree::from_vec(algorithm, wrapped_leafs);

    let proofs_opt = leaf_pub_keys
        .into_iter()
        .map(|pub_key| tree.gen_proof(MerklePublicKey::new(pub_key)))
        .collect::<Option<Vec<_>>>();

    let signatures_opt = leaf_keys
        .iter_mut()
        .zip(data.iter())
        .map(|(priv_key, data)| priv_key.sign(data.as_ref()))
        .collect::<Result<Vec<_>, _>>();

    match (signatures_opt, proofs_opt) {
        (_, None) => Err(signing_error(
            "an issue occured while generating the inclusion proofs.",
        )),

        (Err(err), _) => Err(signing_error(&format!(
            "an issue occured while signing the data: {}",
            err
        ))),

        (Ok(signatures), Some(proofs)) => Ok(signatures.into_iter().zip(proofs).collect()),
    }
}

fn verif_error(reason: &str) -> Error {
    Error::new(ErrorKind::Other, reason)
}

/// Verifies the signature of the data. Returns an error if data couldn't be verified.
pub fn verify_data_vec_signature<T>(
    data: T,
    signature: &MerkleSignature,
    root_hash: &[u8],
) -> io::Result<()>
where
    T: Into<Vec<u8>>,
{
    let (ref sig, ref proof) = *signature;

    let valid_root = proof.validate(root_hash);
    let data_vec = data.into();

    let valid_sig = proof.value.key.verify_signature(sig, data_vec.as_slice());

    if !valid_root {
        return Err(verif_error("The inclusion proof failed to validate."));
    }

    if !valid_sig {
        return Err(verif_error("The signature could not be properly verified."));
    }

    Ok(())
}
