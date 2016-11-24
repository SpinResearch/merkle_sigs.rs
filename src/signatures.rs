use std::io;
use lamport_sigs::{PrivateKey, PublicKey, LamportSignatureData};
use crypto::digest::Digest;
use merkle::{MerkleTree, Proof};
use std::io::{Error, ErrorKind};

pub type MerkleSignature<D> = (LamportSignatureData, Proof<D, PublicKey<D>>);
pub type MerkleSignedData<D, T> = (Vec<T>, MerkleSignature<D>);

// TODO: Error management. Currently forcing unwrap within the map.
// We can leave optionals to avoid having panics.
pub fn sign_data_vec<D: Digest + Clone, T: AsRef<[u8]>>(data: &Vec<T>,
                                                        digest: D)
                                                        -> Vec<MerkleSignature<D>> {
    let mut leaf_keys: Vec<PrivateKey<D>> = vec![PrivateKey::new(digest.clone()); data.len()];
    let leaf_pub_keys = leaf_keys.iter()
        .map(|priv_key| priv_key.public_key())
        .collect::<Vec<_>>();

    let tree = MerkleTree::from_vec(digest, leaf_pub_keys.clone()).unwrap();

    let signatures = leaf_keys.iter_mut()
        .zip(data.iter())
        .map(|(mut priv_key, data)| priv_key.sign(data.as_ref()).unwrap())
        .collect::<Vec<_>>();

    let proofs = leaf_pub_keys.into_iter()
        .map(|pub_key| (tree.gen_proof(pub_key).unwrap()))
        .collect::<Vec<_>>();

    signatures.into_iter()
              .zip(proofs)
              .map(|(sigs, proof)| (sigs, proof))
              .collect::<Vec<_>>()
}

/// Verifies the signature of the data. Returns an error if data couldn't be verified.
pub fn verify_data_vec_signature<D: Digest+Clone, T: Into<Vec<u8>>>(data: T,
    signature: &MerkleSignature<D>, root_hash: &Vec<u8>) -> io::Result<()>{
    let (ref sig, ref proof) = *signature;

    let valid_root = proof.validate(root_hash);
    let data_vec: Vec<u8> = data.into();
    let valid_sig = proof.value.verify_signature(sig, data_vec.as_slice());

    if !valid_root {
        return Err(Error::new(ErrorKind::Other, "The inclusion proof failed to validate."));
    }

    if !valid_sig {
        return Err(Error::new(ErrorKind::Other,
                              "The signature could not be properly verified."));
    }

    Ok(())
}
