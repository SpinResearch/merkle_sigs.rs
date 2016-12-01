use std::io;
use lamport_sigs::{PrivateKey, PublicKey, LamportSignatureData};
use ring::digest::Algorithm;
use merkle::{MerkleTree, Proof};
use std::io::{Error, ErrorKind};

/// A type alias defining a Merkle signature. That includes both the Lamport leaf signature and inclusion proof.
pub type MerkleSignature = (LamportSignatureData, Proof<PublicKey>);
/// A type alias defining Merkle signed data. That includes the data being signed along with the signature.
pub type MerkleSignedData<T> = (Vec<T>, MerkleSignature);

fn new_err(reason: &str) -> Error {
    Error::new(ErrorKind::Other, format!("A signature could not be produced because {}", reason))
}

/// Signs the entries of the data vector
pub fn sign_data_vec<T>(data: &Vec<T>, algorithm: &'static Algorithm) -> io::Result<Vec<MerkleSignature>>
        where T: AsRef<[u8]> {

    let mut leaf_keys = vec![PrivateKey::new(algorithm); data.len()];
    let leaf_pub_keys = leaf_keys.iter()
        .map(|priv_key| priv_key.public_key())
        .collect::<Vec<_>>();

    let tree_opt = MerkleTree::from_vec(algorithm, leaf_pub_keys.clone());

    if tree_opt.is_none() {
        return Err(new_err("an issue occured while generating the signing tree."));
    }

    let tree = tree_opt.unwrap();

    let proofs_opt = leaf_pub_keys.into_iter()
        .map(|pub_key| tree.gen_proof(pub_key))
        .collect::<Option<Vec<_>>>();

    let signatures_opt = leaf_keys.iter_mut()
        .zip(data.iter())
        .map(|(mut priv_key, data)| priv_key.sign(data.as_ref()))
        .collect::<Result<Vec<_>, _>>();

    match (signatures_opt, proofs_opt) {
        (_, None) =>
            Err(new_err("an issue occured while generating the inclusion proofs.")),

        (Err(err), _) =>
            Err(new_err(&format!("an issue occured while signing the data: {}", err))),

        (Ok(signatures), Some(proofs)) =>
            Ok(signatures.into_iter().zip(proofs).collect())
    }
}

/// Verifies the signature of the data. Returns an error if data couldn't be verified.
pub fn verify_data_vec_signature<T>(data: T, signature: &MerkleSignature, root_hash: &Vec<u8>) -> io::Result<()>
        where T: Into<Vec<u8>> {

    let (ref sig, ref proof) = *signature;

    let valid_root = proof.validate(root_hash);
    let data_vec   = data.into();
    let valid_sig  = proof.value.verify_signature(sig, data_vec.as_slice());

    if !valid_root {
        return Err(Error::new(ErrorKind::Other,
                              "The inclusion proof failed to validate."));
    }

    if !valid_sig {
        return Err(Error::new(ErrorKind::Other,
                              "The signature could not be properly verified."));
    }

    Ok(())
}
