#![cfg(test)]
use crypto::sha3::Sha3;
use signatures::{verify_data_vec_signature, sign_data_vec};

#[test]
fn test_signature_verification_passes() {
    let vec = vec!["0", "1", "2"];
    let digest = Sha3::sha3_512();
    let signatures = sign_data_vec(&vec, digest);
    let ref s0 = signatures[0];
    let ref s1 = signatures[1];
    let ref s2 = signatures[2];

    let (_, _, ref proof) = signatures[2];
    let root_hash = proof.root_hash.clone();
    assert!(verify_data_vec_signature(vec[0], s0, &root_hash).is_ok());
    assert!(verify_data_vec_signature(vec[1], s1, &root_hash).is_ok());
    assert!(verify_data_vec_signature(vec[2], s2, &root_hash).is_ok());
}

#[test]
fn test_same_root_hash() {
    let vec = vec!["I", "won't", "call", "you", "President"];
    let digest = Sha3::sha3_512();
    let signatures = sign_data_vec(&vec, digest);

    let mut root_hash: Option<Vec<u8>> = None;
    for (_, _, proof) in signatures {
        if root_hash.is_none() {
            root_hash = Some(proof.root_hash.clone());
        } else {
            assert_eq!(root_hash.clone().unwrap(), proof.root_hash);
        }
    }
}
