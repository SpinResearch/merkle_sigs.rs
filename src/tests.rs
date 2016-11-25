#![cfg(test)]
use crypto::sha3::Sha3;
use signatures::{verify_data_vec_signature, sign_data_vec};
use Proof;
use PublicKey;

#[test]
fn test_signature_verification_passes() {
    let vec = vec!["0", "1", "2"];
    let digest = Sha3::sha3_512();
    let signatures = sign_data_vec(&vec, digest).unwrap();
    let ref s0 = signatures[0];
    let ref s1 = signatures[1];
    let ref s2 = signatures[2];

    let (_, ref proof) = signatures[2];
    let root_hash = proof.root_hash.clone();
    assert!(verify_data_vec_signature(vec[0], s0, &root_hash).is_ok());
    assert!(verify_data_vec_signature(vec[1], s1, &root_hash).is_ok());
    assert!(verify_data_vec_signature(vec[2], s2, &root_hash).is_ok());
}

#[test]
fn test_same_root_hash() {
    let vec = vec!["I", "won't", "call", "you", "President"];
    let digest = Sha3::sha3_512();
    let signatures = sign_data_vec(&vec, digest).unwrap();

    let mut root_hash: Option<Vec<u8>> = None;
    for (_, proof) in signatures {
        if root_hash.is_none() {
            root_hash = Some(proof.root_hash.clone());
        } else {
            assert_eq!(root_hash.clone().unwrap(), proof.root_hash);
        }
    }
}


#[test]
fn serialization() {
    let vec = vec!["0", "1", "2"];
    let digest = Sha3::sha3_512();
    let signatures = sign_data_vec(&vec, digest).unwrap();
    let (ref sig, ref proof) = signatures[2];

    let proof_bytes = proof.clone().write_to_bytes().unwrap();

    let p = Proof::<Sha3, Vec<u8>>::parse_from_bytes(&proof_bytes, digest).unwrap().unwrap();

    let proof2 = Proof {
        digest: digest,
        lemma: p.lemma,
        root_hash: p.root_hash,
        value: PublicKey::from_vec(p.value, Sha3::sha3_512()).unwrap(),
    };

    let root_hash = proof2.root_hash.clone();
    let s2 = (sig.clone(), proof2);
    let data: Vec<u8> = String::from("2").into_bytes();
    assert!(verify_data_vec_signature(data, &s2, &root_hash).is_ok());
}
