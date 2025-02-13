use secp256k1::{Secp256k1, PublicKey, ecdsa::Signature, Message};
use sha2::{Sha256, Digest};
use std::collections::HashSet;

pub fn verify_two_thirds_signatures(
    public_keys: &[PublicKey],
    signatures: &[Signature],
    message: &[u8],
) -> bool {
    let secp = Secp256k1::new();
    let hash: [u8; 32] = Sha256::digest(message).into();
    let msg = Message::from_digest(hash);

    let total_keys = public_keys.len();
    if total_keys == 0 {
        return false;
    }
    let threshold = ((2.0 / 3.0) * (total_keys as f64)).floor() as usize;

    let mut signed_key_indices = HashSet::new();

    for sig in signatures {
        for (idx, pk) in public_keys.iter().enumerate() {
            if signed_key_indices.contains(&idx) {
                continue;
            }

            if secp.verify_ecdsa(&msg, sig, pk).is_ok() {
                signed_key_indices.insert(idx);
                break;
            }
        }
    }

    signed_key_indices.len() >= threshold
}

use secp256k1::SecretKey;
fn main() {
    let secp = Secp256k1::new();

    let sk1 = SecretKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();  

    let pk1 = PublicKey::from_secret_key(&secp, &sk1);

    let message = b"Hello, secp256k1!";

    let hash: [u8; 32] = Sha256::digest(message).into();
    let msg = Message::from_digest(hash);

    let sig = secp.sign_ecdsa(&msg, &sk1);

    let verified = secp.verify_ecdsa(&msg, &sig, &pk1);
    println!("Ecdsa works: {:?}", verified);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_two_thirds_signatures() {
        let secp = Secp256k1::new();

        let sk1 = SecretKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
        let sk2 = SecretKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
        let sk3 = SecretKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();

        let pk1 = PublicKey::from_secret_key(&secp, &sk1);
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);
        let pk3 = PublicKey::from_secret_key(&secp, &sk3);

        let message = b"Hello, secp256k1!";
        let hash: [u8; 32] = Sha256::digest(message).into();
        let msg = Message::from_digest(hash);

        let sig1 = secp.sign_ecdsa(&msg, &sk1);
        let sig2 = secp.sign_ecdsa(&msg, &sk2);
        let sig3 = secp.sign_ecdsa(&msg, &sk3);

        let invalid_sig = secp.sign_ecdsa(&msg, &sk1);
        let public_keys = vec![pk1, pk2, pk3];

        // Case 1: All signatures
        let signatures = vec![sig1, sig2, sig3];
        let result1 = verify_two_thirds_signatures(&public_keys, &signatures, message);
        assert!(result1);
        println!("Result 1: {:?}", result1);

        // Case 2: Only 2 valid signatures
        let signatures = vec![sig1, sig2, invalid_sig];
        let result2 = verify_two_thirds_signatures(&public_keys, &signatures, message);
        assert!(result2);
        println!("Result 2: {:?}", result2);

        // Case 3: Only 1 valid signature
        let signatures = vec![sig1, invalid_sig, invalid_sig];
        let result3 = verify_two_thirds_signatures(&public_keys, &signatures, message);
        assert!(!result3);
        println!("Result 3: {:?}", result3);
    }
}
