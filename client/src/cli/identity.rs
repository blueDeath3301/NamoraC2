use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use rand::rngs::OsRng;

pub fn run() {
    //let mut rand_generator = rand::rngs::OsRng {};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let identity_keypair = ed25519_dalek::SigningKey::from_bytes(&bytes);

    let encoded_private_key = general_purpose::STANDARD.encode(identity_keypair.to_bytes());
    println!("private key: {}", encoded_private_key);

    let encoded_public_key = general_purpose::STANDARD.encode(identity_keypair.to_bytes());
    println!("public key: {}", encoded_public_key);
}
