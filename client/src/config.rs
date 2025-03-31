use crate::error::Error;
use base64::{Engine as _, engine::general_purpose};

pub const SERVER_URL: &str = "http://localhost:8080";
pub const IDENTITY_PRIVATE_KEY: &str =  "wToLgDfjCxFijRA+YKi6T9j7bTc/4grwoTRJZJs5DU8=";

#[derive(Debug)]
pub struct Config {
    pub identity_public_key: ed25519_dalek::VerifyingKey,
    pub identity_private_key: ed25519_dalek::SecretKey,
}

impl Config {
    pub fn load() -> Result<Config, Error> {

        // Decode base64 private key
        let private_key_bytes = general_purpose::STANDARD.decode(IDENTITY_PRIVATE_KEY)?;
        
        // Convert Vec<u8> to [u8; 32]
        let key_array: [u8; 32] = private_key_bytes.try_into()
            .map_err(|_| Error::Internal("Invalid private key length".to_string()))?;
        
        // Create the SigningKey
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
        
        // Get the verifying key (public key)
        let identity_public_key = signing_key.verifying_key();
        
        // Get the bytes for private key
        let identity_private_key = signing_key.to_bytes();

        Ok(Config {
            identity_public_key,
            identity_private_key,
        })
    }
}
