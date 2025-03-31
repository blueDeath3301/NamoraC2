use serde::{Deserialize, Serialize};
use std::convert::{Into, TryFrom};
use uuid::Uuid;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::SigningKey;

use crate::error::Error;

pub const SERVER_URL: &str = "http://localhost:8080";
pub const AGENT_ID_FILE: &str = "namora";
pub const CLIENT_IDENTITY_PUBLIC_KEY: &str = "xQ6gstFLtTbDC06LDb5dAQap+fXVG45BnRZj0L5th+M=";

#[derive(Debug)]
pub struct Config {
    pub agent_id: Uuid,
    pub identity_public_key: ed25519_dalek::VerifyingKey,
    pub identity_private_key: ed25519_dalek::SigningKey,
    pub public_prekey: [u8; 32],
    pub private_prekey: [u8; 32],
    pub client_identity_public_key: ed25519_dalek::VerifyingKey,
}

impl TryFrom<SerializedConfig> for Config {
    type Error = Error;

    fn try_from(conf: SerializedConfig) -> Result<Config, Self::Error> {
        let agent_id = conf.agent_id;

        // Create SigningKey from bytes
        let identity_private_key = SigningKey::from_bytes(&conf.identity_private_key);

        // Derive public key from secret key
        let identity_public_key = ed25519_dalek::VerifyingKey::from(&identity_private_key);

        let private_prekey = conf.private_prekey;
        let public_prekey = x25519(private_prekey, X25519_BASEPOINT_BYTES);

        // Decode base64 client public key
        let client_public_key_bytes = general_purpose::STANDARD
            .decode(CLIENT_IDENTITY_PUBLIC_KEY)
            .map_err(|e| Error::Internal(e.to_string()))?;

        // Convert to fixed size array
        let key_array: [u8; 32] = client_public_key_bytes
            .try_into()
            .map_err(|_| Error::Internal("Invalid public key length".to_string()))?;

        // Create verifying key from bytes
        let client_identity_public_key = ed25519_dalek::VerifyingKey::from_bytes(&key_array)
            .map_err(|e| Error::Internal(e.to_string()))?;

        Ok(Config {
            agent_id,
            identity_public_key,
            identity_private_key,
            public_prekey,
            private_prekey,
            client_identity_public_key,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedConfig {
    pub agent_id: Uuid,
    pub identity_private_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    pub private_prekey: [u8; 32],
}

impl Into<SerializedConfig> for &Config {
    fn into(self) -> SerializedConfig {
        SerializedConfig {
            agent_id: self.agent_id,
            identity_private_key: self.identity_private_key.to_bytes(),
            private_prekey: self.private_prekey,
        }
    }
}
