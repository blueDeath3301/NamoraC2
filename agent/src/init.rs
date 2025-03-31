use crate::{config::*, error::Error};
use common::{
    api::{self, RegisterAgent},
    crypto,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use std::path::PathBuf;
use std::{convert::TryInto, fs};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use base64::{Engine as _, engine::general_purpose};


pub fn init(api_client: &ureq::Agent) -> Result<Config, Error> {
    let saved_agent_id = get_saved_agent_config()?;

    let conf = match saved_agent_id {
        Some(agent_id) => agent_id,
        None => {
            let conf = register(api_client)?;
            save_agent_config(&conf)?;
            conf
        }
    };

    Ok(conf)
}

pub fn get_agent_config_file_path() -> Result<PathBuf, Error> {
    let mut home_dir = match dirs::home_dir() {
        Some(home_dir) => home_dir,
        None => return Err(Error::Internal("Error getting home directory.".to_string())),
    };

    home_dir.push(AGENT_ID_FILE);

    Ok(home_dir)
}

pub fn get_saved_agent_config() -> Result<Option<Config>, Error> {
    let agent_id_file = get_agent_config_file_path()?;

    if agent_id_file.exists() {
        let agent_file_content = fs::read(agent_id_file)?;

        let serialized_conf: SerializedConfig =
            serde_json::from_slice(&agent_file_content)?;
        let conf = serialized_conf.try_into()?;
        Ok(Some(conf))
    } else {
        Ok(None)
    }
}

pub fn save_agent_config(conf: &Config) -> Result<(), Error> {
    let agent_config_file = get_agent_config_file_path()?;

    let serialized_conf: SerializedConfig = conf.into();
    let config_json = serde_json::to_string(&serialized_conf)?;

    fs::write(agent_config_file, config_json.as_bytes())?;

    Ok(())
}


///requires sever to be already running so that it connects and registers to that server
pub fn register(api_client: &ureq::Agent) -> Result<Config, Error> {
    let register_agent_route = format!("{}/api/agents", SERVER_URL);

    let mut csprng = rand::rngs::OsRng {};

    // Generate a new SigningKey (private key)
    let identity_private_key = SigningKey::generate(&mut csprng);
    

    // Derive the VerifyingKey (public key) from the SigningKey
    let identity_public_key = VerifyingKey::from(&identity_private_key);

    let mut private_prekey = [0u8; crypto::X25519_PRIVATE_KEY_SIZE];
    csprng.fill_bytes(&mut private_prekey);
    let public_prekey = x25519(private_prekey.clone(), X25519_BASEPOINT_BYTES);

    let public_prekey_signature = identity_private_key.sign(&public_prekey);

    let register_agent = RegisterAgent {
        identity_public_key: identity_public_key.to_bytes(),
        public_prekey: public_prekey.clone(),
        public_prekey_signature: public_prekey_signature.to_bytes().to_vec(),
    };

    let api_res: api::Response<api::AgentRegistered> = api_client
        .post(register_agent_route.as_str())
        .send_json(ureq::json!(register_agent))?
        .into_json()?;

    if let Some(err) = api_res.error {
        return Err(Error::Api(err.message));
    }

    //decode CLIENT_IDENTITY_PUBLIC_KEY
    let client_public_key_bytes = general_purpose::STANDARD.decode(CLIENT_IDENTITY_PUBLIC_KEY)
        .map_err(|e| Error::Internal(e.to_string()))?;
    
    // Convert to fixed size array
    let key_array: [u8; 32] = client_public_key_bytes
        .try_into()
        .map_err(|_| Error::Internal("Invalid public key length".to_string()))?;

    // Create verifying key from bytes
    let client_identity_public_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| Error::Internal(e.to_string()))?;

    let conf = Config {
        agent_id: api_res.data.unwrap().id,
        identity_public_key: identity_public_key,
        identity_private_key: identity_private_key,
        public_prekey,
        private_prekey,
        client_identity_public_key,

    };

    Ok(conf)

}
