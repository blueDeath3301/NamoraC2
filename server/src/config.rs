use crate::error::Error;

//use base64::prelude::*;
use base64::{Engine as _, engine::general_purpose};
//use std::path::Path;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub client_identity_public_key: ed25519_dalek::VerifyingKey,
}

//const ENV_DATABASE_URL: &str = "DATABASE_URL";
//const ENV_PORT: &str = "PORT";
//const ENV_CLIENT_IDENTITY_PUBLIC_KEY: &str = "CLIENT_IDENTITY_PUBLIC_KEY";

const DEFAULT_PORT: u16 = 8080;

impl Config {
    pub fn load() -> Result<Config, Error> {
       // dotenv::dotenv().ok();

       //try hardcoded config
       let hard_port = DEFAULT_PORT;
       let hard_database_url = "postgres://user69:namora@localhost:5432/namora?sslmode=disable";
       let hard_client_identity_key_str = "dFa0knTlWODvELy59rzMEvITKxcFj984R28T/K3r6tI=";

/*         let path = Path::new("../server_config.env");
        if let Err(e) = dotenv::from_path(path) {
            println!("Error loading .env file: {:?}", e);
        } else {
            println!("Successfully loaded .env file from path");
        }

        let port = std::env::var(ENV_PORT)
            .ok()
            .map_or(Ok(DEFAULT_PORT), |env_val| env_val.parse::<u16>())?;

        let database_url =
            std::env::var(ENV_DATABASE_URL).map_err(|_| env_not_found(ENV_DATABASE_URL))?;

        let client_identity_key_str = std::env::var(ENV_CLIENT_IDENTITY_PUBLIC_KEY)
            .ok()
            .unwrap_or(String::new());

*/
        //let client_identity_public_key_bytes = BASE64_STANDARD.decode(client_identity_key_str.as_bytes()).unwrap();
        let client_identity_public_key_bytes = general_purpose::STANDARD.decode(hard_client_identity_key_str.as_bytes()).unwrap();

        // Ensure the length is exactly 32 bytes
        if client_identity_public_key_bytes.len() != 32 {
        return Err(Error::Internal("Invalid public key length".to_string()));
}

        // Convert Vec<u8> to [u8; 32]
        let client_identity_public_key_bytes: [u8; 32] = client_identity_public_key_bytes
            .try_into()
            .map_err(|_| Error::Internal("failed to convert Vec<u8> to [u8; 32] for client pk bytes".to_string()))?;

        //let client_identity_public_key_bytes = Engine::decode(&self, &client_identity_key_str)
          //  .map_err(|err| Error::Internal(err.to_string()))?;

        let client_identity_public_key =
            ed25519_dalek::VerifyingKey::from_bytes(&client_identity_public_key_bytes)?;

       /* Ok(Config {
           port,
           database_url,
           client_identity_public_key,
        })  */

       Ok(Config {
        port: hard_port,
        database_url: hard_database_url.to_string(),
        client_identity_public_key,
        })
    }    
}

/* fn env_not_found(var: &str) -> Error {
    Error::NotFound(format!("config: {} env variable not found", var))
} */
