use crate::{
    api::Client,
    config::{self, Config},
    error::Error,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},  Key,
     XChaCha20Poly1305,
};
//use blake2::{Blake2b512, Digest};
use blake3;

use common::{api, crypto};
use ed25519_dalek::Verifier;
use ed25519_dalek::Signer;
use rand::RngCore;
use std::convert::TryFrom;
use std::{thread::sleep, time::Duration};
use uuid::Uuid;
use x25519_dalek::x25519;
use zeroize::Zeroize;


pub fn run(api_client: &Client, agent_id: &str, command: &str, conf: Config) ->Result<(), Error> {
    let agent_id = Uuid::parse_str(agent_id)?;
    let sleep_for = Duration::from_millis(500);

    let mut command_with_args: Vec<String> = command
        .split_whitespace()
        .into_iter()
        .map(|s| s.to_owned())
        .collect();

    if command_with_args.is_empty() {
        return Err(Error::Internal("Command is not valid".to_string()));
    }

    let command = command_with_args.remove(0);
    let args = command_with_args;

    //get agents info
    let agent = api_client.get_agent(agent_id)?;

    let agent_identity_public_key = ed25519_dalek::VerifyingKey::from_bytes(&agent.identity_public_key)?;

    //encrypt the job
    let (input, mut job_ephemeral_private_key) = encrypt_and_sign_job(
        &conf,
        command,
        args,
        agent.id,
        agent.public_prekey,
        &agent.public_prekey_signature,
        &agent_identity_public_key,
    )?;

    //create the job
    let job_id = api_client.create_job(input)?;

    loop {
        if let Some(job) = api_client.get_job_result(job_id)? {

            //decrypt job output
            let job_output = decrypt_and_verify_job_output(
                job,
                job_ephemeral_private_key,
                &agent_identity_public_key,
            )?;
            print!("{}", job_output);
            break;
        }
        sleep(sleep_for);
    }
    job_ephemeral_private_key.zeroize();

    Ok(())

}

fn encrypt_and_sign_job(
    conf: &config::Config,
    command: String,
    args: Vec<String>,
    agent_id: Uuid,
    agent_public_prekey: [u8; crypto::X25519_PUBLIC_KEY_SIZE],
    agent_public_prekey_signature: &[u8],
    agent_identity_public_key: &ed25519_dalek::VerifyingKey,
) -> Result<(api::CreateJob, [u8; crypto::X25519_PRIVATE_KEY_SIZE]), Error> {

    if agent_public_prekey_signature.len() != crypto::ED25519_SIGNATURE_SIZE {
        return Err(Error::Internal("Agent public prekey signature is not valid".to_string()));
    }

    //verify agent public prekey
    let agent_public_prekey_buffer = agent_public_prekey.to_vec();

    //make signature from the first 64 bytes
    let signature = ed25519_dalek::Signature::try_from(&agent_public_prekey_signature[0..64])?;

    //print the signature, agent_public_prekey_buffer and agent_identity_public_key
    print!("Agent Public PreKey Buffer: {:?}", agent_public_prekey_buffer);
    print!("Agent Public Key: {:?}", agent_identity_public_key);
    print!("Signature: {:?}", signature);

    if agent_identity_public_key.verify(&agent_public_prekey_buffer, &signature).is_err() {
        return Err(Error::Internal("Agent public prekey signature is not valid&&&".to_string()));
    }

    let mut rand_generator = rand::rngs::OsRng {};

    //generate ephemeral keypairfor job encryption
    let mut job_ephemeral_private_key = [0u8; crypto::X25519_PRIVATE_KEY_SIZE];
    rand_generator.fill_bytes(&mut job_ephemeral_private_key);

    let job_ephemeral_public_key = x25519(job_ephemeral_private_key.clone(), x25519_dalek::X25519_BASEPOINT_BYTES);

    //generate ephemeral keypair for job result encryption
    let mut job_result_ephemeral_private_key = [0u8; crypto::X25519_PRIVATE_KEY_SIZE];
    rand_generator.fill_bytes(&mut job_result_ephemeral_private_key);

    let job_result_ephemeral_public_key = x25519(job_result_ephemeral_private_key.clone(), x25519_dalek::X25519_BASEPOINT_BYTES);


    //key exchange -> compute a shared secret
    let mut shared_secret = x25519(job_ephemeral_private_key, agent_public_prekey);

    //generate nonce as we are using XChaCha20Poly1305

    let mut nonce = [0u8; crypto::XCHACHA20_POLY1305_NONCE_SIZE];
    rand_generator.fill_bytes(&mut nonce);

    //let nonce =XChaCha20Poly1305::generate_nonce(&mut OsRng); //192-bits per message

    //derive a symmetric key from the shared secret using a KDF. we use blake2
    //let mut hasher = Blake2b512::new();
    let mut hasher = blake3::Hasher::new();
     hasher.update(&shared_secret);

     //optional context for domain separation
     hasher.update(b"symmetric_key_derivation");
     let derived_key = hasher.finalize();
     let derived_key_bytes = derived_key.as_bytes();

     //take the first 32 bytes as the XChaCha20Poly1305 key
     let mut key: Key = Key::clone_from_slice(&derived_key_bytes[..32]);

    //serialize the job
    let encrypted_job_payload = api::JobPayload {
        command,
        args,
        result_ephemeral_public_key: job_result_ephemeral_public_key,
    };
    let encrypted_job_json = serde_json::to_vec(&encrypted_job_payload)?;

    //encrypt the job once and for all !!
    let cipher = XChaCha20Poly1305::new(&key);
    let encrypted_job = cipher.encrypt((&nonce).into(), encrypted_job_json.as_ref())?;

    //zeroize the shared secret and key
    shared_secret.zeroize();
    key.zeroize();

    //other data
    let job_id = Uuid::new_v4();

    //sign the job_id, agent_id, the encrypted job, ephemeral_public_key, nonce
    let mut buffer_to_sign = job_id.as_bytes().to_vec();
    buffer_to_sign.append(&mut agent_id.as_bytes().to_vec());
    buffer_to_sign.append(&mut encrypted_job.clone());
    buffer_to_sign.append(&mut job_ephemeral_public_key.to_vec());
    buffer_to_sign.append(&mut nonce.to_vec());

   // log::debug!("Buffer to sign: {:?}", buffer_to_sign);

    let identity = ed25519_dalek::SigningKey::from(&conf.identity_private_key);
    let signature = identity.sign(&buffer_to_sign); //ed25519_dalek::Signer::sign

    //log::debug("Signature: {:?}", signature);

    Ok((
        api::CreateJob {
            id: job_id,
            agent_id,
            encrypted_job,
            ephemeral_public_key: job_ephemeral_public_key,
            nonce,
            signature: signature.to_bytes().to_vec(),
        },
        job_ephemeral_private_key,
    ))

}

fn decrypt_and_verify_job_output(
    job: api::Job,
    job_ephemeral_private_key: [u8; crypto::X25519_PRIVATE_KEY_SIZE],
    agent_identity_public_key: &ed25519_dalek::VerifyingKey,
) -> Result<String, Error> {

    //verify job_id, agent_id, the encrypted_job_result, result_ephemeral_public_key, result_nonce
    let encrypted_job_result = job
        .encrypted_result
        .ok_or(Error::Internal("Job result is not valid".to_string()))?;

    let result_ephemeral_public_key = job.result_ephemeral_public_key.ok_or(Error::Internal("Job result ephemeral public key is missing".to_string()))?;

    let result_nonce = job.result_nonce.ok_or(Error::Internal("Job result nonce is missing".to_string()))?;

    let mut buffer_to_verify = job.id.as_bytes().to_vec();
    buffer_to_verify.append(&mut job.agent_id.as_bytes().to_vec());
    buffer_to_verify.append(&mut encrypted_job_result.clone());
    buffer_to_verify.append(&mut result_ephemeral_public_key.to_vec());
    buffer_to_verify.append(&mut result_nonce.to_vec());

    //log::debug!("Buffer to verify: {:?}", buffer_to_verify);

    let result_signature = job.result_signature.ok_or(Error::Internal("Job result signature is missing".to_string()))?;

    if result_signature.len() != crypto::ED25519_SIGNATURE_SIZE {
        return Err(Error::Internal("Job result signature is not valid".to_string()));
    }

    let signature = ed25519_dalek::Signature::try_from(&result_signature[0..64])?;

    //log::debug!("Signature: {:?}", signature);

    if agent_identity_public_key.verify(&buffer_to_verify, &signature).is_err() {
        return Err(Error::Internal("Agent's prekey signature is not valid".to_string()));
    }

    //key exchange -> compute a shared secret
    let mut shared_secret = x25519(job_ephemeral_private_key, result_ephemeral_public_key);

    //derive a symmetric key from the shared secret using a KDF. we use blake2
    //let mut hasher = Blake2b512::new();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&shared_secret);

    //optional context for domain separation
    hasher.update(b"symmetric_key_derivation");
    let derived_key = hasher.finalize();
    let derived_key_bytes = derived_key.as_bytes();

    //take the first 32 bytes as the XChaCha20Poly1305 key
    let mut key: Key = Key::clone_from_slice(&derived_key_bytes[..32]);

    //decrypt the job output
    let cipher = XChaCha20Poly1305::new(&key);
    let decrypted_job_bytes = cipher.decrypt((&result_nonce).into(), encrypted_job_result.as_ref())?;


    //zeroize the shared secret and key
    shared_secret.zeroize();
    key.zeroize();

    //deserialize the job output

    let job_result: api::JobResult = serde_json::from_slice(&decrypted_job_bytes)?;

    Ok(job_result.output)
}