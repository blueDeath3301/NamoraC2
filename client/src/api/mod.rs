mod create_jobs;
mod get_agent;
mod get_job_result;
mod list_agents;

use reqwest::redirect;
use std::time::Duration;

#[derive(Debug)]
pub struct Client {
    pub http_client: reqwest::blocking::Client,
    server_url: String,
}

impl Client {
    pub fn new(server_url: String) -> Client {
        let http_timeout = Duration::from_secs(10);
        let http_client = reqwest::blocking::Client::builder()
            .redirect(redirect::Policy::limited(4))
            .timeout(http_timeout)
            .build()
            .expect("api: Building reqwest::Client failed");

        Client {
            http_client,
            server_url,
        }
    }
    pub fn get_server_url(&self) -> &str {
        &self.server_url
    }
}