use crate::config;
use crate::repository::Repository;
use sqlx::{Pool, Postgres};

mod agents;
mod jobs;

pub const ENCRYPTED_JOB_MAX_SIZE: usize = 512_000; // 512k
//pub const ENCRYPTED_JOB_RESULT_MAX_SIZE: usize = 2_000_000; // 2MB

//encrypted job result max size to 6MB
pub const ENCRYPTED_JOB_RESULT_MAX_SIZE: usize = 6_000_000; // 6MB

#[derive(Debug)]
pub struct Service {
    repo: Repository,
    db: Pool<Postgres>,
    config: config::Config,
}

impl Service {
    pub fn new(db: Pool<Postgres>, config: config::Config) -> Service {
        let repo = Repository {};
        Service { db, repo, config }
    }
}
