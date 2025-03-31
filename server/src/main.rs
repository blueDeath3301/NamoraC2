use std::sync::Arc;

mod api;
mod error;
mod service;
mod repository;
mod db;
mod config;
pub mod entities;

use config::Config;
pub use error::Error;
pub use service::Service;
pub use repository::Repository;


#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), anyhow::Error> {

    std::env::set_var("RUST_LOG", "server=debug,warp=debug");
    env_logger::init();

    let config = Config::load()?;

    let db_pool = db::connect(&config.database_url).await?;
    match db_pool.acquire().await {
        Ok(_) => {
            log::info!("Database connection successful");
            println!("Database connection successful");
        }
        Err(e) => log::error!("Database connection failed: {:?}", e),
    }

    match db::migrate(&db_pool).await {
        Ok(_) => {
            log::info!("Database migration successful");
            println!("Database migration successful");
        }
        Err(e) => log::error!("Database migration failed: {:?}", e),
    }
    

    let port = config.port;
    let service = Service::new(db_pool, config);
    let app_state = Arc::new(api::AppState::new(service));

    let routes = api::routes::routes(app_state.clone());

    log::info!("Starting server on: 0.0.0.0 {}", port);

    let (_addr, server) =
        warp::serve(routes).bind_with_graceful_shutdown(([127, 0, 0, 1], port), async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to listen for CRTL+c");
            log::info!("Shutting down server");
        });

        
    server.await;

    Ok(())
}
