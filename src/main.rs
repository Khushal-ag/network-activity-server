use actix_web::{get, web, App, HttpServer, Responder, middleware};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sled::Db;
use log::{info, error, warn, debug};

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResult {
    pub signatures: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub id: String,
    pub tx_result: TransactionResult,
    pub sent_at: DateTime<Utc>,
    pub status: String,
}

struct AppState {
    db: Db,
}

#[get("/network-activity")]
async fn network_activity(data: web::Data<AppState>) -> impl Responder {
    debug!("Fetching network activity from database");
    
    let mut txs: Vec<TransactionRecord> = data.db
        .scan_prefix("tx:")
        .filter_map(|item| {
            match item {
                Ok((_key, v)) => {
                    match serde_json::from_slice::<TransactionRecord>(&v) {
                        Ok(tx) => Some(tx),
                        Err(e) => {
                            warn!("Failed to deserialize transaction record: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading from database: {}", e);
                    None
                }
            }
        })
        .collect();

    info!("Found {} total transactions", txs.len());
    
    txs.sort_by(|a, b| b.sent_at.cmp(&a.sent_at));

    let recent: Vec<TransactionRecord> = txs.into_iter().take(10).collect();
    
    info!("Returning {} recent transactions", recent.len());
    debug!("Transaction IDs: {:?}", recent.iter().map(|t| &t.id).collect::<Vec<_>>());

    web::Json(recent)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let db_path = "/home/ubuntu/sync_cron_job/kv_store";

    info!("Opening database at path: {}", db_path);
    let db = match sled::open(db_path) {
        Ok(db) => {
            info!("Successfully opened database at {}", db_path);
            db
        }
        Err(e) => {
            error!("Failed to open sled database at {}: {}", db_path, e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Database initialization failed: {}", e),
            ));
        }
    };

    info!("🚀 Network Activity API starting on 0.0.0.0:8000");
    info!("📂 Reading DB from {}", db_path);

    let state = web::Data::new(AppState { db });

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(state.clone())
            .service(network_activity)
    })
    .bind(("0.0.0.0", 8000))?
    .run()
    .await
}
