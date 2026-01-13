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
    
    // Retry logic for database lock (cron job might be writing)
    const MAX_RETRIES: u32 = 5;
    const INITIAL_DELAY_MS: u64 = 500;
    
    let mut db = None;
    let mut last_error = None;
    
    for attempt in 0..MAX_RETRIES {
        match sled::open(&db_path) {
            Ok(database) => {
                info!("Successfully opened database at {} (attempt {})", db_path, attempt + 1);
                db = Some(database);
                break;
            }
            Err(e) => {
                let error_msg = format!("{}", e);
                let is_lock_error = error_msg.contains("lock") || 
                                   error_msg.contains("WouldBlock") ||
                                   error_msg.contains("Resource temporarily unavailable");
                
                if is_lock_error && attempt < MAX_RETRIES - 1 {
                    let delay_ms = INITIAL_DELAY_MS * (1 << attempt); // Exponential backoff
                    warn!("Database locked (attempt {}), retrying in {}ms...", attempt + 1, delay_ms);
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    last_error = Some(e);
                } else {
                    last_error = Some(e);
                    break;
                }
            }
        }
    }
    
    let db = match db {
        Some(database) => database,
        None => {
            let error = last_error.expect("Should have an error if db is None");
            let error_msg = format!("{}", error);
            let is_lock_error = error_msg.contains("lock") || 
                               error_msg.contains("WouldBlock") ||
                               error_msg.contains("Resource temporarily unavailable");
            
            if is_lock_error {
                error!("Failed to open database after {} attempts. Database is locked.", MAX_RETRIES);
                error!("This usually means:");
                error!("  1. Another instance of the server is running");
                error!("  2. The cron job is currently writing to the database");
                error!("  3. The database was not properly closed");
                error!("");
                error!("Troubleshooting:");
                error!("  - Check for other instances: ps aux | grep network_activity_server");
                error!("  - Check if cron job is running: ps aux | grep sync_cron_job");
                error!("  - Wait a few seconds and try again");
            } else {
                error!("Failed to open sled database at {}: {}", db_path, error);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Database initialization failed: {}", error),
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
