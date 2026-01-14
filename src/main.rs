use actix_web::{get, web, App, HttpServer, Responder, middleware};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use log::{info, error, warn, debug};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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
    db_path: String,
    temp_dir: PathBuf,
}

fn copy_database(source: &str, dest: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Remove old copy if it exists
    if dest.exists() {
        fs_extra::dir::remove(dest)?;
    }
    
    // Copy the entire database directory
    let mut copy_options = fs_extra::dir::CopyOptions::new();
    copy_options.overwrite = true;
    copy_options.copy_inside = true;
    
    fs_extra::dir::copy(source, dest, &copy_options)?;
    Ok(())
}

fn read_from_database(db_path: &PathBuf) -> Result<Vec<TransactionRecord>, Box<dyn std::error::Error>> {
    let db = sled::open(db_path)?;
    
    let txs: Vec<TransactionRecord> = db
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
    
    // Close the database connection
    drop(db);
    
    Ok(txs)
}

#[get("/network-activity")]
async fn network_activity(data: web::Data<AppState>) -> impl Responder {
    debug!("Fetching network activity from database");
    
    // Generate unique temp path for this request
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_db_path = data.temp_dir.join(format!("kv_store_{}", timestamp));
    
    // Copy database to temp location
    debug!("Copying database from {} to temp location", data.db_path);
    let copy_result = copy_database(&data.db_path, &temp_db_path);
    
    if let Err(e) = copy_result {
        error!("Failed to copy database: {}", e);
        return web::Json(Vec::<TransactionRecord>::new());
    }
    
    // Read from copied database
    let txs_result = read_from_database(&temp_db_path);
    
    // Clean up temp copy
    if temp_db_path.exists() {
        if let Err(e) = fs_extra::dir::remove(&temp_db_path) {
            warn!("Failed to remove temp database copy: {}", e);
        } else {
            debug!("Cleaned up temp database copy");
        }
    }
    
    let mut txs = match txs_result {
        Ok(transactions) => transactions,
        Err(e) => {
            error!("Failed to read from database: {}", e);
            return web::Json(Vec::<TransactionRecord>::new());
        }
    };

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
    
    // Create temp directory for database copies
    let temp_dir = std::env::temp_dir().join("network_activity_db_copies");
    if !temp_dir.exists() {
        std::fs::create_dir_all(&temp_dir)?;
        info!("Created temp directory for database copies: {:?}", temp_dir);
    } else {
        // Clean up any old copies on startup
        info!("Cleaning up old database copies from temp directory");
        if let Ok(entries) = std::fs::read_dir(&temp_dir) {
            for entry in entries.flatten() {
                if let Err(e) = fs_extra::dir::remove(entry.path()) {
                    warn!("Failed to remove old copy: {}", e);
                }
            }
        }
    }

    info!("🚀 Network Activity API starting on 0.0.0.0:8000");
    info!("📂 Source DB path: {}", db_path);
    info!("📁 Temp copies directory: {:?}", temp_dir);
    info!("💡 Database will be copied to temp location on each API call to avoid locks");

    let state = web::Data::new(AppState {
        db_path: db_path.to_string(),
        temp_dir,
    });

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
