use actix_web::{get, web, App, HttpServer, Responder, middleware};
use log::{info, error, warn, debug};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};


struct AppState {
    db_path: String,
    temp_dir: PathBuf,
}


fn copy_database(source: &str, dest: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if dest.exists() {
        fs_extra::dir::remove(dest)?;
    }
    let mut opts = fs_extra::dir::CopyOptions::new();
    opts.overwrite = true;
    opts.copy_inside = true;
    fs_extra::dir::copy(source, dest, &opts)?;
    Ok(())
}

fn read_from_database(db_path: &PathBuf) -> Result<(Vec<serde_json::Value>, Vec<(String, String)>), Box<dyn std::error::Error>> {
    let db = sled::open(db_path)?;
    
    // Read transactions as raw JSON values
    let mut raw_tx_data = Vec::new();
    let txs: Vec<serde_json::Value> = db
        .scan_prefix("tx:")
        .filter_map(|item| {
            item.ok().and_then(|(_key, v)| {
                if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(&v) {
                    // Store raw JSON with transaction ID for logging
                    if let Some(id) = json_value.get("id").and_then(|v| v.as_str()) {
                        if let Ok(json_str) = serde_json::to_string_pretty(&json_value) {
                            raw_tx_data.push((id.to_string(), json_str));
                        }
                    }
                    Some(json_value)
                } else {
                    None
                }
            })
        })
        .collect();
    
    drop(db);
    Ok((txs, raw_tx_data))
}

#[get("/network-activity")]
async fn network_activity(data: web::Data<AppState>) -> actix_web::Result<impl Responder> {
    debug!("Fetching network activity from database");
    
    let temp_db_path = data.temp_dir.join(format!(
        "kv_store_{}",
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    
    // Copy and read database
    if let Err(e) = copy_database(&data.db_path, &temp_db_path) {
        error!("Failed to copy database: {}", e);
        return Ok(web::Json(Vec::<serde_json::Value>::new()));
    }
    
    let (mut txs, raw_tx_data) = match read_from_database(&temp_db_path) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to read from database: {}", e);
            return Ok(web::Json(Vec::<serde_json::Value>::new()));
        }
    };
    
    // Cleanup temp copy
    if temp_db_path.exists() {
        let _ = fs_extra::dir::remove(&temp_db_path);
    }
    
    info!("Found {} transactions", txs.len());
    
    // Sort by sent_at (newest first) and take 30
    txs.sort_by(|a, b| {
        let a_time = a.get("sent_at").and_then(|v| v.as_str());
        let b_time = b.get("sent_at").and_then(|v| v.as_str());
        match (a_time, b_time) {
            (Some(a), Some(b)) => b.cmp(a), // Reverse for newest first
            _ => std::cmp::Ordering::Equal,
        }
    });
    
    let top_30: Vec<serde_json::Value> = txs.into_iter().take(30).collect();
    let top_30_ids: Vec<String> = top_30
        .iter()
        .filter_map(|tx| tx.get("id").and_then(|v| v.as_str().map(|s| s.to_string())))
        .collect();
    
    // Log raw database entries for the 30 transactions being returned
    info!("=== Raw Database Entries for {} Transactions Being Returned ===", top_30_ids.len());
    for (i, id) in top_30_ids.iter().enumerate() {
        if let Some((_, raw_json)) = raw_tx_data.iter().find(|(tx_id, _)| tx_id == id) {
            info!("--- Transaction {} (ID: {}) ---", i + 1, id);
            info!("{}", raw_json);
        } else {
            warn!("Could not find raw data for transaction ID: {}", id);
        }
    }
    
    info!("Returning {} transactions", top_30.len());
    Ok(web::Json(top_30))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let db_path = "/home/ubuntu/sync_cron_job/kv_store";
    let temp_dir = std::env::temp_dir().join("network_activity_db_copies");
    
    if !temp_dir.exists() {
        std::fs::create_dir_all(&temp_dir)?;
        info!("Created temp directory: {:?}", temp_dir);
    } else {
        info!("Cleaning up old database copies");
        let _ = std::fs::read_dir(&temp_dir)
            .map(|entries| entries.flatten().for_each(|e| { let _ = fs_extra::dir::remove(e.path()); }));
    }

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8001".to_string())
        .parse::<u16>()
        .unwrap_or(8001);

    info!("🚀 Network Activity API starting on 0.0.0.0:{}", port);
    info!("📂 Source DB: {}", db_path);
    info!("📁 Temp dir: {:?}", temp_dir);

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
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
