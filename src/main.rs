use actix_web::{get, web, App, HttpServer, Responder, middleware};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use log::{info, error, warn, debug};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ChainTarget {
    #[default]
    #[serde(alias = "solana")]
    Solana,
    #[serde(alias = "base", alias = "evm")]
    Base,
}

impl ChainTarget {
    fn as_str(&self) -> &'static str {
        match self {
            ChainTarget::Solana => "solana",
            ChainTarget::Base => "base",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TransactionResult {
    pub signatures: Vec<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for TransactionResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut map = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        let signatures = map
            .remove("signatures")
            .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
            .unwrap_or_default();
        Ok(TransactionResult { signatures, extra: map })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub id: String,
    pub tx_result: TransactionResult,
    pub sent_at: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserKeyRecord {
    pub id: String,
    pub pubkey: String,
    #[serde(skip_serializing)]
    pub private_key: String,
    #[serde(default)]
    pub chain: ChainTarget,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub accumulated_credits: u128,
}

#[derive(Debug, Serialize)]
pub struct FrontendActivityRecord {
    pub id: String,
    pub transaction_id: String,
    pub user_address: Option<String>,
    pub signatures: Vec<String>,
    pub sent_at: DateTime<Utc>,
    pub status: String,
    pub chain: Option<String>,
    pub ipfs_url: Option<String>,
    pub credits: Option<u128>,
    pub user_accumulated_credits: Option<u128>,
    pub tx_result: serde_json::Value,
}

struct AppState {
    db_path: String,
    temp_dir: PathBuf,
}

// Helper: Extract value from JSON map by multiple possible keys
fn get_str_from_map(map: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| map.get(*key)?.as_str().map(|s| s.to_string()))
}

fn get_u64_from_map(map: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> Option<u128> {
    keys.iter()
        .find_map(|key| map.get(*key)?.as_u64().map(|n| n as u128))
}

// Helper: Infer chain from signature format
fn infer_chain_from_signature(sig: &str) -> Option<ChainTarget> {
    if sig.starts_with("0x") {
        Some(ChainTarget::Base)
    } else if sig.len() > 40 {
        Some(ChainTarget::Solana)
    } else {
        None
    }
}

// Helper: Find matching user key for transaction
fn find_matching_user_key<'a>(signatures: &[String], user_keys: &'a [UserKeyRecord]) -> Option<&'a UserKeyRecord> {
    for sig in signatures {
        if let Some(key) = user_keys.iter().find(|k| {
            k.pubkey == *sig || sig.contains(&k.pubkey) || k.pubkey.contains(sig)
        }) {
            return Some(key);
        }
    }
    None
}

// Helper: Extract address from transaction
fn extract_address(tx: &TransactionRecord, chain: Option<ChainTarget>, user_key: Option<&UserKeyRecord>) -> Option<String> {
    // Try from transaction extra fields
    get_str_from_map(&tx.tx_result.extra, &["from", "from_address", "sender", "wallet", "account"])
        // Try from user key
        .or_else(|| user_key.map(|k| k.pubkey.clone()))
        // For Base/EVM: try signature if it looks like an address (42 chars = 0x + 40 hex)
        .or_else(|| {
            if chain == Some(ChainTarget::Base) {
                tx.tx_result.signatures.first().and_then(|sig| {
                    if sig.starts_with("0x") && sig.len() == 42 {
                        Some(sig.clone())
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        })
        // Fallback: use first signature as identifier (even if it's a transaction hash)
        .or_else(|| tx.tx_result.signatures.first().cloned())
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

fn read_from_database(db_path: &PathBuf) -> Result<(Vec<TransactionRecord>, Vec<UserKeyRecord>, Vec<(String, String)>), Box<dyn std::error::Error>> {
    let db = sled::open(db_path)?;
    
    // Read transactions with raw JSON data
    let mut raw_tx_data = Vec::new();
    let txs: Vec<TransactionRecord> = db
        .scan_prefix("tx:")
        .filter_map(|item| {
            item.ok().and_then(|(_key, v)| {
                // Store raw JSON with transaction ID for later logging
                if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(&v) {
                    if let Some(id) = json_value.get("id").and_then(|v| v.as_str()) {
                        if let Ok(json_str) = serde_json::to_string_pretty(&json_value) {
                            raw_tx_data.push((id.to_string(), json_str));
                        }
                    }
                    
                    serde_json::from_value::<TransactionRecord>(json_value).ok()
                } else {
                    None
                }
            })
        })
        .collect();
    
    // Read user keys
    let user_keys: Vec<UserKeyRecord> = db
        .scan_prefix("user_key:")
        .filter_map(|item| {
            item.ok()
                .and_then(|(_key, v)| serde_json::from_slice::<UserKeyRecord>(&v).ok())
        })
        .collect();
    
    drop(db);
    Ok((txs, user_keys, raw_tx_data))
}

fn enhance_transaction(tx: TransactionRecord, user_keys: &[UserKeyRecord]) -> FrontendActivityRecord {
    // Infer chain
    let chain = tx.tx_result.signatures.first()
        .and_then(|sig| infer_chain_from_signature(sig))
        .or_else(|| {
            get_str_from_map(&tx.tx_result.extra, &["chain"])
                .and_then(|s| match s.to_lowercase().as_str() {
                    "solana" => Some(ChainTarget::Solana),
                    "base" | "evm" => Some(ChainTarget::Base),
                    _ => None,
                })
        });
    
    // Find matching user key
    let user_key = find_matching_user_key(&tx.tx_result.signatures, user_keys);
    let chain = chain.or_else(|| user_key.map(|k| k.chain));
    
    // Extract fields
    let user_address = extract_address(&tx, chain, user_key);
    let ipfs_url = get_str_from_map(&tx.tx_result.extra, &["ipfs_url", "purpose", "description"])
        .filter(|url| url.contains("ipfs"));
    let credits = get_u64_from_map(&tx.tx_result.extra, &["credits", "reward", "amount"])
        .filter(|&c| c > 0);
    let user_accumulated_credits = get_u64_from_map(&tx.tx_result.extra, &["user_accumulated_credits"]);
    
    // Build tx_result JSON
    let mut tx_result_json = serde_json::Map::new();
    tx_result_json.insert("signatures".to_string(), serde_json::to_value(&tx.tx_result.signatures).unwrap());
    tx_result_json.extend(tx.tx_result.extra);
    
    FrontendActivityRecord {
        id: tx.id.clone(),
        transaction_id: tx.id,
        user_address,
        signatures: tx.tx_result.signatures,
        sent_at: tx.sent_at,
        status: tx.status,
        chain: chain.map(|c| c.as_str().to_string()),
        ipfs_url,
        credits,
        user_accumulated_credits,
        tx_result: serde_json::Value::Object(tx_result_json),
    }
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
        return Ok(web::Json(Vec::<FrontendActivityRecord>::new()));
    }
    
    let (mut txs, user_keys, raw_tx_data) = match read_from_database(&temp_db_path) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to read from database: {}", e);
            return Ok(web::Json(Vec::<FrontendActivityRecord>::new()));
        }
    };
    
    // Cleanup temp copy
    if temp_db_path.exists() {
        let _ = fs_extra::dir::remove(&temp_db_path);
    }
    
    info!("Found {} transactions and {} user keys", txs.len(), user_keys.len());
    
    // Sort and take 30
    txs.sort_by(|a, b| b.sent_at.cmp(&a.sent_at));
    let top_30_ids: Vec<String> = txs.iter().take(30).map(|tx| tx.id.clone()).collect();
    
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
    
    // Enhance and return
    let records: Vec<FrontendActivityRecord> = txs
        .into_iter()
        .take(30)
        .map(|tx| enhance_transaction(tx, &user_keys))
        .collect();
    
    info!("Returning {} transactions", records.len());
    Ok(web::Json(records))
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
