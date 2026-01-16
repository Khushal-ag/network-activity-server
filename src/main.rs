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

#[derive(Debug, Serialize)]
pub struct TransactionResult {
    pub signatures: Vec<String>,
    // Allow additional fields that might exist in the database
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
        
        Ok(TransactionResult {
            signatures,
            extra: map,
        })
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
    pub private_key: String, // Don't expose private keys in API
    #[serde(default)]
    pub chain: ChainTarget,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub accumulated_credits: u128,
}

#[derive(Debug, Serialize)]
pub struct EnhancedTransactionRecord {
    pub id: String,
    pub tx_result: TransactionResult,
    pub sent_at: DateTime<Utc>,
    pub status: String,
    pub chain: Option<ChainTarget>,
    pub from_address: Option<String>,
    pub user_key_info: Option<UserKeyInfo>,
    pub transaction_purpose: Option<String>, // e.g., IPFS URL or description
}

// Simple frontend format - just raw transaction fields
#[derive(Debug, Serialize)]
pub struct FrontendActivityRecord {
    pub id: String,
    pub transaction_id: String,
    pub user_address: Option<String>, // Full wallet address
    pub signatures: Vec<String>,
    pub sent_at: DateTime<Utc>,
    pub status: String,
    pub chain: Option<String>, // "solana" or "base"
    pub ipfs_url: Option<String>,
    pub credits: Option<u128>,
    pub user_accumulated_credits: Option<u128>,
    pub tx_result: serde_json::Value, // All other transaction result fields
}


#[derive(Debug, Serialize)]
pub struct UserKeyInfo {
    pub pubkey: String,
    pub chain: ChainTarget,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub accumulated_credits: u128,
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

fn read_from_database(db_path: &PathBuf) -> Result<(Vec<TransactionRecord>, Vec<UserKeyRecord>), Box<dyn std::error::Error>> {
    let db = sled::open(db_path)?;
    
    // Read transactions
    let txs: Vec<TransactionRecord> = db
        .scan_prefix("tx:")
        .filter_map(|item| {
            match item {
                Ok((_key, v)) => {
                    // Try to deserialize, but be flexible with TransactionResult
                    match serde_json::from_slice::<serde_json::Value>(&v) {
                        Ok(json_value) => {
                            // Try to deserialize as TransactionRecord
                            match serde_json::from_value::<TransactionRecord>(json_value.clone()) {
                                Ok(tx) => Some(tx),
                                Err(_) => {
                                    // If that fails, try to construct manually
                                    if let (Some(id), Some(tx_result), Some(sent_at), Some(status)) = (
                                        json_value.get("id").and_then(|v| v.as_str()),
                                        json_value.get("tx_result"),
                                        json_value.get("sent_at").and_then(|v| {
                                            serde_json::from_value::<DateTime<Utc>>(v.clone()).ok()
                                        }),
                                        json_value.get("status").and_then(|v| v.as_str()),
                                    ) {
                                        let signatures = tx_result
                                            .get("signatures")
                                            .and_then(|v| v.as_array())
                                            .map(|arr| {
                                                arr.iter()
                                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                                    .collect()
                                            })
                                            .unwrap_or_default();
                                        
                                        let mut extra = serde_json::Map::new();
                                        if let Some(obj) = tx_result.as_object() {
                                            for (k, v) in obj {
                                                if k != "signatures" {
                                                    extra.insert(k.clone(), v.clone());
                                                }
                                            }
                                        }
                                        
                                        Some(TransactionRecord {
                                            id: id.to_string(),
                                            tx_result: TransactionResult {
                                                signatures,
                                                extra,
                                            },
                                            sent_at,
                                            status: status.to_string(),
                                        })
                                    } else {
                                        warn!("Failed to parse transaction record structure");
                                        None
                                    }
                                }
                            }
                        }
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
    
    // Read user keys
    let user_keys: Vec<UserKeyRecord> = db
        .scan_prefix("user_key:")
        .filter_map(|item| {
            match item {
                Ok((_key, v)) => {
                    match serde_json::from_slice::<UserKeyRecord>(&v) {
                        Ok(key) => Some(key),
                        Err(e) => {
                            debug!("Failed to deserialize user key record: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    debug!("Error reading user key from database: {}", e);
                    None
                }
            }
        })
        .collect();

    // Close the database connection
    drop(db);
    
    Ok((txs, user_keys))
}

#[get("/network-activity")]
async fn network_activity(data: web::Data<AppState>) -> actix_web::Result<impl Responder> {
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
        return Ok(web::Json(Vec::<FrontendActivityRecord>::new()));
    }
    
    // Read from copied database
    let db_result = read_from_database(&temp_db_path);
    
    // Clean up temp copy
    if temp_db_path.exists() {
        if let Err(e) = fs_extra::dir::remove(&temp_db_path) {
            warn!("Failed to remove temp database copy: {}", e);
        } else {
            debug!("Cleaned up temp database copy");
        }
    }
    
    let (mut txs, user_keys) = match db_result {
        Ok((transactions, keys)) => (transactions, keys),
        Err(e) => {
            error!("Failed to read from database: {}", e);
            return Ok(web::Json(Vec::<FrontendActivityRecord>::new()));
        }
    };

    info!("Found {} total transactions and {} user keys", txs.len(), user_keys.len());
    
    txs.sort_by(|a, b| b.sent_at.cmp(&a.sent_at));

    let recent = txs.into_iter().take(30);
    
    // First enhance transactions with user key information
    let enhanced: Vec<EnhancedTransactionRecord> = recent
        .map(|tx| {
            // Try to match transaction with user key by checking if any signature matches a user key
            // or if we can infer chain from transaction data
            let mut matched_key: Option<&UserKeyRecord> = None;
            let mut inferred_chain: Option<ChainTarget> = None;
            
            // Infer chain from signature format
            // Signatures starting with 0x are EVM/Base, base58 are Solana
            if inferred_chain.is_none() {
                if let Some(first_sig) = tx.tx_result.signatures.first() {
                    if first_sig.starts_with("0x") {
                        inferred_chain = Some(ChainTarget::Base);
                    } else if first_sig.len() > 40 && !first_sig.starts_with("0x") {
                        // Solana signatures are typically base58 encoded, longer and don't start with 0x
                        inferred_chain = Some(ChainTarget::Solana);
                    }
                }
            }
            
            // Check if any signature might match a user key pubkey
            for sig in &tx.tx_result.signatures {
                // Try to find matching user key
                if let Some(key) = user_keys.iter().find(|k| {
                    k.pubkey == *sig || 
                    sig.contains(&k.pubkey) || 
                    k.pubkey.contains(sig)
                }) {
                    matched_key = Some(key);
                    // Override inferred chain with user key's chain if we found a match
                    if inferred_chain.is_none() {
                        inferred_chain = Some(key.chain);
                    }
                    break;
                }
            }
            
            // If no match found, try to infer chain from extra fields
            if inferred_chain.is_none() {
                if let Some(chain_str) = tx.tx_result.extra.get("chain")
                    .and_then(|v| v.as_str())
                {
                    inferred_chain = match chain_str.to_lowercase().as_str() {
                        "solana" => Some(ChainTarget::Solana),
                        "base" | "evm" => Some(ChainTarget::Base),
                        _ => None,
                    };
                }
            }
            
            // Extract from_address if available
            // For EVM transactions, the first signature might be the address
            let from_address = tx.tx_result.extra
                .get("from")
                .or_else(|| tx.tx_result.extra.get("from_address"))
                .or_else(|| tx.tx_result.extra.get("sender"))
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .or_else(|| {
                    // For Base/EVM, if we have a signature starting with 0x, it might be an address
                    if inferred_chain == Some(ChainTarget::Base) {
                        tx.tx_result.signatures.first()
                            .and_then(|sig| {
                                // Check if it looks like an address (0x followed by 40 hex chars)
                                if sig.starts_with("0x") && sig.len() == 42 {
                                    Some(sig.clone())
                                } else {
                                    None
                                }
                            })
                    } else {
                        None
                    }
                });
            
            // Extract transaction purpose (e.g., IPFS URL)
            let transaction_purpose = tx.tx_result.extra
                .get("ipfs_url")
                .or_else(|| tx.tx_result.extra.get("purpose"))
                .or_else(|| tx.tx_result.extra.get("description"))
                .and_then(|v| v.as_str().map(|s| s.to_string()));
            
            EnhancedTransactionRecord {
                id: tx.id,
                tx_result: tx.tx_result,
                sent_at: tx.sent_at,
                status: tx.status,
                chain: inferred_chain,
                from_address,
                user_key_info: matched_key.map(|k| UserKeyInfo {
                    pubkey: k.pubkey.clone(),
                    chain: k.chain,
                    created_at: k.created_at,
                    expires_at: k.expires_at,
                    accumulated_credits: k.accumulated_credits,
                }),
                transaction_purpose,
            }
        })
        .collect();
    
    // Transform to simple frontend format - just raw fields
    let frontend_records: Vec<FrontendActivityRecord> = enhanced
        .into_iter()
        .map(|tx| {
            // Get user address from various sources
            let user_address = tx.from_address
                .clone()
                .or_else(|| {
                    tx.user_key_info
                        .as_ref()
                        .map(|info| info.pubkey.clone())
                })
                .or_else(|| {
                    tx.tx_result.signatures.first()
                        .cloned()
                });
            
            // Get credits from transaction data
            let credits = tx.tx_result.extra
                .get("credits")
                .or_else(|| tx.tx_result.extra.get("reward"))
                .or_else(|| tx.tx_result.extra.get("amount"))
                .and_then(|v| v.as_u64().map(|n| n as u128))
                .filter(|&credits| credits > 0);
            
            let user_accumulated_credits = tx.tx_result.extra
                .get("user_accumulated_credits")
                .and_then(|v| v.as_u64().map(|n| n as u128));
            
            // Get IPFS URL
            let ipfs_url = tx.transaction_purpose
                .clone()
                .filter(|url| url.contains("ipfs"));
            
            // Convert chain to string
            let chain = tx.chain.map(|c| match c {
                ChainTarget::Solana => "solana".to_string(),
                ChainTarget::Base => "base".to_string(),
            });
            
            // Convert tx_result to JSON value for all extra fields
            let mut tx_result_json = serde_json::Map::new();
            tx_result_json.insert("signatures".to_string(), serde_json::to_value(&tx.tx_result.signatures).unwrap());
            for (k, v) in tx.tx_result.extra {
                tx_result_json.insert(k, v);
            }
            
            FrontendActivityRecord {
                id: tx.id.clone(),
                transaction_id: tx.id,
                user_address,
                signatures: tx.tx_result.signatures,
                sent_at: tx.sent_at,
                status: tx.status,
                chain,
                ipfs_url,
                credits,
                user_accumulated_credits,
                tx_result: serde_json::Value::Object(tx_result_json),
            }
        })
        .collect();
    
    info!("Returning {} transactions", frontend_records.len());
    debug!("Transaction IDs: {:?}", frontend_records.iter().map(|t| &t.id).collect::<Vec<_>>());

    Ok(web::Json(frontend_records))
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

    // Get port from environment variable or default to 8001
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8001".to_string())
        .parse::<u16>()
        .unwrap_or(8001);

    info!("🚀 Network Activity API starting on 0.0.0.0:{}", port);
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
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
