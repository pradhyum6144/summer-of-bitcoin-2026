mod analyzer;
mod block;
mod parser;
mod script;
mod types;

use analyzer::analyze_transaction;
use block::parse_and_analyze_block;
use axum::{
    extract::{DefaultBodyLimit, Multipart},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::env;
use std::fs;
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/health", get(health_handler))
        .route("/api/analyze", post(analyze_handler))
        .route("/api/analyze-block", post(analyze_block_handler))
        .layer(DefaultBodyLimit::max(1024 * 1024 * 1024)) // 1 GB — covers large blk*.dat files
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    // Print URL only after the socket is bound so callers can connect immediately
    println!("http://127.0.0.1:{}", port);
    axum::serve(listener, app).await.unwrap();
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

#[derive(Deserialize)]
struct AnalyzeRequest {
    raw_tx: String,
    prevouts: Vec<types::Prevout>,
    #[serde(default = "default_network")]
    network: String,
}

fn default_network() -> String {
    "mainnet".to_string()
}

async fn analyze_handler(Json(req): Json<AnalyzeRequest>) -> impl IntoResponse {
    match analyze_transaction(&req.raw_tx, &req.prevouts, &req.network) {
        Ok(result) => (StatusCode::OK, Json(result)),
        Err(e) => {
            let error_response = types::TransactionOutput {
                ok: false,
                error: Some(types::ErrorInfo {
                    code: "ANALYSIS_ERROR".to_string(),
                    message: e.to_string(),
                }),
                network: None,
                segwit: None,
                txid: None,
                wtxid: None,
                version: None,
                locktime: None,
                size_bytes: None,
                weight: None,
                vbytes: None,
                total_input_sats: None,
                total_output_sats: None,
                fee_sats: None,
                fee_rate_sat_vb: None,
                rbf_signaling: None,
                locktime_type: None,
                locktime_value: None,
                segwit_savings: None,
                vin: None,
                vout: None,
                warnings: None,
            };
            (StatusCode::BAD_REQUEST, Json(error_response))
        }
    }
}

async fn analyze_block_handler(mut multipart: Multipart) -> impl IntoResponse {
    let temp_dir = std::env::temp_dir();
    let mut blk_path = None;
    let mut rev_path = None;
    let mut xor_path = None;

    // Process multipart form data
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        let data = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        match name.as_str() {
            "blk" => {
                let p = temp_dir.join("uploaded_blk.dat");
                if let Err(_) = fs::write(&p, &data) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "ok": false,
                            "error": {
                                "code": "FILE_WRITE_ERROR",
                                "message": "Failed to write blk file"
                            }
                        })),
                    );
                }
                blk_path = Some(p);
            }
            "rev" => {
                let p = temp_dir.join("uploaded_rev.dat");
                if let Err(_) = fs::write(&p, &data) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "ok": false,
                            "error": {
                                "code": "FILE_WRITE_ERROR",
                                "message": "Failed to write rev file"
                            }
                        })),
                    );
                }
                rev_path = Some(p);
            }
            "xor" => {
                let p = temp_dir.join("uploaded_xor.dat");
                if let Err(_) = fs::write(&p, &data) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "ok": false,
                            "error": {
                                "code": "FILE_WRITE_ERROR",
                                "message": "Failed to write xor file"
                            }
                        })),
                    );
                }
                xor_path = Some(p);
            }
            _ => continue,
        }
    }

    // Validate all files are present
    let blk = match blk_path {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": "MISSING_FILE",
                        "message": "Missing blk*.dat file"
                    }
                })),
            );
        }
    };

    let rev = match rev_path {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": "MISSING_FILE",
                        "message": "Missing rev*.dat file"
                    }
                })),
            );
        }
    };

    let xor = match xor_path {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": "MISSING_FILE",
                        "message": "Missing xor.dat file"
                    }
                })),
            );
        }
    };

    // Parse and analyze the block
    let result = parse_and_analyze_block(
        blk.to_str().unwrap(),
        rev.to_str().unwrap(),
        xor.to_str().unwrap(),
    );

    // Clean up temp files
    let _ = fs::remove_file(blk);
    let _ = fs::remove_file(rev);
    let _ = fs::remove_file(xor);

    match result {
        Ok(blocks) => (StatusCode::OK, Json(serde_json::json!(blocks))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": {
                    "code": "BLOCK_PARSE_ERROR",
                    "message": e.to_string()
                }
            })),
        ),
    }
}
