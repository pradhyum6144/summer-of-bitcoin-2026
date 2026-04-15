mod analyzer;
mod block;
mod parser;
mod script;
mod types;

use analyzer::analyze_transaction;
use block::parse_and_analyze_block;
use std::env;
use std::fs;
use types::{ErrorInfo, Fixture, TransactionOutput};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <fixture.json> or {} --block <blk.dat> <rev.dat> <xor.dat>", args[0], args[0]);
        std::process::exit(1);
    }

    // Check for block mode
    if args.len() >= 5 && args[1] == "--block" {
        // Block mode
        let blk_path = &args[2];
        let rev_path = &args[3];
        let xor_path = &args[4];

        match parse_and_analyze_block(blk_path, rev_path, xor_path) {
            Ok(blocks) => {
                // Create output directory
                if let Err(e) = fs::create_dir_all("out") {
                    eprintln!("Failed to create output directory: {}", e);
                    std::process::exit(1);
                }

                // Write each block to a separate file
                for block in &blocks {
                    // Always write if we have a hash — error blocks get written too
                    if let Some(ref header) = block.block_header {
                        let filename = format!("out/{}.json", header.block_hash);
                        let json = serde_json::to_string_pretty(&block).unwrap();
                        if let Err(e) = fs::write(&filename, json) {
                            eprintln!("Failed to write {}: {}", filename, e);
                        }
                    } else if !block.ok {
                        // No hash available — just log, don't exit
                        eprintln!("Block parsing failed (no hash): {:?}", block.error);
                    }
                }

                std::process::exit(0);
            }
            Err(e) => {
                let error_output = serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": "BLOCK_PARSE_ERROR",
                        "message": e.to_string()
                    }
                });
                eprintln!("{}", serde_json::to_string_pretty(&error_output).unwrap());
                std::process::exit(1);
            }
        }
    }

    // Single transaction mode
    let fixture_path = &args[1];

    // Read fixture file
    let fixture_content = match fs::read_to_string(fixture_path) {
        Ok(content) => content,
        Err(e) => {
            let error_output = TransactionOutput {
                ok: false,
                error: Some(ErrorInfo {
                    code: "FILE_READ_ERROR".to_string(),
                    message: format!("Failed to read fixture file: {}", e),
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
            println!("{}", serde_json::to_string_pretty(&error_output).unwrap());
            std::process::exit(1);
        }
    };

    // Parse fixture
    let fixture: Fixture = match serde_json::from_str(&fixture_content) {
        Ok(f) => f,
        Err(e) => {
            let error_output = TransactionOutput {
                ok: false,
                error: Some(ErrorInfo {
                    code: "INVALID_FIXTURE".to_string(),
                    message: format!("Failed to parse fixture JSON: {}", e),
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
            println!("{}", serde_json::to_string_pretty(&error_output).unwrap());
            std::process::exit(1);
        }
    };

    // Analyze transaction
    match analyze_transaction(&fixture.raw_tx, &fixture.prevouts, &fixture.network) {
        Ok(output) => {
            let json = serde_json::to_string_pretty(&output).unwrap();

            // Print to stdout
            println!("{}", json);

            // Write to file
            if let Some(ref txid) = output.txid {
                if let Err(e) = fs::create_dir_all("out") {
                    eprintln!("Failed to create output directory: {}", e);
                    std::process::exit(1);
                }

                let filename = format!("out/{}.json", txid);
                if let Err(e) = fs::write(&filename, json) {
                    eprintln!("Failed to write output file: {}", e);
                    std::process::exit(1);
                }
            }

            if output.ok {
                std::process::exit(0);
            } else {
                std::process::exit(1);
            }
        }
        Err(e) => {
            let error_output = TransactionOutput {
                ok: false,
                error: Some(ErrorInfo {
                    code: "ANALYSIS_ERROR".to_string(),
                    message: format!("Failed to analyze transaction: {}", e),
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
            println!("{}", serde_json::to_string_pretty(&error_output).unwrap());
            std::process::exit(1);
        }
    }
}
