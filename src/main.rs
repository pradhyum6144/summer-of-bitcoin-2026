mod parser;
mod analysis;
mod output;

use std::env;
use std::fs;
use std::path::Path;
use std::process;

fn error_json(code: &str, message: &str) {
    let j = serde_json::json!({"ok": false, "error": {"code": code, "message": message}});
    println!("{}", j);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] != "--block" {
        error_json("INVALID_ARGS", "Usage: sherlock --block <blk.dat> <rev.dat> <xor.dat>");
        eprintln!("Error: Use --block flag.");
        process::exit(1);
    }

    if args.len() < 5 {
        error_json("INVALID_ARGS", "Block mode requires: --block <blk.dat> <rev.dat> <xor.dat>");
        eprintln!("Error: Block mode requires 3 file arguments.");
        process::exit(1);
    }

    let blk_path = &args[2];
    let rev_path = &args[3];
    let xor_path = &args[4];

    for p in [blk_path, rev_path, xor_path] {
        if !Path::new(p).exists() {
            error_json("FILE_NOT_FOUND", &format!("File not found: {}", p));
            eprintln!("Error: File not found: {}", p);
            process::exit(1);
        }
    }

    // Read XOR key
    let xor_key = match fs::read(xor_path) {
        Ok(data) => data,
        Err(e) => {
            error_json("IO_ERROR", &format!("Failed to read xor.dat: {}", e));
            process::exit(1);
        }
    };

    // Read and decode blk file
    let blk_raw = match fs::read(blk_path) {
        Ok(data) => data,
        Err(e) => {
            error_json("IO_ERROR", &format!("Failed to read blk file: {}", e));
            process::exit(1);
        }
    };
    let blk_data = parser::xor_decode(&blk_raw, &xor_key);

    // Read and decode rev file
    let rev_raw = match fs::read(rev_path) {
        Ok(data) => data,
        Err(e) => {
            error_json("IO_ERROR", &format!("Failed to read rev file: {}", e));
            process::exit(1);
        }
    };
    let rev_data = parser::xor_decode(&rev_raw, &xor_key);

    // Parse blocks
    let blocks = match parser::parse_blocks(&blk_data) {
        Ok(b) => b,
        Err(e) => {
            error_json("PARSE_ERROR", &format!("Failed to parse blocks: {}", e));
            process::exit(1);
        }
    };

    eprintln!("Parsed {} blocks", blocks.len());

    // Parse undo data
    let undos = match parser::parse_rev_blocks(&rev_data, &blocks) {
        Ok(u) => u,
        Err(e) => {
            error_json("PARSE_ERROR", &format!("Failed to parse rev data: {}", e));
            process::exit(1);
        }
    };

    eprintln!("Parsed {} undo records", undos.len());

    // Match undo records to blocks by non-coinbase tx count
    let matched_undos = match_undos_to_blocks(&blocks, &undos);

    // Analyze each block
    let mut block_analyses = Vec::with_capacity(blocks.len());
    for (i, block) in blocks.iter().enumerate() {
        let undo = matched_undos[i].map(|idx| &undos[idx]);
        let ba = analysis::analyze_block(block, undo);
        eprintln!(
            "  Block {} (h={}): {} txs, {} flagged",
            i, ba.block_height, ba.tx_count, ba.flagged_count
        );
        block_analyses.push(ba);
    }

    // Generate output
    let blk_stem = Path::new(blk_path)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy();
    let file_name = format!("{}.dat", blk_stem);

    // Create output directory
    fs::create_dir_all("out").ok();

    // Write JSON
    let json_output = output::build_output_json(&file_name, &block_analyses);
    let json_path = format!("out/{}.json", blk_stem);
    let json_str = match serde_json::to_string_pretty(&json_output) {
        Ok(s) => s,
        Err(e) => {
            error_json("SERIALIZE_ERROR", &format!("Failed to serialize JSON: {}", e));
            process::exit(1);
        }
    };
    match fs::write(&json_path, json_str) {
        Ok(_) => eprintln!("Wrote {}", json_path),
        Err(e) => {
            error_json("IO_ERROR", &format!("Failed to write JSON: {}", e));
            process::exit(1);
        }
    }

    // Write Markdown
    let md_output = output::build_markdown_report(&file_name, &block_analyses);
    let md_path = format!("out/{}.md", blk_stem);
    match fs::write(&md_path, md_output) {
        Ok(_) => eprintln!("Wrote {}", md_path),
        Err(e) => {
            error_json("IO_ERROR", &format!("Failed to write Markdown: {}", e));
            process::exit(1);
        }
    }

    eprintln!("Done.");
}

/// Match undo records to blocks. For each block, find the undo record with
/// matching non-coinbase tx count. Returns a vec of Option<undo_index>.
fn match_undos_to_blocks(
    blocks: &[parser::Block],
    undos: &[parser::BlockUndo],
) -> Vec<Option<usize>> {
    let mut result = vec![None; blocks.len()];
    let mut used = vec![false; undos.len()];

    for (bi, block) in blocks.iter().enumerate() {
        let expected = block.transactions.len().saturating_sub(1);
        // First try same-index match
        if bi < undos.len() && undos[bi].tx_undos.len() == expected && !used[bi] {
            result[bi] = Some(bi);
            used[bi] = true;
            continue;
        }
        // Search for matching undo
        for (ui, undo) in undos.iter().enumerate() {
            if !used[ui] && undo.tx_undos.len() == expected {
                // Verify input counts match for first few txs
                let mut matches = true;
                let non_cb_txs: Vec<&parser::Transaction> = block.transactions.iter()
                    .filter(|tx| !parser::is_coinbase(tx))
                    .collect();
                for (ti, tx) in non_cb_txs.iter().take(3).enumerate() {
                    if ti < undo.tx_undos.len()
                        && undo.tx_undos[ti].prevouts.len() != tx.inputs.len()
                    {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    result[bi] = Some(ui);
                    used[ui] = true;
                    break;
                }
            }
        }
    }
    result
}
