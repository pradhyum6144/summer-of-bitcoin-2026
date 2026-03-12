use crate::analysis::*;
use serde_json::{json, Value};
use std::collections::HashMap;

const HEURISTIC_IDS: &[&str] = &[
    "cioh",
    "change_detection",
    "coinjoin",
    "consolidation",
    "round_number_payment",
    "address_reuse",
    "self_transfer",
];

// ─── JSON Output ────────────────────────────────────────────────────────────

fn tx_analysis_to_json(ta: &TxAnalysis) -> Value {
    let mut heuristics = serde_json::Map::new();

    heuristics.insert("cioh".to_string(), json!({
        "detected": ta.heuristics.cioh.detected,
    }));

    let mut cd = serde_json::Map::new();
    cd.insert("detected".to_string(), json!(ta.heuristics.change_detection.detected));
    if ta.heuristics.change_detection.detected {
        cd.insert("likely_change_index".to_string(),
            json!(ta.heuristics.change_detection.likely_change_index));
        cd.insert("method".to_string(),
            json!(ta.heuristics.change_detection.method));
        cd.insert("confidence".to_string(),
            json!(ta.heuristics.change_detection.confidence));
    }
    heuristics.insert("change_detection".to_string(), Value::Object(cd));

    heuristics.insert("coinjoin".to_string(), json!({
        "detected": ta.heuristics.coinjoin.detected,
    }));

    heuristics.insert("consolidation".to_string(), json!({
        "detected": ta.heuristics.consolidation.detected,
    }));

    heuristics.insert("round_number_payment".to_string(), json!({
        "detected": ta.heuristics.round_number.detected,
    }));

    heuristics.insert("address_reuse".to_string(), json!({
        "detected": ta.heuristics.address_reuse.detected,
    }));

    heuristics.insert("self_transfer".to_string(), json!({
        "detected": ta.heuristics.self_transfer.detected,
    }));

    json!({
        "txid": ta.txid,
        "heuristics": Value::Object(heuristics),
        "classification": ta.classification.as_str(),
    })
}

fn compute_fee_rate_stats(analyses: &[&TxAnalysis]) -> Value {
    let mut rates: Vec<f64> = analyses.iter()
        .filter_map(|ta| ta.fee_rate)
        .filter(|r| r.is_finite() && *r >= 0.0)
        .collect();

    if rates.is_empty() {
        return json!({
            "min_sat_vb": 0.0,
            "max_sat_vb": 0.0,
            "median_sat_vb": 0.0,
            "mean_sat_vb": 0.0,
        });
    }

    rates.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let min = rates[0];
    let max = rates[rates.len() - 1];
    let mean = rates.iter().sum::<f64>() / rates.len() as f64;
    let median = if rates.len() % 2 == 0 {
        (rates[rates.len() / 2 - 1] + rates[rates.len() / 2]) / 2.0
    } else {
        rates[rates.len() / 2]
    };

    json!({
        "min_sat_vb": round2(min),
        "max_sat_vb": round2(max),
        "median_sat_vb": round2(median),
        "mean_sat_vb": round2(mean),
    })
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn build_script_type_dist(dist: &HashMap<String, usize>) -> Value {
    let keys = ["p2wpkh", "p2tr", "p2sh", "p2pkh", "p2wsh", "p2pk", "op_return", "unknown"];
    let mut obj = serde_json::Map::new();
    for key in &keys {
        let count = dist.get(*key).copied().unwrap_or(0);
        obj.insert(key.to_string(), json!(count));
    }
    Value::Object(obj)
}

fn build_block_json(ba: &BlockAnalysis, include_txs: bool) -> Value {
    // Non-coinbase tx analyses for fee stats
    let non_cb_analyses: Vec<&TxAnalysis> = ba.tx_analyses.iter()
        .filter(|ta| ta.fee.is_some())
        .collect();

    let fee_stats = compute_fee_rate_stats(&non_cb_analyses);

    let transactions = if include_txs {
        let txs: Vec<Value> = ba.tx_analyses.iter()
            .map(tx_analysis_to_json)
            .collect();
        json!(txs)
    } else {
        json!([])
    };

    json!({
        "block_hash": ba.block_hash,
        "block_height": ba.block_height,
        "tx_count": ba.tx_count,
        "analysis_summary": {
            "total_transactions_analyzed": ba.tx_count,
            "heuristics_applied": HEURISTIC_IDS,
            "flagged_transactions": ba.flagged_count,
            "script_type_distribution": build_script_type_dist(&ba.script_type_dist),
            "fee_rate_stats": fee_stats,
        },
        "transactions": transactions,
    })
}

pub fn build_output_json(
    file_name: &str,
    block_analyses: &[BlockAnalysis],
) -> Value {
    // Aggregate stats across all blocks
    let total_txs: usize = block_analyses.iter().map(|ba| ba.tx_count).sum();
    let total_flagged: usize = block_analyses.iter().map(|ba| ba.flagged_count).sum();

    // Aggregate script type distribution
    let mut agg_dist: HashMap<String, usize> = HashMap::new();
    for ba in block_analyses {
        for (k, v) in &ba.script_type_dist {
            *agg_dist.entry(k.clone()).or_insert(0) += v;
        }
    }

    // Aggregate fee rate stats across all non-coinbase txs
    let all_non_cb: Vec<&TxAnalysis> = block_analyses.iter()
        .flat_map(|ba| ba.tx_analyses.iter())
        .filter(|ta| ta.fee.is_some())
        .collect();
    let agg_fee_stats = compute_fee_rate_stats(&all_non_cb);

    // Build per-block JSON (full txs only for first block)
    let blocks_json: Vec<Value> = block_analyses.iter().enumerate()
        .map(|(i, ba)| build_block_json(ba, i == 0))
        .collect();

    json!({
        "ok": true,
        "mode": "chain_analysis",
        "file": file_name,
        "block_count": block_analyses.len(),
        "analysis_summary": {
            "total_transactions_analyzed": total_txs,
            "heuristics_applied": HEURISTIC_IDS,
            "flagged_transactions": total_flagged,
            "script_type_distribution": build_script_type_dist(&agg_dist),
            "fee_rate_stats": agg_fee_stats,
        },
        "blocks": blocks_json,
    })
}

// ─── Markdown Output ────────────────────────────────────────────────────────

pub fn build_markdown_report(
    file_name: &str,
    block_analyses: &[BlockAnalysis],
) -> String {
    let mut md = String::new();

    let total_txs: usize = block_analyses.iter().map(|ba| ba.tx_count).sum();
    let total_flagged: usize = block_analyses.iter().map(|ba| ba.flagged_count).sum();

    md.push_str(&format!("# Chain Analysis Report: {}\n\n", file_name));
    md.push_str("## File Overview\n\n");
    md.push_str(&format!("| Property | Value |\n|---|---|\n"));
    md.push_str(&format!("| Source file | `{}` |\n", file_name));
    md.push_str(&format!("| Blocks | {} |\n", block_analyses.len()));
    md.push_str(&format!("| Total transactions | {} |\n", total_txs));
    md.push_str(&format!("| Flagged transactions | {} |\n", total_flagged));
    md.push_str("\n");

    // Aggregate script distribution
    let mut agg_dist: HashMap<String, usize> = HashMap::new();
    for ba in block_analyses {
        for (k, v) in &ba.script_type_dist {
            *agg_dist.entry(k.clone()).or_insert(0) += v;
        }
    }

    md.push_str("## Script Type Distribution\n\n");
    md.push_str("| Script Type | Count |\n|---|---|\n");
    let mut dist_vec: Vec<(&String, &usize)> = agg_dist.iter().collect();
    dist_vec.sort_by(|a, b| b.1.cmp(a.1));
    for (k, v) in &dist_vec {
        md.push_str(&format!("| {} | {} |\n", k, v));
    }
    md.push_str("\n");

    // Fee rate stats
    let all_non_cb: Vec<&TxAnalysis> = block_analyses.iter()
        .flat_map(|ba| ba.tx_analyses.iter())
        .filter(|ta| ta.fee.is_some())
        .collect();

    let mut rates: Vec<f64> = all_non_cb.iter()
        .filter_map(|ta| ta.fee_rate)
        .filter(|r| r.is_finite() && *r >= 0.0)
        .collect();
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap());

    if !rates.is_empty() {
        md.push_str("## Fee Rate Distribution\n\n");
        md.push_str("| Stat | sat/vB |\n|---|---|\n");
        md.push_str(&format!("| Min | {:.2} |\n", rates[0]));
        md.push_str(&format!("| Median | {:.2} |\n", rates[rates.len() / 2]));
        md.push_str(&format!("| Mean | {:.2} |\n",
            rates.iter().sum::<f64>() / rates.len() as f64));
        md.push_str(&format!("| Max | {:.2} |\n", rates[rates.len() - 1]));
        md.push_str("\n");
    }

    // Heuristic summary
    md.push_str("## Heuristic Summary\n\n");
    md.push_str("| Heuristic | Transactions Flagged |\n|---|---|\n");

    let mut cioh_count = 0usize;
    let mut change_count = 0usize;
    let mut coinjoin_count = 0usize;
    let mut consolidation_count = 0usize;
    let mut round_count = 0usize;
    let mut reuse_count = 0usize;
    let mut self_count = 0usize;

    for ba in block_analyses {
        for ta in &ba.tx_analyses {
            if ta.heuristics.cioh.detected { cioh_count += 1; }
            if ta.heuristics.change_detection.detected { change_count += 1; }
            if ta.heuristics.coinjoin.detected { coinjoin_count += 1; }
            if ta.heuristics.consolidation.detected { consolidation_count += 1; }
            if ta.heuristics.round_number.detected { round_count += 1; }
            if ta.heuristics.address_reuse.detected { reuse_count += 1; }
            if ta.heuristics.self_transfer.detected { self_count += 1; }
        }
    }

    md.push_str(&format!("| Common Input Ownership (CIOH) | {} |\n", cioh_count));
    md.push_str(&format!("| Change Detection | {} |\n", change_count));
    md.push_str(&format!("| CoinJoin Detection | {} |\n", coinjoin_count));
    md.push_str(&format!("| Consolidation Detection | {} |\n", consolidation_count));
    md.push_str(&format!("| Round Number Payment | {} |\n", round_count));
    md.push_str(&format!("| Address Reuse | {} |\n", reuse_count));
    md.push_str(&format!("| Self-Transfer | {} |\n", self_count));
    md.push_str("\n");

    // Classification summary
    md.push_str("## Transaction Classification\n\n");
    md.push_str("| Classification | Count |\n|---|---|\n");
    let mut class_counts: HashMap<&str, usize> = HashMap::new();
    for ba in block_analyses {
        for ta in &ba.tx_analyses {
            *class_counts.entry(ta.classification.as_str()).or_insert(0) += 1;
        }
    }
    let mut class_vec: Vec<(&&str, &usize)> = class_counts.iter().collect();
    class_vec.sort_by(|a, b| b.1.cmp(a.1));
    for (k, v) in &class_vec {
        md.push_str(&format!("| {} | {} |\n", k, v));
    }
    md.push_str("\n");

    // Per-block sections
    md.push_str("## Per-Block Analysis\n\n");
    for ba in block_analyses {
        md.push_str(&format!("### Block {} (height {})\n\n", ba.block_hash, ba.block_height));
        md.push_str(&format!("- **Timestamp**: {}\n", ba.timestamp));
        md.push_str(&format!("- **Transactions**: {}\n", ba.tx_count));
        md.push_str(&format!("- **Flagged**: {}\n\n", ba.flagged_count));

        // Per-block heuristic breakdown
        let mut b_cioh = 0usize;
        let mut b_change = 0usize;
        let mut b_coinjoin = 0usize;
        let mut b_consolidation = 0usize;
        let mut b_round = 0usize;
        let mut b_reuse = 0usize;
        let mut b_self = 0usize;
        for ta in &ba.tx_analyses {
            if ta.heuristics.cioh.detected { b_cioh += 1; }
            if ta.heuristics.change_detection.detected { b_change += 1; }
            if ta.heuristics.coinjoin.detected { b_coinjoin += 1; }
            if ta.heuristics.consolidation.detected { b_consolidation += 1; }
            if ta.heuristics.round_number.detected { b_round += 1; }
            if ta.heuristics.address_reuse.detected { b_reuse += 1; }
            if ta.heuristics.self_transfer.detected { b_self += 1; }
        }
        md.push_str("| Heuristic | Fired |\n|---|---|\n");
        md.push_str(&format!("| CIOH | {} |\n", b_cioh));
        md.push_str(&format!("| Change Detection | {} |\n", b_change));
        md.push_str(&format!("| CoinJoin | {} |\n", b_coinjoin));
        md.push_str(&format!("| Consolidation | {} |\n", b_consolidation));
        md.push_str(&format!("| Round Number | {} |\n", b_round));
        md.push_str(&format!("| Address Reuse | {} |\n", b_reuse));
        md.push_str(&format!("| Self-Transfer | {} |\n\n", b_self));

        // Notable transactions
        let coinjoins: Vec<&TxAnalysis> = ba.tx_analyses.iter()
            .filter(|ta| ta.classification == TxClassification::Coinjoin)
            .collect();
        let consolidations: Vec<&TxAnalysis> = ba.tx_analyses.iter()
            .filter(|ta| ta.classification == TxClassification::Consolidation)
            .collect();

        if !coinjoins.is_empty() {
            md.push_str(&format!("**CoinJoin transactions ({}):**\n", coinjoins.len()));
            for cj in coinjoins.iter().take(5) {
                md.push_str(&format!("- `{}`\n", cj.txid));
            }
            if coinjoins.len() > 5 {
                md.push_str(&format!("- ... and {} more\n", coinjoins.len() - 5));
            }
            md.push_str("\n");
        }

        if !consolidations.is_empty() {
            md.push_str(&format!("**Consolidation transactions ({}):**\n", consolidations.len()));
            for c in consolidations.iter().take(5) {
                md.push_str(&format!("- `{}`\n", c.txid));
            }
            if consolidations.len() > 5 {
                md.push_str(&format!("- ... and {} more\n", consolidations.len() - 5));
            }
            md.push_str("\n");
        }

        md.push_str("---\n\n");
    }

    md
}
