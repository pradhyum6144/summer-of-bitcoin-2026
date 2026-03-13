use crate::parser::*;
use std::collections::HashMap;

// ─── Heuristic Results ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CiohResult {
    pub detected: bool,
}

#[derive(Debug, Clone)]
pub struct ChangeDetectionResult {
    pub detected: bool,
    pub likely_change_index: Option<usize>,
    pub method: String,
    pub confidence: String,
}

#[derive(Debug, Clone)]
pub struct CoinjoinResult {
    pub detected: bool,
    pub equal_output_count: usize,
    pub equal_output_value: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ConsolidationResult {
    pub detected: bool,
}

#[derive(Debug, Clone)]
pub struct RoundNumberResult {
    pub detected: bool,
    pub round_output_indices: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct AddressReuseResult {
    pub detected: bool,
}

#[derive(Debug, Clone)]
pub struct SelfTransferResult {
    pub detected: bool,
}

#[derive(Debug, Clone)]
pub struct HeuristicResults {
    pub cioh: CiohResult,
    pub change_detection: ChangeDetectionResult,
    pub coinjoin: CoinjoinResult,
    pub consolidation: ConsolidationResult,
    pub round_number: RoundNumberResult,
    pub address_reuse: AddressReuseResult,
    pub self_transfer: SelfTransferResult,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TxClassification {
    SimplePayment,
    Consolidation,
    Coinjoin,
    SelfTransfer,
    BatchPayment,
    Unknown,
}

impl TxClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            TxClassification::SimplePayment => "simple_payment",
            TxClassification::Consolidation => "consolidation",
            TxClassification::Coinjoin => "coinjoin",
            TxClassification::SelfTransfer => "self_transfer",
            TxClassification::BatchPayment => "batch_payment",
            TxClassification::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TxAnalysis {
    pub txid: String,
    pub heuristics: HeuristicResults,
    pub classification: TxClassification,
    pub fee: Option<u64>,
    pub vsize: f64,
    pub fee_rate: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct BlockAnalysis {
    pub block_hash: String,
    pub block_height: u32,
    pub timestamp: u32,
    pub tx_count: usize,
    pub tx_analyses: Vec<TxAnalysis>,
    pub script_type_dist: HashMap<String, usize>,
    pub flagged_count: usize,
}

// ─── Heuristic Functions ────────────────────────────────────────────────────

/// CIOH: Common Input Ownership — flag transactions with multiple inputs
fn analyze_cioh(tx: &Transaction) -> CiohResult {
    CiohResult {
        detected: tx.inputs.len() > 1,
    }
}

/// Change Detection — identify the likely change output
fn analyze_change_detection(
    tx: &Transaction,
    prevout_scripts: &[ScriptType],
    _prevout_values: &[u64],
) -> ChangeDetectionResult {
    let outputs = &tx.outputs;
    if outputs.len() < 2 {
        return ChangeDetectionResult {
            detected: false,
            likely_change_index: None,
            method: "none".to_string(),
            confidence: "none".to_string(),
        };
    }

    // Method 1: Script type matching — change output matches input script type
    if !prevout_scripts.is_empty() {
        let input_types: Vec<ScriptType> = prevout_scripts.to_vec();
        let dominant_input_type = most_common(&input_types);
        let all_same_type = input_types.iter().all(|t| *t == dominant_input_type);

        let mut matching_indices: Vec<usize> = Vec::new();
        for (i, out) in outputs.iter().enumerate() {
            let out_type = classify_script(&out.script_pubkey);
            if out_type == dominant_input_type {
                matching_indices.push(i);
            }
        }

        // If exactly one output matches input script type, it's likely change
        if matching_indices.len() == 1 {
            let confidence = if all_same_type { "high" } else { "medium" };
            return ChangeDetectionResult {
                detected: true,
                likely_change_index: Some(matching_indices[0]),
                method: "script_type_match".to_string(),
                confidence: confidence.to_string(),
            };
        }
    }

    // Method 2: Round number analysis — non-round output is likely change
    let mut round_indices = Vec::new();
    let mut non_round_indices = Vec::new();
    for (i, out) in outputs.iter().enumerate() {
        if is_round_number(out.value) {
            round_indices.push(i);
        } else {
            non_round_indices.push(i);
        }
    }

    if round_indices.len() >= 1 && non_round_indices.len() == 1 {
        return ChangeDetectionResult {
            detected: true,
            likely_change_index: Some(non_round_indices[0]),
            method: "round_number".to_string(),
            confidence: "medium".to_string(),
        };
    }

    // Method 3: Value analysis — only fire when one output is clearly much smaller
    if outputs.len() == 2 {
        let (smaller, larger) = if outputs[0].value < outputs[1].value {
            (0, 1)
        } else {
            (1, 0)
        };
        let small_val = outputs[smaller].value;
        let large_val = outputs[larger].value;
        // Only flag if the smaller output is <20% of the larger AND neither is round
        if large_val > 0
            && (small_val as f64) < (large_val as f64) * 0.2
            && !is_round_number(small_val)
            && !is_round_number(large_val)
        {
            return ChangeDetectionResult {
                detected: true,
                likely_change_index: Some(smaller),
                method: "value_analysis".to_string(),
                confidence: "low".to_string(),
            };
        }
    }

    ChangeDetectionResult {
        detected: false,
        likely_change_index: None,
        method: "none".to_string(),
        confidence: "none".to_string(),
    }
}

/// CoinJoin Detection — multiple inputs, equal-value outputs
fn analyze_coinjoin(tx: &Transaction) -> CoinjoinResult {
    if tx.inputs.len() < 3 || tx.outputs.len() < 3 {
        return CoinjoinResult {
            detected: false,
            equal_output_count: 0,
            equal_output_value: None,
        };
    }

    // Count output value frequencies
    let mut value_counts: HashMap<u64, usize> = HashMap::new();
    for out in &tx.outputs {
        if out.value > 0 {
            *value_counts.entry(out.value).or_insert(0) += 1;
        }
    }

    // Find the most common output value with count >= 3
    let mut best_value = 0u64;
    let mut best_count = 0usize;
    for (&val, &count) in &value_counts {
        if count > best_count {
            best_count = count;
            best_value = val;
        }
    }

    // CoinJoin: at least 3 equal-value outputs AND many inputs
    let detected = best_count >= 3 && tx.inputs.len() >= best_count;

    CoinjoinResult {
        detected,
        equal_output_count: best_count,
        equal_output_value: if detected { Some(best_value) } else { None },
    }
}

/// Consolidation Detection — many inputs, 1-2 outputs
fn analyze_consolidation(tx: &Transaction, prevout_scripts: &[ScriptType]) -> ConsolidationResult {
    let many_inputs = tx.inputs.len() >= 3;
    let few_outputs = tx.outputs.len() <= 2;

    // Check if all inputs/outputs are same script type
    let output_types: Vec<ScriptType> = tx.outputs.iter()
        .map(|o| classify_script(&o.script_pubkey))
        .collect();

    let same_script_types = if !prevout_scripts.is_empty() && !output_types.is_empty() {
        let all_types: Vec<ScriptType> = prevout_scripts.iter()
            .chain(output_types.iter())
            .copied()
            .collect();
        all_types.iter().all(|t| *t == all_types[0])
    } else {
        false
    };

    // When undo data is unavailable (prevout_scripts empty), fall back to
    // input/output count ratio: many inputs to few outputs is likely consolidation
    let fallback = prevout_scripts.is_empty() && many_inputs && few_outputs;

    ConsolidationResult {
        detected: many_inputs && few_outputs && (same_script_types || tx.outputs.len() == 1 || fallback),
    }
}

/// Round Number Payment Detection
fn analyze_round_number(tx: &Transaction) -> RoundNumberResult {
    let mut round_indices = Vec::new();
    for (i, out) in tx.outputs.iter().enumerate() {
        if is_round_number(out.value) && out.value > 0 {
            round_indices.push(i);
        }
    }
    RoundNumberResult {
        detected: !round_indices.is_empty(),
        round_output_indices: round_indices,
    }
}

/// Address Reuse Detection — same script appears in inputs and outputs.
/// Only flags wallet script types (P2PKH, P2WPKH, P2TR) where reuse is a
/// privacy mistake. Skips P2SH/P2WSH (exchange/contract infrastructure where
/// reuse is intentional), OP_RETURN, empty scripts, and other non-wallet types.
fn analyze_address_reuse(tx: &Transaction, prevout_scripts_raw: &[Vec<u8>]) -> AddressReuseResult {
    fn is_wallet_script(script: &[u8]) -> bool {
        if script.is_empty() {
            return false;
        }
        matches!(
            classify_script(script),
            ScriptType::P2PKH | ScriptType::P2WPKH | ScriptType::P2TR
        )
    }

    let output_scripts: Vec<&[u8]> = tx.outputs.iter()
        .map(|o| o.script_pubkey.as_slice())
        .filter(|s| is_wallet_script(s))
        .collect();

    for prev_script in prevout_scripts_raw {
        if !is_wallet_script(prev_script) {
            continue;
        }
        if output_scripts.contains(&prev_script.as_slice()) {
            return AddressReuseResult { detected: true };
        }
    }
    AddressReuseResult { detected: false }
}

/// Self-Transfer Detection — all outputs match input script type pattern
/// Requires address reuse or single output to avoid false positives on
/// normal payments where sender and recipient happen to use the same script type.
fn analyze_self_transfer(
    tx: &Transaction,
    prevout_scripts: &[ScriptType],
    address_reuse: &AddressReuseResult,
) -> SelfTransferResult {
    if prevout_scripts.is_empty() || tx.outputs.is_empty() {
        return SelfTransferResult { detected: false };
    }

    let input_type = most_common(prevout_scripts);
    let all_outputs_match = tx.outputs.iter().all(|o| {
        let ot = classify_script(&o.script_pubkey);
        ot == input_type
    });

    // Self transfer: all outputs same type as inputs, and 1-2 outputs,
    // AND either address reuse detected or single output (no external recipient)
    SelfTransferResult {
        detected: all_outputs_match
            && tx.outputs.len() <= 2
            && (address_reuse.detected || tx.outputs.len() == 1),
    }
}

// ─── Classification ─────────────────────────────────────────────────────────

fn classify_transaction(
    tx: &Transaction,
    heuristics: &HeuristicResults,
) -> TxClassification {
    if is_coinbase(tx) {
        return TxClassification::Unknown;
    }

    if heuristics.coinjoin.detected {
        return TxClassification::Coinjoin;
    }
    if heuristics.consolidation.detected {
        return TxClassification::Consolidation;
    }
    if heuristics.self_transfer.detected && !heuristics.change_detection.detected {
        return TxClassification::SelfTransfer;
    }
    // Batch payment: many outputs (>= 3) suggesting multiple recipients
    if tx.outputs.len() >= 3 && tx.inputs.len() >= 1 {
        return TxClassification::BatchPayment;
    }
    if tx.outputs.len() <= 2 {
        return TxClassification::SimplePayment;
    }
    TxClassification::Unknown
}

// ─── Main Analysis ──────────────────────────────────────────────────────────

pub fn analyze_block(
    block: &Block,
    undo: Option<&BlockUndo>,
) -> BlockAnalysis {
    let block_hash = hash_to_hex_reversed(&block.header.block_hash);
    let block_height = if !block.transactions.is_empty() && is_coinbase(&block.transactions[0]) {
        extract_bip34_height(&block.transactions[0].inputs[0].script_sig).unwrap_or(0)
    } else {
        0
    };

    let mut tx_analyses = Vec::with_capacity(block.transactions.len());
    let mut script_type_dist: HashMap<String, usize> = HashMap::new();
    let mut flagged_count = 0;
    let mut undo_idx = 0; // index into undo tx_undos (skips coinbase)

    for tx in &block.transactions {
        let txid = hash_to_hex_reversed(&tx.txid);
        let is_cb = is_coinbase(tx);

        // Collect output script types
        for out in &tx.outputs {
            let st = classify_script(&out.script_pubkey);
            let key = st.as_str().to_string();
            *script_type_dist.entry(key).or_insert(0) += 1;
        }

        if is_cb {
            // Coinbase — minimal analysis
            tx_analyses.push(TxAnalysis {
                txid,
                heuristics: HeuristicResults {
                    cioh: CiohResult { detected: false },
                    change_detection: ChangeDetectionResult {
                        detected: false,
                        likely_change_index: None,
                        method: "none".to_string(),
                        confidence: "none".to_string(),
                    },
                    coinjoin: CoinjoinResult { detected: false, equal_output_count: 0, equal_output_value: None },
                    consolidation: ConsolidationResult { detected: false },
                    round_number: analyze_round_number(tx),
                    address_reuse: AddressReuseResult { detected: false },
                    self_transfer: SelfTransferResult { detected: false },
                },
                classification: TxClassification::Unknown,
                fee: None,
                vsize: ((tx.weight + 3) / 4) as f64,
                fee_rate: None,
            });
            continue;
        }

        // Get prevout data from undo if available
        let (prevout_scripts, prevout_values, prevout_scripts_raw) = if let Some(u) = undo {
            if undo_idx < u.tx_undos.len() {
                let tx_undo = &u.tx_undos[undo_idx];
                let scripts: Vec<ScriptType> = tx_undo.prevouts.iter()
                    .map(|p| classify_script(&p.script_pubkey))
                    .collect();
                let values: Vec<u64> = tx_undo.prevouts.iter()
                    .map(|p| p.value)
                    .collect();
                let raw_scripts: Vec<Vec<u8>> = tx_undo.prevouts.iter()
                    .map(|p| p.script_pubkey.clone())
                    .collect();
                (scripts, values, raw_scripts)
            } else {
                (vec![], vec![], vec![])
            }
        } else {
            (vec![], vec![], vec![])
        };
        undo_idx += 1;

        // Calculate fee
        let input_total: u64 = prevout_values.iter().sum();
        let output_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
        let fee = if !prevout_values.is_empty() && input_total >= output_total {
            Some(input_total - output_total)
        } else {
            None
        };

        let vsize = if tx.weight > 0 { ((tx.weight + 3) / 4) as f64 } else { 1.0 };
        let fee_rate = fee.map(|f| f as f64 / vsize);

        // Run heuristics
        let mut cioh = analyze_cioh(tx);
        let change_detection = analyze_change_detection(tx, &prevout_scripts, &prevout_values);
        let coinjoin = analyze_coinjoin(tx);
        let consolidation = analyze_consolidation(tx, &prevout_scripts);
        let round_number = analyze_round_number(tx);
        let address_reuse = analyze_address_reuse(tx, &prevout_scripts_raw);
        let self_transfer = analyze_self_transfer(tx, &prevout_scripts, &address_reuse);

        // CIOH assumption is violated by CoinJoins — multiple parties contribute inputs
        if coinjoin.detected {
            cioh.detected = false;
        }

        let heuristics = HeuristicResults {
            cioh,
            change_detection,
            coinjoin,
            consolidation,
            round_number,
            address_reuse,
            self_transfer,
        };

        let classification = classify_transaction(tx, &heuristics);

        // CIOH alone (2+ inputs) is normal; only flag when combined with
        // address reuse or absence of change output (suggests single entity)
        let cioh_suspicious = heuristics.cioh.detected
            && (heuristics.address_reuse.detected
                || !heuristics.change_detection.detected);

        // Self-transfer alone is just wallet maintenance; only flag when
        // address reuse confirms it's genuinely the same wallet
        let self_transfer_suspicious = heuristics.self_transfer.detected
            && heuristics.address_reuse.detected;

        let is_flagged = cioh_suspicious
            || heuristics.coinjoin.detected
            || heuristics.consolidation.detected
            || self_transfer_suspicious;

        if is_flagged {
            flagged_count += 1;
        }

        tx_analyses.push(TxAnalysis {
            txid,
            heuristics,
            classification,
            fee,
            vsize,
            fee_rate,
        });
    }

    BlockAnalysis {
        block_hash,
        block_height,
        timestamp: block.header.timestamp,
        tx_count: block.transactions.len(),
        tx_analyses,
        script_type_dist,
        flagged_count,
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn most_common(types: &[ScriptType]) -> ScriptType {
    let mut counts: HashMap<ScriptType, usize> = HashMap::new();
    for t in types {
        *counts.entry(*t).or_insert(0) += 1;
    }
    counts.into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(t, _)| t)
        .unwrap_or(ScriptType::Unknown)
}

fn is_round_number(sats: u64) -> bool {
    if sats == 0 {
        return false;
    }
    // Check divisibility by round BTC amounts from 1 BTC down to 0.00001 BTC
    let thresholds: &[u64] = &[
        100_000_000, // 1 BTC
        10_000_000,  // 0.1 BTC
        1_000_000,   // 0.01 BTC
        100_000,     // 0.001 BTC
        10_000,      // 0.0001 BTC
        1_000,       // 0.00001 BTC
    ];
    thresholds.iter().any(|&t| sats % t == 0)
}
