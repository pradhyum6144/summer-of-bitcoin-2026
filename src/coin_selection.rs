use crate::fixture::{BuildError, Utxo};

pub const DUST_THRESHOLD: u64 = 546;

/// Estimate the input weight in virtual bytes for a given script type.
pub fn input_vbytes(script_type: &str) -> u64 {
    match script_type {
        "p2pkh" => 148,
        "p2sh-p2wpkh" => 91,
        "p2sh" => 256,
        "p2sh-p2wsh" => 140,
        "p2wpkh" => 68,
        "p2wsh" => 104,
        "p2tr" => 58,
        _ => 68,
    }
}

/// Estimate the output weight in virtual bytes for a given script type.
pub fn output_vbytes(script_type: &str) -> u64 {
    match script_type {
        "p2pkh" => 34,
        "p2sh" | "p2sh-p2wpkh" | "p2sh-p2wsh" => 32,
        "p2wpkh" => 31,
        "p2wsh" => 43,
        "p2tr" => 43,
        _ => 31,
    }
}

/// Fixed transaction overhead vbytes
pub fn tx_overhead_vbytes() -> u64 {
    11
}

/// Estimate total transaction vbytes
pub fn estimate_vbytes(
    inputs: &[&Utxo],
    payment_script_types: &[&str],
    change_script_type: Option<&str>,
) -> u64 {
    let mut vbytes = tx_overhead_vbytes();
    for input in inputs {
        vbytes += input_vbytes(&input.script_type);
    }
    for st in payment_script_types {
        vbytes += output_vbytes(st);
    }
    if let Some(cst) = change_script_type {
        vbytes += output_vbytes(cst);
    }
    vbytes
}

#[derive(Debug, Clone)]
pub struct CoinSelectionResult {
    pub selected: Vec<Utxo>,
    pub fee: u64,
    pub change_amount: Option<u64>,
    pub vbytes: u64,
    pub strategy: String,
}

/// Score a coin selection result. Lower is better.
/// Considers: fee waste, number of inputs, change presence.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SelectionScore {
    pub strategy: String,
    pub fee_sats: u64,
    pub input_count: usize,
    pub has_change: bool,
    pub waste: f64,
    pub total_score: f64,
}

pub fn score_selection(result: &CoinSelectionResult, target_fee_rate: f64) -> SelectionScore {
    let input_count = result.selected.len();
    let has_change = result.change_amount.is_some();

    // Waste = excess fee beyond minimum + cost of creating change output
    let min_fee = (target_fee_rate * result.vbytes as f64).ceil() as u64;
    let fee_waste = result.fee.saturating_sub(min_fee) as f64;

    // Input cost penalty: more inputs = more future spend cost
    let input_penalty = input_count as f64 * 10.0;

    // Change penalty: creating change costs future spend
    let change_penalty = if has_change { 30.0 } else { 0.0 };

    let total_score = fee_waste + input_penalty + change_penalty;

    SelectionScore {
        strategy: result.strategy.clone(),
        fee_sats: result.fee,
        input_count,
        has_change,
        waste: fee_waste,
        total_score,
    }
}

/// Finalize a selected set of UTXOs into a CoinSelectionResult with proper fee/change.
fn finalize_selection(
    selected: Vec<Utxo>,
    payment_total: u64,
    payment_script_types: &[&str],
    change_script_type: &str,
    fee_rate: f64,
    strategy: &str,
) -> Option<CoinSelectionResult> {
    let refs: Vec<&Utxo> = selected.iter().collect();
    let selected_total: u64 = selected.iter().map(|u| u.value_sats).sum();

    let vbytes_no_change = estimate_vbytes(&refs, payment_script_types, None);
    let fee_no_change = (fee_rate * vbytes_no_change as f64).ceil() as u64;

    if selected_total < payment_total + fee_no_change {
        return None;
    }

    let leftover = selected_total - payment_total - fee_no_change;

    if leftover == 0 {
        return Some(CoinSelectionResult {
            selected,
            fee: fee_no_change,
            change_amount: None,
            vbytes: vbytes_no_change,
            strategy: strategy.to_string(),
        });
    }

    // Try with change
    let vbytes_with_change =
        estimate_vbytes(&refs, payment_script_types, Some(change_script_type));
    let fee_with_change = (fee_rate * vbytes_with_change as f64).ceil() as u64;

    if selected_total >= payment_total + fee_with_change {
        let change_amount = selected_total - payment_total - fee_with_change;
        if change_amount >= DUST_THRESHOLD {
            return Some(CoinSelectionResult {
                selected,
                fee: fee_with_change,
                change_amount: Some(change_amount),
                vbytes: vbytes_with_change,
                strategy: strategy.to_string(),
            });
        }
    }

    // Send all (change is dust)
    Some(CoinSelectionResult {
        selected,
        fee: selected_total - payment_total,
        change_amount: None,
        vbytes: vbytes_no_change,
        strategy: strategy.to_string(),
    })
}

/// Strategy 1: Greedy largest-first
fn select_greedy(
    utxos: &[Utxo],
    payment_total: u64,
    payment_script_types: &[&str],
    change_script_type: &str,
    fee_rate: f64,
    max_inputs: usize,
) -> Result<CoinSelectionResult, BuildError> {
    let mut sorted: Vec<&Utxo> = utxos.iter().collect();
    sorted.sort_by(|a, b| b.value_sats.cmp(&a.value_sats));

    let mut selected: Vec<Utxo> = Vec::new();

    for utxo in sorted {
        if selected.len() >= max_inputs {
            break;
        }
        selected.push(utxo.clone());

        if let Some(result) = finalize_selection(
            selected.clone(),
            payment_total,
            payment_script_types,
            change_script_type,
            fee_rate,
            "greedy",
        ) {
            return Ok(result);
        }
    }

    // Try with all selected
    if let Some(result) = finalize_selection(
        selected,
        payment_total,
        payment_script_types,
        change_script_type,
        fee_rate,
        "greedy",
    ) {
        return Ok(result);
    }

    Err(BuildError {
        code: "INSUFFICIENT_FUNDS".to_string(),
        message: "Greedy: insufficient funds".to_string(),
    })
}

/// Strategy 2: Smallest-first (consolidation-friendly)
fn select_smallest_first(
    utxos: &[Utxo],
    payment_total: u64,
    payment_script_types: &[&str],
    change_script_type: &str,
    fee_rate: f64,
    max_inputs: usize,
) -> Result<CoinSelectionResult, BuildError> {
    let mut sorted: Vec<&Utxo> = utxos.iter().collect();
    sorted.sort_by(|a, b| a.value_sats.cmp(&b.value_sats));

    let mut selected: Vec<Utxo> = Vec::new();

    for utxo in sorted {
        if selected.len() >= max_inputs {
            break;
        }
        selected.push(utxo.clone());

        if let Some(result) = finalize_selection(
            selected.clone(),
            payment_total,
            payment_script_types,
            change_script_type,
            fee_rate,
            "smallest_first",
        ) {
            return Ok(result);
        }
    }

    if let Some(result) = finalize_selection(
        selected,
        payment_total,
        payment_script_types,
        change_script_type,
        fee_rate,
        "smallest_first",
    ) {
        return Ok(result);
    }

    Err(BuildError {
        code: "INSUFFICIENT_FUNDS".to_string(),
        message: "Smallest-first: insufficient funds".to_string(),
    })
}

/// Strategy 3: Knapsack — try to find a single UTXO that covers it, else combine
fn select_knapsack(
    utxos: &[Utxo],
    payment_total: u64,
    payment_script_types: &[&str],
    change_script_type: &str,
    fee_rate: f64,
    max_inputs: usize,
) -> Result<CoinSelectionResult, BuildError> {
    // First: try to find a single UTXO that is the best fit (smallest sufficient)
    let mut candidates: Vec<&Utxo> = utxos.iter().collect();
    candidates.sort_by(|a, b| a.value_sats.cmp(&b.value_sats));

    // Estimate minimum needed (1 input, no change)
    for utxo in &candidates {
        let single = vec![(*utxo).clone()];
        if let Some(result) = finalize_selection(
            single,
            payment_total,
            payment_script_types,
            change_script_type,
            fee_rate,
            "knapsack",
        ) {
            return Ok(result);
        }
    }

    // No single UTXO works; fall back to greedy
    let mut sorted: Vec<&Utxo> = utxos.iter().collect();
    sorted.sort_by(|a, b| b.value_sats.cmp(&a.value_sats));

    let mut selected: Vec<Utxo> = Vec::new();
    for utxo in sorted {
        if selected.len() >= max_inputs {
            break;
        }
        selected.push(utxo.clone());

        if let Some(result) = finalize_selection(
            selected.clone(),
            payment_total,
            payment_script_types,
            change_script_type,
            fee_rate,
            "knapsack",
        ) {
            return Ok(result);
        }
    }

    if let Some(result) = finalize_selection(
        selected,
        payment_total,
        payment_script_types,
        change_script_type,
        fee_rate,
        "knapsack",
    ) {
        return Ok(result);
    }

    Err(BuildError {
        code: "INSUFFICIENT_FUNDS".to_string(),
        message: "Knapsack: insufficient funds".to_string(),
    })
}

/// Run all strategies, score them, and return the best result + comparison.
pub fn select_coins_multi(
    utxos: &[Utxo],
    payment_total: u64,
    payment_script_types: &[&str],
    change_script_type: &str,
    fee_rate: f64,
    max_inputs: Option<usize>,
) -> Result<(CoinSelectionResult, Vec<SelectionScore>), BuildError> {
    let limit = max_inputs.unwrap_or(utxos.len());

    let strategies: Vec<(&str, Result<CoinSelectionResult, BuildError>)> = vec![
        (
            "greedy",
            select_greedy(utxos, payment_total, payment_script_types, change_script_type, fee_rate, limit),
        ),
        (
            "smallest_first",
            select_smallest_first(utxos, payment_total, payment_script_types, change_script_type, fee_rate, limit),
        ),
        (
            "knapsack",
            select_knapsack(utxos, payment_total, payment_script_types, change_script_type, fee_rate, limit),
        ),
    ];

    let mut results: Vec<CoinSelectionResult> = Vec::new();
    for (_name, result) in strategies {
        if let Ok(r) = result {
            results.push(r);
        }
    }

    if results.is_empty() {
        return Err(BuildError {
            code: "INSUFFICIENT_FUNDS".to_string(),
            message: format!(
                "No strategy could fund payment: needed={}+fee",
                payment_total
            ),
        });
    }

    let mut scores: Vec<SelectionScore> = results
        .iter()
        .map(|r| score_selection(r, fee_rate))
        .collect();

    // Sort by total_score (lower is better)
    scores.sort_by(|a, b| a.total_score.partial_cmp(&b.total_score).unwrap());

    // Pick the best
    let best_strategy = &scores[0].strategy;
    let best_idx = results
        .iter()
        .position(|r| r.strategy == *best_strategy)
        .unwrap();
    let best = results.remove(best_idx);

    // Rebuild scores for all (since we moved best)
    let all_scores = scores;

    Ok((best, all_scores))
}

/// Original API — kept for backward compatibility. Uses best strategy.
pub fn select_coins(
    utxos: &[Utxo],
    payment_total: u64,
    payment_script_types: &[&str],
    change_script_type: &str,
    fee_rate: f64,
    max_inputs: Option<usize>,
) -> Result<CoinSelectionResult, BuildError> {
    let (best, _scores) =
        select_coins_multi(utxos, payment_total, payment_script_types, change_script_type, fee_rate, max_inputs)?;
    Ok(best)
}
