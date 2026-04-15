use crate::fixture::{Utxo, Payment, ChangeTemplate};
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAnalysis {
    pub score: u32,         // 0-100, higher is better
    pub rating: String,     // "good", "moderate", "poor"
    pub issues: Vec<PrivacyIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyIssue {
    pub code: String,
    pub severity: String,   // "low", "medium", "high"
    pub description: String,
}

/// Analyze the privacy characteristics of a transaction.
pub fn analyze_privacy(
    selected_inputs: &[Utxo],
    payments: &[Payment],
    change: &ChangeTemplate,
    change_amount: Option<u64>,
) -> PrivacyAnalysis {
    let mut issues = Vec::new();
    let mut score: i32 = 100;

    // 1. Input reuse: check if multiple inputs share the same script_pubkey
    let mut seen_scripts: HashSet<String> = HashSet::new();
    let mut reused_count = 0;
    for input in selected_inputs {
        if !seen_scripts.insert(input.script_pubkey_hex.clone()) {
            reused_count += 1;
        }
    }
    if reused_count > 0 {
        issues.push(PrivacyIssue {
            code: "INPUT_REUSE".to_string(),
            severity: "high".to_string(),
            description: format!(
                "{} input(s) share the same script, revealing address reuse",
                reused_count
            ),
        });
        score -= 25;
    }

    // 2. Output linkage: change output has same script type as an input
    if let Some(_change_amt) = change_amount {
        let input_types: HashSet<&str> = selected_inputs.iter().map(|i| i.script_type.as_str()).collect();
        if input_types.contains(change.script_type.as_str()) {
            issues.push(PrivacyIssue {
                code: "CHANGE_TYPE_MATCH".to_string(),
                severity: "low".to_string(),
                description: "Change output script type matches an input, aiding change detection".to_string(),
            });
            score -= 5;
        }
    }

    // 3. Round payment amounts are suspicious (exact multiples of 10000)
    for (i, p) in payments.iter().enumerate() {
        if p.value_sats >= 10000 && p.value_sats % 10000 == 0 {
            issues.push(PrivacyIssue {
                code: "ROUND_PAYMENT".to_string(),
                severity: "low".to_string(),
                description: format!(
                    "Payment {} is a round number ({} sats), making change identification easier",
                    i, p.value_sats
                ),
            });
            score -= 3;
        }
    }

    // 4. Change amount close to a payment amount (within 10%) enables subset-sum analysis
    if let Some(change_amt) = change_amount {
        for (i, p) in payments.iter().enumerate() {
            let diff = (change_amt as i64 - p.value_sats as i64).unsigned_abs();
            let threshold = (p.value_sats as f64 * 0.1) as u64;
            if diff <= threshold && threshold > 0 {
                issues.push(PrivacyIssue {
                    code: "CHANGE_AMOUNT_LINKAGE".to_string(),
                    severity: "medium".to_string(),
                    description: format!(
                        "Change ({} sats) is close to payment {} ({} sats), aiding analysis",
                        change_amt, i, p.value_sats
                    ),
                });
                score -= 10;
                break;
            }
        }
    }

    // 5. Single input → single output (no-change) is fully transparent
    if selected_inputs.len() == 1 && payments.len() == 1 && change_amount.is_none() {
        issues.push(PrivacyIssue {
            code: "TRIVIAL_TX".to_string(),
            severity: "medium".to_string(),
            description: "Single input, single output: transaction is trivially linkable".to_string(),
        });
        score -= 15;
    }

    // 6. Mixed input types reveal wallet software fingerprint
    let input_types: HashSet<&str> = selected_inputs.iter().map(|i| i.script_type.as_str()).collect();
    if input_types.len() > 1 {
        issues.push(PrivacyIssue {
            code: "MIXED_INPUT_TYPES".to_string(),
            severity: "medium".to_string(),
            description: format!(
                "Inputs use {} different script types, creating a wallet fingerprint",
                input_types.len()
            ),
        });
        score -= 10;
    }

    // 7. Many inputs consolidation
    if selected_inputs.len() > 5 {
        issues.push(PrivacyIssue {
            code: "CONSOLIDATION".to_string(),
            severity: "low".to_string(),
            description: format!(
                "{} inputs being consolidated reveals UTXO ownership linkage",
                selected_inputs.len()
            ),
        });
        score -= 5;
    }

    let score = score.max(0).min(100) as u32;
    let rating = if score >= 70 {
        "good"
    } else if score >= 40 {
        "moderate"
    } else {
        "poor"
    }
    .to_string();

    PrivacyAnalysis {
        score,
        rating,
        issues,
    }
}
