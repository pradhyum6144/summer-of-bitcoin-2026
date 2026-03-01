use serde::{Deserialize, Serialize};

use crate::builder::{locktime_to_u32, locktime_type_str, determine_locktime, determine_nsequence};
use crate::coin_selection::{CoinSelectionResult, SelectionScore};
use crate::descriptors::{export_descriptors, WatchOnlyDescriptor};
use crate::fixture::{BuildError, Fixture};
use crate::privacy::{analyze_privacy, PrivacyAnalysis};
use crate::signer::SigningResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub ok: bool,
    pub network: String,
    pub strategy: String,
    pub selected_inputs: Vec<ReportInput>,
    pub outputs: Vec<ReportOutput>,
    pub change_index: Option<usize>,
    pub fee_sats: u64,
    pub fee_rate_sat_vb: f64,
    pub vbytes: u64,
    pub rbf_signaling: bool,
    pub locktime: u32,
    pub locktime_type: String,
    pub psbt_base64: String,
    pub warnings: Vec<Warning>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy_scores: Option<Vec<SelectionScore>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy: Option<PrivacyAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptors: Option<Vec<WatchOnlyDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<SigningResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportInput {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub script_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportOutput {
    pub n: usize,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub script_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub is_change: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warning {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReport {
    pub ok: bool,
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

pub fn build_report(
    fixture: &Fixture,
    selection: &CoinSelectionResult,
    psbt_base64: &str,
) -> Report {
    build_report_full(fixture, selection, psbt_base64, None, None)
}

pub fn build_report_full(
    fixture: &Fixture,
    selection: &CoinSelectionResult,
    psbt_base64: &str,
    strategy_scores: Option<Vec<SelectionScore>>,
    signing: Option<SigningResult>,
) -> Report {
    let seq = determine_nsequence(fixture);
    let lt = determine_locktime(fixture);
    let lt_val = locktime_to_u32(&lt);

    let rbf_signaling = seq.0 <= 0xFFFFFFFD;

    let mut outputs = Vec::new();
    for (i, payment) in fixture.payments.iter().enumerate() {
        outputs.push(ReportOutput {
            n: i,
            value_sats: payment.value_sats,
            script_pubkey_hex: payment.script_pubkey_hex.clone(),
            script_type: payment.script_type.clone(),
            address: payment.address.clone(),
            is_change: false,
        });
    }

    let change_index = if let Some(change_amount) = selection.change_amount {
        let idx = outputs.len();
        outputs.push(ReportOutput {
            n: idx,
            value_sats: change_amount,
            script_pubkey_hex: fixture.change.script_pubkey_hex.clone(),
            script_type: fixture.change.script_type.clone(),
            address: fixture.change.address.clone(),
            is_change: true,
        });
        Some(idx)
    } else {
        None
    };

    let selected_inputs: Vec<ReportInput> = selection
        .selected
        .iter()
        .map(|u| ReportInput {
            txid: u.txid.clone(),
            vout: u.vout,
            value_sats: u.value_sats,
            script_pubkey_hex: u.script_pubkey_hex.clone(),
            script_type: u.script_type.clone(),
            address: u.address.clone(),
        })
        .collect();

    let fee_rate_actual = if selection.vbytes > 0 {
        selection.fee as f64 / selection.vbytes as f64
    } else {
        0.0
    };

    let mut warnings = Vec::new();

    if selection.fee > 1_000_000 || fee_rate_actual > 200.0 {
        warnings.push(Warning { code: "HIGH_FEE".to_string() });
    }
    if let Some(change_amount) = selection.change_amount {
        if change_amount < 546 {
            warnings.push(Warning { code: "DUST_CHANGE".to_string() });
        }
    }
    if selection.change_amount.is_none() {
        warnings.push(Warning { code: "SEND_ALL".to_string() });
    }
    if rbf_signaling {
        warnings.push(Warning { code: "RBF_SIGNALING".to_string() });
    }

    // Privacy analysis
    let privacy = analyze_privacy(
        &selection.selected,
        &fixture.payments,
        &fixture.change,
        selection.change_amount,
    );

    // Add privacy-related warnings
    if privacy.score < 40 {
        warnings.push(Warning { code: "LOW_PRIVACY".to_string() });
    }

    // Watch-only descriptors
    let descriptors = export_descriptors(&selection.selected);

    Report {
        ok: true,
        network: fixture.network.clone(),
        strategy: selection.strategy.clone(),
        selected_inputs,
        outputs,
        change_index,
        fee_sats: selection.fee,
        fee_rate_sat_vb: (fee_rate_actual * 100.0).round() / 100.0,
        vbytes: selection.vbytes,
        rbf_signaling,
        locktime: lt_val,
        locktime_type: locktime_type_str(lt_val).to_string(),
        psbt_base64: psbt_base64.to_string(),
        warnings,
        strategy_scores,
        privacy: Some(privacy),
        descriptors: Some(descriptors),
        signing,
    }
}

pub fn error_report(err: &BuildError) -> ErrorReport {
    ErrorReport {
        ok: false,
        error: ErrorDetail {
            code: err.code.clone(),
            message: err.message.clone(),
        },
    }
}
