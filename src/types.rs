use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Fixture {
    pub network: String,
    pub raw_tx: String,
    pub prevouts: Vec<Prevout>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Prevout {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
}

#[derive(Debug, Serialize)]
pub struct TransactionOutput {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segwit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    pub wtxid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locktime: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vbytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_input_sats: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_output_sats: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_sats: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_rate_sat_vb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rbf_signaling: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locktime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locktime_value: Option<u32>,
    pub segwit_savings: Option<SegwitSavings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vin: Option<Vec<TxInput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vout: Option<Vec<TxOutput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<Warning>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
}

#[derive(Debug, Serialize)]
pub struct ErrorInfo {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct SegwitSavings {
    pub witness_bytes: usize,
    pub non_witness_bytes: usize,
    pub total_bytes: usize,
    pub weight_actual: usize,
    pub weight_if_legacy: usize,
    pub savings_pct: f64,
}

#[derive(Debug, Serialize)]
pub struct TxInput {
    pub txid: String,
    pub vout: u32,
    pub sequence: u32,
    pub script_sig_hex: String,
    pub script_asm: String,
    pub witness: Vec<String>,
    pub script_type: String,
    pub address: Option<String>,
    pub prevout: PrevoutInfo,
    pub relative_timelock: RelativeTimelock,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_script_asm: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PrevoutInfo {
    pub value_sats: u64,
    pub script_pubkey_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum RelativeTimelock {
    Disabled {
        enabled: bool,
    },
    Enabled {
        enabled: bool,
        #[serde(rename = "type")]
        lock_type: String,
        value: u32,
    },
}

#[derive(Debug, Serialize)]
pub struct TxOutput {
    pub n: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub script_asm: String,
    pub script_type: String,
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_data_hex: Option<String>,
    // For OP_RETURN outputs: Some(Some("...")) = valid UTF-8, Some(None) = non-UTF-8 (serializes
    // as JSON null), None = not an OP_RETURN output (field omitted entirely).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_data_utf8: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_protocol: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Warning {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct BlockOutput {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_header: Option<BlockHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coinbase: Option<CoinbaseInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transactions: Option<Vec<TransactionOutput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_stats: Option<BlockStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
}

#[derive(Debug, Serialize)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub merkle_root_valid: bool,
    pub timestamp: u32,
    pub bits: String,
    pub nonce: u32,
    pub block_hash: String,
}

#[derive(Debug, Serialize)]
pub struct CoinbaseInfo {
    pub bip34_height: u64,
    pub coinbase_script_hex: String,
    pub total_output_sats: u64,
}

#[derive(Debug, Serialize)]
pub struct BlockStats {
    pub total_fees_sats: u64,
    pub total_weight: usize,
    pub avg_fee_rate_sat_vb: f64,
    pub script_type_summary: std::collections::HashMap<String, usize>,
}
