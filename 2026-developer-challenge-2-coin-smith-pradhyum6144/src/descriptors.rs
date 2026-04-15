use crate::fixture::Utxo;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchOnlyDescriptor {
    pub script_type: String,
    pub descriptor: String,
    pub address: Option<String>,
}

/// Generate watch-only descriptors for a set of UTXOs.
/// These descriptors allow a watch-only wallet to track the UTXOs without spending ability.
pub fn export_descriptors(utxos: &[Utxo]) -> Vec<WatchOnlyDescriptor> {
    utxos
        .iter()
        .map(|utxo| {
            let descriptor = match utxo.script_type.as_str() {
                "p2wpkh" => format!("raw({})", utxo.script_pubkey_hex),
                "p2tr" => format!("raw({})", utxo.script_pubkey_hex),
                "p2pkh" => format!("raw({})", utxo.script_pubkey_hex),
                "p2sh-p2wpkh" => format!("raw({})", utxo.script_pubkey_hex),
                "p2sh" => format!("raw({})", utxo.script_pubkey_hex),
                "p2wsh" => format!("raw({})", utxo.script_pubkey_hex),
                _ => format!("raw({})", utxo.script_pubkey_hex),
            };

            WatchOnlyDescriptor {
                script_type: utxo.script_type.clone(),
                descriptor,
                address: utxo.address.clone(),
            }
        })
        .collect()
}
