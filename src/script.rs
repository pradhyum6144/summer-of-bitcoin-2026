use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

// Opcode definitions (partial list - add more as needed)
pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_1: u8 = 0x51;
pub const OP_16: u8 = 0x60;
pub const OP_DUP: u8 = 0x76;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_RETURN: u8 = 0x6a;

pub fn disassemble_script(script: &[u8]) -> Result<String> {
    if script.is_empty() {
        return Ok(String::new());
    }

    let mut result = Vec::new();
    let mut i = 0;

    while i < script.len() {
        let opcode = script[i];
        i += 1;

        if opcode == 0 {
            result.push("OP_0".to_string());
        } else if opcode >= 1 && opcode <= 75 {
            // Direct push
            if i + opcode as usize > script.len() {
                return Err(anyhow!("Script truncated"));
            }
            let data = &script[i..i + opcode as usize];
            result.push(format!("OP_PUSHBYTES_{} {}", opcode, hex::encode(data)));
            i += opcode as usize;
        } else if opcode == OP_PUSHDATA1 {
            if i >= script.len() {
                return Err(anyhow!("Script truncated"));
            }
            let len = script[i] as usize;
            i += 1;
            if i + len > script.len() {
                return Err(anyhow!("Script truncated"));
            }
            let data = &script[i..i + len];
            result.push(format!("OP_PUSHDATA1 {}", hex::encode(data)));
            i += len;
        } else if opcode == OP_PUSHDATA2 {
            if i + 1 >= script.len() {
                return Err(anyhow!("Script truncated"));
            }
            let len = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            i += 2;
            if i + len > script.len() {
                return Err(anyhow!("Script truncated"));
            }
            let data = &script[i..i + len];
            result.push(format!("OP_PUSHDATA2 {}", hex::encode(data)));
            i += len;
        } else if opcode == OP_PUSHDATA4 {
            if i + 3 >= script.len() {
                return Err(anyhow!("Script truncated"));
            }
            let len = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]]) as usize;
            i += 4;
            if i + len > script.len() {
                return Err(anyhow!("Script truncated"));
            }
            let data = &script[i..i + len];
            result.push(format!("OP_PUSHDATA4 {}", hex::encode(data)));
            i += len;
        } else if opcode == OP_1NEGATE {
            result.push("OP_1NEGATE".to_string());
        } else if opcode >= OP_1 && opcode <= OP_16 {
            result.push(format!("OP_{}", opcode - 0x50));
        } else {
            result.push(opcode_name(opcode));
        }
    }

    Ok(result.join(" "))
}

fn opcode_name(opcode: u8) -> String {
    match opcode {
        0x00 => "OP_0".to_string(),
        0x4c => "OP_PUSHDATA1".to_string(),
        0x4d => "OP_PUSHDATA2".to_string(),
        0x4e => "OP_PUSHDATA4".to_string(),
        0x4f => "OP_1NEGATE".to_string(),
        0x50 => "OP_RESERVED".to_string(),
        0x61 => "OP_NOP".to_string(),
        0x62 => "OP_VER".to_string(),
        0x63 => "OP_IF".to_string(),
        0x64 => "OP_NOTIF".to_string(),
        0x65 => "OP_VERIF".to_string(),
        0x66 => "OP_VERNOTIF".to_string(),
        0x67 => "OP_ELSE".to_string(),
        0x68 => "OP_ENDIF".to_string(),
        0x69 => "OP_VERIFY".to_string(),
        0x6a => "OP_RETURN".to_string(),
        0x6b => "OP_TOALTSTACK".to_string(),
        0x6c => "OP_FROMALTSTACK".to_string(),
        0x6d => "OP_2DROP".to_string(),
        0x6e => "OP_2DUP".to_string(),
        0x6f => "OP_3DUP".to_string(),
        0x70 => "OP_2OVER".to_string(),
        0x71 => "OP_2ROT".to_string(),
        0x72 => "OP_2SWAP".to_string(),
        0x73 => "OP_IFDUP".to_string(),
        0x74 => "OP_DEPTH".to_string(),
        0x75 => "OP_DROP".to_string(),
        0x76 => "OP_DUP".to_string(),
        0x77 => "OP_NIP".to_string(),
        0x78 => "OP_OVER".to_string(),
        0x79 => "OP_PICK".to_string(),
        0x7a => "OP_ROLL".to_string(),
        0x7b => "OP_ROT".to_string(),
        0x7c => "OP_SWAP".to_string(),
        0x7d => "OP_TUCK".to_string(),
        0x7e => "OP_CAT".to_string(),
        0x7f => "OP_SUBSTR".to_string(),
        0x80 => "OP_LEFT".to_string(),
        0x81 => "OP_RIGHT".to_string(),
        0x82 => "OP_SIZE".to_string(),
        0x83 => "OP_INVERT".to_string(),
        0x84 => "OP_AND".to_string(),
        0x85 => "OP_OR".to_string(),
        0x86 => "OP_XOR".to_string(),
        0x87 => "OP_EQUAL".to_string(),
        0x88 => "OP_EQUALVERIFY".to_string(),
        0x89 => "OP_RESERVED1".to_string(),
        0x8a => "OP_RESERVED2".to_string(),
        0x8b => "OP_1ADD".to_string(),
        0x8c => "OP_1SUB".to_string(),
        0x8d => "OP_2MUL".to_string(),
        0x8e => "OP_2DIV".to_string(),
        0x8f => "OP_NEGATE".to_string(),
        0x90 => "OP_ABS".to_string(),
        0x91 => "OP_NOT".to_string(),
        0x92 => "OP_0NOTEQUAL".to_string(),
        0x93 => "OP_ADD".to_string(),
        0x94 => "OP_SUB".to_string(),
        0x95 => "OP_MUL".to_string(),
        0x96 => "OP_DIV".to_string(),
        0x97 => "OP_MOD".to_string(),
        0x98 => "OP_LSHIFT".to_string(),
        0x99 => "OP_RSHIFT".to_string(),
        0x9a => "OP_BOOLAND".to_string(),
        0x9b => "OP_BOOLOR".to_string(),
        0x9c => "OP_NUMEQUAL".to_string(),
        0x9d => "OP_NUMEQUALVERIFY".to_string(),
        0x9e => "OP_NUMNOTEQUAL".to_string(),
        0x9f => "OP_LESSTHAN".to_string(),
        0xa0 => "OP_GREATERTHAN".to_string(),
        0xa1 => "OP_LESSTHANOREQUAL".to_string(),
        0xa2 => "OP_GREATERTHANOREQUAL".to_string(),
        0xa3 => "OP_MIN".to_string(),
        0xa4 => "OP_MAX".to_string(),
        0xa5 => "OP_WITHIN".to_string(),
        0xa6 => "OP_RIPEMD160".to_string(),
        0xa7 => "OP_SHA1".to_string(),
        0xa8 => "OP_SHA256".to_string(),
        0xa9 => "OP_HASH160".to_string(),
        0xaa => "OP_HASH256".to_string(),
        0xab => "OP_CODESEPARATOR".to_string(),
        0xac => "OP_CHECKSIG".to_string(),
        0xad => "OP_CHECKSIGVERIFY".to_string(),
        0xae => "OP_CHECKMULTISIG".to_string(),
        0xaf => "OP_CHECKMULTISIGVERIFY".to_string(),
        0xb0 => "OP_NOP1".to_string(),
        0xb1 => "OP_CHECKLOCKTIMEVERIFY".to_string(),
        0xb2 => "OP_CHECKSEQUENCEVERIFY".to_string(),
        0xb3 => "OP_NOP4".to_string(),
        0xb4 => "OP_NOP5".to_string(),
        0xb5 => "OP_NOP6".to_string(),
        0xb6 => "OP_NOP7".to_string(),
        0xb7 => "OP_NOP8".to_string(),
        0xb8 => "OP_NOP9".to_string(),
        0xb9 => "OP_NOP10".to_string(),
        0xba => "OP_CHECKSIGADD".to_string(),
        0xff => "OP_INVALIDOPCODE".to_string(),
        _ => format!("OP_UNKNOWN_<0x{:02x}>", opcode),
    }
}

#[derive(Debug, PartialEq)]
pub enum ScriptType {
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR,
    OpReturn,
    Unknown,
}

pub fn classify_script(script: &[u8]) -> ScriptType {
    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if script.len() == 25
        && script[0] == OP_DUP
        && script[1] == OP_HASH160
        && script[2] == 0x14
        && script[23] == OP_EQUALVERIFY
        && script[24] == OP_CHECKSIG
    {
        return ScriptType::P2PKH;
    }

    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if script.len() == 23 && script[0] == OP_HASH160 && script[1] == 0x14 && script[22] == OP_EQUAL {
        return ScriptType::P2SH;
    }

    // P2WPKH: OP_0 <20 bytes>
    if script.len() == 22 && script[0] == OP_0 && script[1] == 0x14 {
        return ScriptType::P2WPKH;
    }

    // P2WSH: OP_0 <32 bytes>
    if script.len() == 34 && script[0] == OP_0 && script[1] == 0x20 {
        return ScriptType::P2WSH;
    }

    // P2TR: OP_1 <32 bytes>
    if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        return ScriptType::P2TR;
    }

    // OP_RETURN
    if !script.is_empty() && script[0] == OP_RETURN {
        return ScriptType::OpReturn;
    }

    ScriptType::Unknown
}

pub fn script_type_to_string(script_type: &ScriptType) -> &'static str {
    match script_type {
        ScriptType::P2PKH => "p2pkh",
        ScriptType::P2SH => "p2sh",
        ScriptType::P2WPKH => "p2wpkh",
        ScriptType::P2WSH => "p2wsh",
        ScriptType::P2TR => "p2tr",
        ScriptType::OpReturn => "op_return",
        ScriptType::Unknown => "unknown",
    }
}

pub fn encode_address(script: &[u8], network: &str) -> Option<String> {
    let script_type = classify_script(script);

    match script_type {
        ScriptType::P2PKH => {
            // Extract pubkey hash (skip OP_DUP OP_HASH160 0x14, take 20 bytes)
            let pubkey_hash = &script[3..23];
            encode_base58_address(pubkey_hash, if network == "mainnet" { 0x00 } else { 0x6f })
        }
        ScriptType::P2SH => {
            // Extract script hash (skip OP_HASH160 0x14, take 20 bytes)
            let script_hash = &script[2..22];
            encode_base58_address(script_hash, if network == "mainnet" { 0x05 } else { 0xc4 })
        }
        ScriptType::P2WPKH | ScriptType::P2WSH => {
            // Bech32 encoding
            let witness_version = 0;
            let witness_program = &script[2..];
            encode_bech32_address(witness_version, witness_program, network)
        }
        ScriptType::P2TR => {
            // Bech32m encoding (witness v1)
            let witness_version = 1;
            let witness_program = &script[2..];
            encode_bech32_address(witness_version, witness_program, network)
        }
        _ => None,
    }
}

fn encode_base58_address(hash: &[u8], version: u8) -> Option<String> {
    let mut payload = vec![version];
    payload.extend_from_slice(hash);

    // Add checksum
    let checksum = &double_sha256(&payload)[..4];
    payload.extend_from_slice(checksum);

    Some(bs58::encode(payload).into_string())
}

fn encode_bech32_address(witness_version: u8, witness_program: &[u8], network: &str) -> Option<String> {
    use bech32::{Bech32, Bech32m, Hrp};

    let hrp_str = if network == "mainnet" { "bc" } else { "tb" };
    let hrp = Hrp::parse(hrp_str).ok()?;

    // Prepare data: witness version + witness program
    let mut data = vec![witness_version];
    data.extend_from_slice(witness_program);

    if witness_version == 0 {
        // Use Bech32 for witness v0
        bech32::encode::<Bech32>(hrp, &data).ok()
    } else {
        // Use Bech32m for witness v1+
        bech32::encode::<Bech32m>(hrp, &data).ok()
    }
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(&hash1);
    hash2.to_vec()
}

pub fn extract_op_return_data(script: &[u8]) -> Option<(Vec<u8>, String, Option<String>, String)> {
    if script.is_empty() || script[0] != OP_RETURN {
        return None;
    }

    let mut data = Vec::new();
    let mut i = 1;

    while i < script.len() {
        let opcode = script[i];
        i += 1;

        if opcode == 0 {
            // OP_0 - empty push
            continue;
        } else if opcode >= 1 && opcode <= 75 {
            // Direct push (0x01-0x4b)
            if i + opcode as usize > script.len() {
                break;
            }
            data.extend_from_slice(&script[i..i + opcode as usize]);
            i += opcode as usize;
        } else if opcode == OP_PUSHDATA1 {
            if i >= script.len() {
                break;
            }
            let len = script[i] as usize;
            i += 1;
            if i + len > script.len() {
                break;
            }
            data.extend_from_slice(&script[i..i + len]);
            i += len;
        } else if opcode == OP_PUSHDATA2 {
            if i + 1 >= script.len() {
                break;
            }
            let len = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            i += 2;
            if i + len > script.len() {
                break;
            }
            data.extend_from_slice(&script[i..i + len]);
            i += len;
        } else if opcode == OP_PUSHDATA4 {
            if i + 3 >= script.len() {
                break;
            }
            let len = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]]) as usize;
            i += 4;
            if i + len > script.len() {
                break;
            }
            data.extend_from_slice(&script[i..i + len]);
            i += len;
        } else {
            // Unknown opcode, stop parsing
            break;
        }
    }

    let data_hex = hex::encode(&data);

    // Return None (null) if not valid UTF-8, per spec
    let data_utf8 = String::from_utf8(data.clone()).ok();

    // Detect protocol
    let protocol = if data.starts_with(b"omni") {
        "omni"
    } else if data.starts_with(&[0x01, 0x09, 0xf9, 0x11, 0x02]) {
        "opentimestamps"
    } else {
        "unknown"
    };

    Some((data, data_hex, data_utf8, protocol.to_string()))
}

#[derive(Debug, PartialEq)]
pub enum InputScriptType {
    P2PKH,
    P2SHP2WPKH,
    P2SHP2WSH,
    P2WPKH,
    P2WSH,
    P2TRKeypath,
    P2TRScriptpath,
    Unknown,
}

pub fn classify_input(script_sig: &[u8], witness: &[Vec<u8>], prevout_script: &[u8]) -> InputScriptType {
    let prevout_type = classify_script(prevout_script);

    // Check witness data
    let has_witness = !witness.is_empty();

    match prevout_type {
        ScriptType::P2PKH => InputScriptType::P2PKH,
        ScriptType::P2SH => {
            // Could be nested SegWit
            if has_witness && !script_sig.is_empty() {
                // Check if scriptSig is a push of witness script
                // scriptSig for P2SH-P2WPKH: [0x16][0x00][0x14][20 bytes] = 23 bytes total
                // scriptSig for P2SH-P2WSH:  [0x22][0x00][0x20][32 bytes] = 35 bytes total
                if script_sig.len() == 23 && script_sig[0] == 0x16 && script_sig[1] == 0x00 && script_sig[2] == 0x14 {
                    InputScriptType::P2SHP2WPKH
                } else if script_sig.len() == 35 && script_sig[0] == 0x22 && script_sig[1] == 0x00 && script_sig[2] == 0x20 {
                    InputScriptType::P2SHP2WSH
                } else {
                    InputScriptType::Unknown
                }
            } else {
                InputScriptType::Unknown
            }
        }
        ScriptType::P2WPKH => InputScriptType::P2WPKH,
        ScriptType::P2WSH => InputScriptType::P2WSH,
        ScriptType::P2TR => {
            // BIP341: strip annex if present (last witness item starting with 0x50)
            let effective: &[Vec<u8>] = if witness.len() >= 2
                && witness.last().map(|a| a.first() == Some(&0x50)).unwrap_or(false)
            {
                &witness[..witness.len() - 1]
            } else {
                witness
            };
            // BIP341: keypath witness = [sig] where sig is 64 bytes (SIGHASH_DEFAULT)
            // or 65 bytes (explicit sighash type appended). Scriptpath needs >= 2 items.
            if effective.len() == 1 && (effective[0].len() == 64 || effective[0].len() == 65) {
                InputScriptType::P2TRKeypath
            } else {
                InputScriptType::P2TRScriptpath
            }
        }
        _ => InputScriptType::Unknown,
    }
}

pub fn input_script_type_to_string(input_type: &InputScriptType) -> &'static str {
    match input_type {
        InputScriptType::P2PKH => "p2pkh",
        InputScriptType::P2SHP2WPKH => "p2sh-p2wpkh",
        InputScriptType::P2SHP2WSH => "p2sh-p2wsh",
        InputScriptType::P2WPKH => "p2wpkh",
        InputScriptType::P2WSH => "p2wsh",
        InputScriptType::P2TRKeypath => "p2tr_keypath",
        InputScriptType::P2TRScriptpath => "p2tr_scriptpath",
        InputScriptType::Unknown => "unknown",
    }
}
