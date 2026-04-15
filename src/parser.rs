use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
    pub has_witness: bool,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TxIn {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

pub struct Parser<'a> {
    data: &'a [u8],
    pub pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(anyhow!("Unexpected end of data"));
        }
        let val = self.data[self.pos];
        self.pos += 1;
        Ok(val)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(anyhow!("Unexpected end of data"));
        }
        let val = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(anyhow!("Unexpected end of data"));
        }
        let val = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        Ok(self.read_u32()? as i32)
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        if self.pos + 8 > self.data.len() {
            return Err(anyhow!("Unexpected end of data"));
        }
        let val = u64::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(val)
    }

    pub fn read_varint(&mut self) -> Result<u64> {
        let first = self.read_u8()?;
        match first {
            0..=0xfc => Ok(first as u64),
            0xfd => Ok(self.read_u16()? as u64),
            0xfe => Ok(self.read_u32()? as u64),
            0xff => self.read_u64(),
        }
    }

    pub fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        if self.pos + len > self.data.len() {
            return Err(anyhow!("Unexpected end of data"));
        }
        let bytes = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(bytes)
    }
}

/// Parse a transaction from raw bytes (used in block mode — avoids O(n²) hex encoding).
pub fn parse_transaction_raw(raw_bytes: &[u8]) -> Result<Transaction> {
    let mut parser = Parser::new(raw_bytes);

    let version = parser.read_i32()?;

    let marker = parser.read_u8()?;
    let has_witness = if marker == 0 {
        let flag = parser.read_u8()?;
        if flag != 1 {
            return Err(anyhow!("Invalid witness flag"));
        }
        true
    } else {
        parser.pos -= 1;
        false
    };

    let input_count = parser.read_varint()?;
    let mut inputs = Vec::new();
    for _ in 0..input_count {
        let mut prev_txid = parser.read_bytes(32)?;
        prev_txid.reverse();
        let prev_vout = parser.read_u32()?;
        let script_len = parser.read_varint()?;
        let script_sig = parser.read_bytes(script_len as usize)?;
        let sequence = parser.read_u32()?;
        inputs.push(TxIn { prev_txid: prev_txid.try_into().unwrap(), prev_vout, script_sig, sequence, witness: Vec::new() });
    }

    let output_count = parser.read_varint()?;
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let value = parser.read_u64()?;
        let script_len = parser.read_varint()?;
        let script_pubkey = parser.read_bytes(script_len as usize)?;
        outputs.push(TxOut { value, script_pubkey });
    }

    if has_witness {
        for input in &mut inputs {
            let witness_count = parser.read_varint()?;
            let mut witness = Vec::new();
            for _ in 0..witness_count {
                let item_len = parser.read_varint()?;
                let item = parser.read_bytes(item_len as usize)?;
                witness.push(item);
            }
            input.witness = witness;
        }
    }

    let locktime = parser.read_u32()?;
    let actual_raw_bytes = raw_bytes[..parser.pos].to_vec();
    Ok(Transaction { version, inputs, outputs, locktime, has_witness, raw_bytes: actual_raw_bytes })
}

pub fn parse_transaction(hex_str: &str) -> Result<Transaction> {
    let raw_bytes = hex::decode(hex_str)?;
    let mut parser = Parser::new(&raw_bytes);

    let version = parser.read_i32()?;

    // Check for witness flag
    let marker = parser.read_u8()?;
    let has_witness = if marker == 0 {
        let flag = parser.read_u8()?;
        if flag != 1 {
            return Err(anyhow!("Invalid witness flag"));
        }
        true
    } else {
        parser.pos -= 1; // Rewind, it was the input count
        false
    };

    // Parse inputs
    let input_count = parser.read_varint()?;
    let mut inputs = Vec::new();
    for _ in 0..input_count {
        let mut prev_txid = parser.read_bytes(32)?;
        prev_txid.reverse(); // Bitcoin stores in little-endian
        let prev_vout = parser.read_u32()?;
        let script_len = parser.read_varint()?;
        let script_sig = parser.read_bytes(script_len as usize)?;
        let sequence = parser.read_u32()?;

        inputs.push(TxIn {
            prev_txid: prev_txid.try_into().unwrap(),
            prev_vout,
            script_sig,
            sequence,
            witness: Vec::new(),
        });
    }

    // Parse outputs
    let output_count = parser.read_varint()?;
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let value = parser.read_u64()?;
        let script_len = parser.read_varint()?;
        let script_pubkey = parser.read_bytes(script_len as usize)?;

        outputs.push(TxOut {
            value,
            script_pubkey,
        });
    }

    // Parse witness data if present
    if has_witness {
        for input in &mut inputs {
            let witness_count = parser.read_varint()?;
            let mut witness = Vec::new();
            for _ in 0..witness_count {
                let item_len = parser.read_varint()?;
                let item = parser.read_bytes(item_len as usize)?;
                witness.push(item);
            }
            input.witness = witness;
        }
    }

    let locktime = parser.read_u32()?;

    // Only store the bytes that were actually consumed (not the full input slice)
    let actual_raw_bytes = raw_bytes[..parser.pos].to_vec();

    Ok(Transaction {
        version,
        inputs,
        outputs,
        locktime,
        has_witness,
        raw_bytes: actual_raw_bytes,
    })
}

pub fn compute_txid(tx: &Transaction) -> String {
    // Serialize without witness data
    let mut serialized = Vec::new();

    // Version
    serialized.extend_from_slice(&tx.version.to_le_bytes());

    // Input count
    write_varint(&mut serialized, tx.inputs.len() as u64);

    // Inputs
    for input in &tx.inputs {
        let mut txid = input.prev_txid.to_vec();
        txid.reverse();
        serialized.extend_from_slice(&txid);
        serialized.extend_from_slice(&input.prev_vout.to_le_bytes());
        write_varint(&mut serialized, input.script_sig.len() as u64);
        serialized.extend_from_slice(&input.script_sig);
        serialized.extend_from_slice(&input.sequence.to_le_bytes());
    }

    // Output count
    write_varint(&mut serialized, tx.outputs.len() as u64);

    // Outputs
    for output in &tx.outputs {
        serialized.extend_from_slice(&output.value.to_le_bytes());
        write_varint(&mut serialized, output.script_pubkey.len() as u64);
        serialized.extend_from_slice(&output.script_pubkey);
    }

    // Locktime
    serialized.extend_from_slice(&tx.locktime.to_le_bytes());

    // Double SHA256
    let hash1 = Sha256::digest(&serialized);
    let hash2 = Sha256::digest(&hash1);

    // Reverse for display
    let mut result = hash2.to_vec();
    result.reverse();
    hex::encode(result)
}

pub fn compute_wtxid(tx: &Transaction) -> Option<String> {
    if !tx.has_witness {
        return None;
    }

    // Use the entire raw transaction (with witness data)
    let hash1 = Sha256::digest(&tx.raw_bytes);
    let hash2 = Sha256::digest(&hash1);

    let mut result = hash2.to_vec();
    result.reverse();
    Some(hex::encode(result))
}

fn write_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

pub fn compute_merkle_root(txids: &[Vec<u8>]) -> Vec<u8> {
    if txids.is_empty() {
        return vec![0; 32];
    }

    let mut level = txids.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::new();

        for i in (0..level.len()).step_by(2) {
            let left = &level[i];
            let right = if i + 1 < level.len() {
                &level[i + 1]
            } else {
                &level[i] // Duplicate last element if odd
            };

            let mut combined = Vec::new();
            combined.extend_from_slice(left);
            combined.extend_from_slice(right);

            let hash1 = Sha256::digest(&combined);
            let hash2 = Sha256::digest(&hash1);
            next_level.push(hash2.to_vec());
        }

        level = next_level;
    }

    level[0].clone()
}
