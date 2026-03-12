use sha2::{Digest, Sha256};
use std::io::{self, Read, Cursor};

// ─── XOR Decoding ───────────────────────────────────────────────────────────

pub fn xor_decode(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

// ─── Low-level readers ──────────────────────────────────────────────────────

fn read_u8(cur: &mut Cursor<&[u8]>) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    cur.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16_le(cur: &mut Cursor<&[u8]>) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    cur.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32_le(cur: &mut Cursor<&[u8]>) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    cur.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_i32_le(cur: &mut Cursor<&[u8]>) -> io::Result<i32> {
    let mut buf = [0u8; 4];
    cur.read_exact(&mut buf)?;
    Ok(i32::from_le_bytes(buf))
}

fn read_u64_le(cur: &mut Cursor<&[u8]>) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    cur.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_bytes(cur: &mut Cursor<&[u8]>, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    cur.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read Bitcoin compact size (varint)
fn read_varint(cur: &mut Cursor<&[u8]>) -> io::Result<u64> {
    let first = read_u8(cur)?;
    match first {
        0xfd => Ok(read_u16_le(cur)? as u64),
        0xfe => Ok(read_u32_le(cur)? as u64),
        0xff => read_u64_le(cur),
        n => Ok(n as u64),
    }
}

// ─── Data Structures ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
    pub block_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct TxInput {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone)]
pub struct TxOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub txid: [u8; 32],
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub witness: Vec<Vec<Vec<u8>>>,  // per-input witness stacks
    pub lock_time: u32,
    pub is_segwit: bool,
    pub raw_size: usize,    // total serialized size
    pub weight: usize,      // weight units
}

#[derive(Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

/// Prevout data from undo (rev) files
#[derive(Debug, Clone)]
pub struct PrevOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub height: u32,
    pub coinbase: bool,
}

/// Per-transaction undo data
#[derive(Debug, Clone)]
pub struct TxUndo {
    pub prevouts: Vec<PrevOut>,
}

/// Per-block undo data
#[derive(Debug, Clone)]
pub struct BlockUndo {
    pub tx_undos: Vec<TxUndo>,  // one per non-coinbase tx
}

// ─── Block Header Parsing ───────────────────────────────────────────────────

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

pub fn hash_to_hex_reversed(hash: &[u8; 32]) -> String {
    let mut reversed = *hash;
    reversed.reverse();
    hex::encode(reversed)
}

fn parse_block_header(cur: &mut Cursor<&[u8]>) -> io::Result<BlockHeader> {
    let start = cur.position() as usize;
    let version = read_i32_le(cur)?;
    let mut prev_block_hash = [0u8; 32];
    cur.read_exact(&mut prev_block_hash)?;
    let mut merkle_root = [0u8; 32];
    cur.read_exact(&mut merkle_root)?;
    let timestamp = read_u32_le(cur)?;
    let bits = read_u32_le(cur)?;
    let nonce = read_u32_le(cur)?;
    let end = cur.position() as usize;

    let header_bytes = &cur.get_ref()[start..end];
    let block_hash = double_sha256(header_bytes);

    Ok(BlockHeader {
        version,
        prev_block_hash,
        merkle_root,
        timestamp,
        bits,
        nonce,
        block_hash,
    })
}

// ─── Transaction Parsing ────────────────────────────────────────────────────

fn parse_tx_input(cur: &mut Cursor<&[u8]>) -> io::Result<TxInput> {
    let mut prev_txid = [0u8; 32];
    cur.read_exact(&mut prev_txid)?;
    let prev_vout = read_u32_le(cur)?;
    let script_len = read_varint(cur)? as usize;
    let script_sig = read_bytes(cur, script_len)?;
    let sequence = read_u32_le(cur)?;
    Ok(TxInput {
        prev_txid,
        prev_vout,
        script_sig,
        sequence,
    })
}

fn parse_tx_output(cur: &mut Cursor<&[u8]>) -> io::Result<TxOutput> {
    let value = read_u64_le(cur)?;
    let script_len = read_varint(cur)? as usize;
    let script_pubkey = read_bytes(cur, script_len)?;
    Ok(TxOutput {
        value,
        script_pubkey,
    })
}

fn parse_transaction(cur: &mut Cursor<&[u8]>) -> io::Result<Transaction> {
    let tx_start = cur.position() as usize;

    let version = read_i32_le(cur)?;

    // Check for segwit marker
    let marker_pos = cur.position();
    let marker = read_u8(cur)?;
    let flag = read_u8(cur)?;

    let is_segwit = marker == 0x00 && flag == 0x01;
    if !is_segwit {
        // Reset — marker/flag were actually the input count
        cur.set_position(marker_pos);
    }

    // Parse inputs
    let input_count = read_varint(cur)? as usize;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        inputs.push(parse_tx_input(cur)?);
    }

    // Parse outputs
    let output_count = read_varint(cur)? as usize;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(parse_tx_output(cur)?);
    }

    // Parse witness data if segwit
    let mut witness = Vec::new();
    if is_segwit {
        for _ in 0..input_count {
            let stack_items = read_varint(cur)? as usize;
            let mut stack = Vec::with_capacity(stack_items);
            for _ in 0..stack_items {
                let item_len = read_varint(cur)? as usize;
                stack.push(read_bytes(cur, item_len)?);
            }
            witness.push(stack);
        }
    }

    let lock_time = read_u32_le(cur)?;
    let tx_end = cur.position() as usize;
    let raw_size = tx_end - tx_start;

    // Compute txid (hash of non-witness serialization)
    let txid = compute_txid(cur.get_ref(), tx_start, version, &inputs, &outputs, lock_time);

    // Compute weight: non-witness * 4 + witness * 1
    // non-witness size = version(4) + varint(in_count) + inputs + varint(out_count) + outputs + locktime(4)
    let weight = if is_segwit {
        let non_witness_size = raw_size - witness_data_size(&witness) - 2; // subtract marker+flag and witness
        non_witness_size * 4 + (raw_size - non_witness_size) * 1
    } else {
        raw_size * 4
    };

    Ok(Transaction {
        txid,
        version,
        inputs,
        outputs,
        witness,
        lock_time,
        is_segwit,
        raw_size,
        weight,
    })
}

fn witness_data_size(witness: &[Vec<Vec<u8>>]) -> usize {
    let mut size = 0;
    for stack in witness {
        size += varint_size(stack.len() as u64);
        for item in stack {
            size += varint_size(item.len() as u64);
            size += item.len();
        }
    }
    size
}

fn varint_size(val: u64) -> usize {
    if val < 0xfd { 1 }
    else if val <= 0xffff { 3 }
    else if val <= 0xffff_ffff { 5 }
    else { 9 }
}

fn compute_txid(
    _raw: &[u8],
    _start: usize,
    version: i32,
    inputs: &[TxInput],
    outputs: &[TxOutput],
    lock_time: u32,
) -> [u8; 32] {
    // Serialize without witness for txid
    let mut buf = Vec::new();
    buf.extend_from_slice(&version.to_le_bytes());

    // inputs
    push_varint(&mut buf, inputs.len() as u64);
    for inp in inputs {
        buf.extend_from_slice(&inp.prev_txid);
        buf.extend_from_slice(&inp.prev_vout.to_le_bytes());
        push_varint(&mut buf, inp.script_sig.len() as u64);
        buf.extend_from_slice(&inp.script_sig);
        buf.extend_from_slice(&inp.sequence.to_le_bytes());
    }

    // outputs
    push_varint(&mut buf, outputs.len() as u64);
    for out in outputs {
        buf.extend_from_slice(&out.value.to_le_bytes());
        push_varint(&mut buf, out.script_pubkey.len() as u64);
        buf.extend_from_slice(&out.script_pubkey);
    }

    buf.extend_from_slice(&lock_time.to_le_bytes());
    double_sha256(&buf)
}

fn push_varint(buf: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

// ─── Block Parsing ──────────────────────────────────────────────────────────

const BITCOIN_MAGIC: u32 = 0xD9B4BEF9;

pub fn parse_blocks(data: &[u8]) -> io::Result<Vec<Block>> {
    let mut cur = Cursor::new(data);
    let mut blocks = Vec::new();
    let len = data.len() as u64;

    while cur.position() + 8 < len {
        // Read magic number
        let magic = read_u32_le(&mut cur)?;
        if magic != BITCOIN_MAGIC {
            // Try to scan forward for magic
            let pos = cur.position() as usize;
            if let Some(offset) = find_magic(&data[pos..]) {
                cur.set_position((pos + offset) as u64);
                continue;
            }
            break;
        }

        let block_size = read_u32_le(&mut cur)? as usize;
        let block_start = cur.position() as usize;

        if block_start + block_size > data.len() {
            break;
        }

        // Parse header
        let header = parse_block_header(&mut cur)?;

        // Parse transactions
        let tx_count = read_varint(&mut cur)? as usize;
        let mut transactions = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            transactions.push(parse_transaction(&mut cur)?);
        }

        // Ensure cursor is at block end
        cur.set_position((block_start + block_size) as u64);

        blocks.push(Block {
            header,
            transactions,
        });
    }

    Ok(blocks)
}

fn find_magic(data: &[u8]) -> Option<usize> {
    let magic_bytes = BITCOIN_MAGIC.to_le_bytes();
    data.windows(4).position(|w| w == magic_bytes)
}

// ─── Undo Data Parsing ─────────────────────────────────────────────────────

/// Read Bitcoin Core VARINT encoding (MSB continuation, different from CompactSize)
fn read_core_varint(cur: &mut Cursor<&[u8]>) -> io::Result<u64> {
    let mut n: u64 = 0;
    loop {
        let b = read_u8(cur)? as u64;
        if n > (u64::MAX - 0x7F) >> 7 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "core varint overflow"));
        }
        n = (n << 7) | (b & 0x7F);
        if b & 0x80 != 0 {
            n += 1;
        } else {
            break;
        }
    }
    Ok(n)
}

/// Read a compressed amount (Bitcoin Core's CTxOutCompressor format)
fn read_compressed_amount(cur: &mut Cursor<&[u8]>) -> io::Result<u64> {
    let n = read_core_varint(cur)?;
    Ok(decompress_amount(n))
}

fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    x -= 1;
    let e = x % 10;
    x /= 10;
    let mut n = if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        x * 10 + d
    } else {
        x + 1
    };
    for _ in 0..e {
        n *= 10;
    }
    n
}

/// Read a compressed script
fn read_compressed_script(cur: &mut Cursor<&[u8]>) -> io::Result<Vec<u8>> {
    let size = read_varint(cur)?;  // CompactSize for script type/size
    match size {
        0x00 => {
            // P2PKH: 20 bytes key hash
            let hash = read_bytes(cur, 20)?;
            let mut script = Vec::with_capacity(25);
            script.push(0x76); // OP_DUP
            script.push(0xa9); // OP_HASH160
            script.push(0x14); // push 20 bytes
            script.extend_from_slice(&hash);
            script.push(0x88); // OP_EQUALVERIFY
            script.push(0xac); // OP_CHECKSIG
            Ok(script)
        }
        0x01 => {
            // P2SH: 20 bytes script hash
            let hash = read_bytes(cur, 20)?;
            let mut script = Vec::with_capacity(23);
            script.push(0xa9); // OP_HASH160
            script.push(0x14); // push 20 bytes
            script.extend_from_slice(&hash);
            script.push(0x87); // OP_EQUAL
            Ok(script)
        }
        0x02 | 0x03 => {
            // Compressed pubkey (P2PK)
            let key_data = read_bytes(cur, 32)?;
            let mut script = Vec::with_capacity(35);
            script.push(0x21); // push 33 bytes
            script.push(size as u8);
            script.extend_from_slice(&key_data);
            script.push(0xac); // OP_CHECKSIG
            Ok(script)
        }
        0x04 | 0x05 => {
            // Uncompressed pubkey (P2PK) — stored compressed, we reconstruct
            let key_data = read_bytes(cur, 32)?;
            // Store as compressed P2PK (we don't need the full uncompressed key for analysis)
            let mut script = Vec::with_capacity(35);
            script.push(0x21); // push 33 bytes
            script.push(if size == 0x04 { 0x02 } else { 0x03 });
            script.extend_from_slice(&key_data);
            script.push(0xac); // OP_CHECKSIG
            Ok(script)
        }
        n => {
            // Raw script, size is n - 6
            let script_len = (n - 6) as usize;
            if script_len > 10_000 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("compressed script too large: {} (varint={})", script_len, n),
                ));
            }
            read_bytes(cur, script_len)
        }
    }
}

/// Read height+coinbase encoding in undo data (uses Core VARINT, not CompactSize)
fn read_height_and_coinbase(cur: &mut Cursor<&[u8]>) -> io::Result<(u32, bool)> {
    let code = read_core_varint(cur)?;
    let coinbase = (code & 1) != 0;
    let height = (code >> 1) as u32;
    Ok((height, coinbase))
}

/// Parse a single TxUndo: reads CompactSize prevout count, then each prevout
fn parse_tx_undo(cur: &mut Cursor<&[u8]>) -> io::Result<TxUndo> {
    let input_count = read_varint(cur)? as usize;
    if input_count > 100_000 {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            format!("unlikely input_count {} at pos {}", input_count, cur.position())));
    }
    let mut prevouts = Vec::with_capacity(input_count);
    for j in 0..input_count {
        let pos_before = cur.position();
        let (height, coinbase) = read_height_and_coinbase(cur)?;
        // Dummy version byte (backward compat) — present when height > 0
        if height > 0 {
            let _version_dummy = read_core_varint(cur)?;
        }
        let value = read_compressed_amount(cur)?;
        let script_pubkey = read_compressed_script(cur).map_err(|e| {
            io::Error::new(e.kind(), format!("prevout[{}/{}] h={} cb={} val={} start_pos={}: {}",
                j, input_count, height, coinbase, value, pos_before, e))
        })?;
        prevouts.push(PrevOut {
            value,
            script_pubkey,
            height,
            coinbase,
        });
    }
    Ok(TxUndo { prevouts })
}

pub fn parse_block_undo(cur: &mut Cursor<&[u8]>) -> io::Result<BlockUndo> {
    let tx_count = read_varint(cur)? as usize;
    let mut tx_undos = Vec::with_capacity(tx_count);
    for i in 0..tx_count {
        let undo = parse_tx_undo(cur).map_err(|e| {
            io::Error::new(e.kind(), format!("tx_undo[{}/{}] at pos {}: {}", i, tx_count, cur.position(), e))
        })?;
        tx_undos.push(undo);
    }
    Ok(BlockUndo { tx_undos })
}

/// Parse all block undos from a rev file.
/// Rev files have the same magic+size framing as blk files.
pub fn parse_rev_blocks(data: &[u8], _blocks: &[Block]) -> io::Result<Vec<BlockUndo>> {
    let mut cur = Cursor::new(data);
    let mut undos = Vec::new();
    let len = data.len() as u64;

    while cur.position() + 8 < len {
        let magic = read_u32_le(&mut cur)?;
        if magic != BITCOIN_MAGIC {
            let pos = cur.position() as usize;
            if let Some(offset) = find_magic(&data[pos..]) {
                cur.set_position((pos + offset) as u64);
                continue;
            }
            break;
        }

        let block_size = read_u32_le(&mut cur)? as usize;
        let block_start = cur.position() as usize;

        if block_start + block_size > data.len() {
            break;
        }

        let undo = parse_block_undo(&mut cur)?;

        // Skip to end of block (undo data may include trailing checksum)
        cur.set_position((block_start + block_size) as u64);

        undos.push(undo);
    }

    Ok(undos)
}

// ─── Script Type Classification ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptType {
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR,
    OpReturn,
    P2PK,
    Unknown,
}

impl ScriptType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScriptType::P2PKH => "p2pkh",
            ScriptType::P2SH => "p2sh",
            ScriptType::P2WPKH => "p2wpkh",
            ScriptType::P2WSH => "p2wsh",
            ScriptType::P2TR => "p2tr",
            ScriptType::OpReturn => "op_return",
            ScriptType::P2PK => "p2pk",
            ScriptType::Unknown => "unknown",
        }
    }
}

pub fn classify_script(script: &[u8]) -> ScriptType {
    let len = script.len();

    // OP_RETURN
    if len > 0 && script[0] == 0x6a {
        return ScriptType::OpReturn;
    }

    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if len == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        return ScriptType::P2PKH;
    }

    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if len == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        return ScriptType::P2SH;
    }

    // P2WPKH: OP_0 <20 bytes>
    if len == 22 && script[0] == 0x00 && script[1] == 0x14 {
        return ScriptType::P2WPKH;
    }

    // P2WSH: OP_0 <32 bytes>
    if len == 34 && script[0] == 0x00 && script[1] == 0x20 {
        return ScriptType::P2WSH;
    }

    // P2TR: OP_1 <32 bytes>
    if len == 34 && script[0] == 0x51 && script[1] == 0x20 {
        return ScriptType::P2TR;
    }

    // P2PK: <33 or 65 byte pubkey> OP_CHECKSIG
    if (len == 35 && script[0] == 0x21 && script[34] == 0xac)
        || (len == 67 && script[0] == 0x41 && script[66] == 0xac)
    {
        return ScriptType::P2PK;
    }

    ScriptType::Unknown
}

// ─── BIP34 Height Extraction ────────────────────────────────────────────────

pub fn extract_bip34_height(coinbase_script: &[u8]) -> Option<u32> {
    if coinbase_script.is_empty() {
        return None;
    }
    let nbytes = coinbase_script[0] as usize;
    if nbytes == 0 || nbytes > 4 || coinbase_script.len() < 1 + nbytes {
        return None;
    }
    let mut height: u32 = 0;
    for i in 0..nbytes {
        height |= (coinbase_script[1 + i] as u32) << (8 * i);
    }
    Some(height)
}

// ─── Coinbase Detection ─────────────────────────────────────────────────────

pub fn is_coinbase(tx: &Transaction) -> bool {
    tx.inputs.len() == 1
        && tx.inputs[0].prev_txid == [0u8; 32]
        && tx.inputs[0].prev_vout == 0xFFFFFFFF
}
