<p align="center">
  <img src="./assets/banner.png" alt="Summer of Bitcoin 2026 Banner" width="100%" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/₿-Bitcoin-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" />
  <img src="https://img.shields.io/badge/Protocol_Level-FF6B00?style=for-the-badge" />
</p>

<h1 align="center">Summer of Bitcoin 2026</h1>
<p align="center"><em>Three Bitcoin Development Challenges</em></p>

<p align="center">
  <code>Transaction Parser</code> · <code>PSBT Builder</code> · <code>Chain Analysis</code>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=flat-square&logo=rust&logoColor=white" />
  <img src="https://img.shields.io/badge/Protocol_Level-FF6B00?style=flat-square" />
  <img src="https://img.shields.io/badge/Lines_of_Code-9200+-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Tests-203-brightgreen?style=flat-square" />
</p>

---

<p align="center">
  <a href="#challenges">Challenges</a> · <a href="#tech-stack">Tech Stack</a> · <a href="#architecture">Architecture</a> · <a href="#getting-started">Getting Started</a>
</p>

---

Three Bitcoin development challenges completed as part of [Summer of Bitcoin](https://www.summerofbitcoin.org/) 2026 — a global open-source program that selects developers through protocol-level coding challenges before matching them with Bitcoin projects for a paid internship.

Each challenge was built from a specification: core logic as a CLI, comprehensive tests, and a web visualizer. All three are written entirely in **Rust** with embedded single-page web UIs — no npm, no bundler, just `cargo build`.

---

## Challenges

---

### ₿ Chain Lens — Transaction Parser & Visualizer

> **Challenge 1** · [`challenge-1-chain-lens/`](./2026-developer-challenge-1-chain-lens-pradhyum6144/)

Parse raw Bitcoin transactions and blocks from hex into structured JSON. Classify every script type, compute fees and weights, detect timelocks, and explore the results through an interactive web visualizer.

| Capability | Details |
|---|---|
| **Parsing** | Raw hex transactions with full SegWit & witness support |
| **Block mode** | Reads `blk.dat` / `rev.dat` / `xor.dat` files, XOR-decodes, iterates all blocks |
| **Script classification** | P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP\_RETURN, Bare Multisig |
| **Script disassembly** | Full opcode disassembly for inputs & outputs, witnessScript for P2WSH |
| **Timelock detection** | BIP68 relative timelocks (blocks & time), absolute locktime |
| **SegWit savings** | Witness vs legacy weight comparison with savings percentage |
| **Visualization** | Interactive web UI with transaction flow diagrams |

**Stack:** Rust · axum · sha2 · bech32 · bs58

---

### ₿ Coin Smith — PSBT Transaction Builder

> **Challenge 2** · 124 tests · [`challenge-2-coin-smith/`](./2026-developer-challenge-2-coin-smith-pradhyum6144/)

Build safe, unsigned Bitcoin transactions from a set of UTXOs. Select coins with multiple strategies, estimate fees down to the vbyte, handle RBF and locktime, and export the result as a valid PSBT.

| Capability | Details |
|---|---|
| **Coin selection** | Branch-and-Bound (exact match), Largest-First, Lowest-Fee |
| **Fee estimation** | Per-input/output vbyte estimation with dust threshold detection |
| **RBF & Locktime** | Full sequence/locktime matrix per BIP 125 / BIP 68 |
| **Output** | PSBT Base64 export with strategy comparison and privacy meter |
| **Signing** | Test key signing and transaction finalization |
| **Privacy** | Input reuse detection + output linkage risk analysis |

**Stack:** Rust · bitcoin (rust-bitcoin) · actix-web · base64

---

### ₿ Sherlock — Chain Analysis Engine

> **Challenge 3** · 79 tests · [`challenge-3-sherlock/`](./2026-developer-challenge-3-sherlock-pradhyum6144/)

Analyze Bitcoin blocks with 9 chain-analysis heuristics. Classify every transaction, flag suspicious patterns, generate detailed reports, and explore results through an interactive web dashboard.

| Capability | Details |
|---|---|
| **9 heuristics** | CIOH, Change Detection, CoinJoin, Peeling Chain, Address Reuse, Round Number, Consolidation, Self-Transfer, OP\_RETURN |
| **Classification** | `simple`, `batch`, `consolidation`, `coinjoin`, `self_transfer` |
| **Reports** | JSON + Markdown with per-block and per-file statistics |
| **Performance** | 340k transactions parsed & analyzed in ~2 seconds |
| **Block parsing** | Full Bitcoin Core format: XOR decode, compressed undo data, BIP34 heights |

**Stack:** Rust · sha2 · serde · std::net (zero-dependency web server)

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Language** | Rust (2021/2024 edition) |
| **Bitcoin** | rust-bitcoin, sha2, ripemd, bech32, bs58 (protocol-level, no APIs) |
| **Web (Ch1)** | axum + tower-http (CORS, static files) |
| **Web (Ch2)** | actix-web + actix-cors |
| **Web (Ch3)** | `std::net::TcpListener` (zero external dependencies) |
| **Testing** | 203 tests across all challenges |
| **Serialization** | serde + serde\_json |

---

## Architecture

```
summer-of-bitcoin-2026/
├── challenge-1-chain-lens/         # Transaction parser + block parser
│   ├── src/
│   │   ├── main.rs                 # CLI entry point
│   │   ├── parser.rs               # Raw hex transaction deserializer
│   │   ├── block.rs                # Block/undo file parser, XOR decode
│   │   ├── analyzer.rs             # Fee, weight, timelock, warning analysis
│   │   ├── script.rs               # Script classification + disassembly
│   │   ├── types.rs                # Shared data structures
│   │   ├── web.rs                  # axum web server
│   │   └── index.html              # Embedded SPA visualizer
│   ├── fixtures/                   # Public test fixtures
│   └── grader/                     # Evaluation infrastructure
│
├── challenge-2-coin-smith/         # PSBT transaction builder
│   ├── src/
│   │   ├── main.rs                 # CLI entry point
│   │   ├── coin_selection.rs       # BnB, Largest-First, Lowest-Fee strategies
│   │   ├── builder.rs              # Transaction construction
│   │   ├── fixture.rs              # Fixture parsing + validation
│   │   ├── report.rs               # JSON report generation
│   │   ├── signer.rs               # Test key signing + PSBT finalization
│   │   ├── privacy.rs              # Privacy meter + input reuse detection
│   │   ├── descriptors.rs          # Watch-only descriptor export
│   │   ├── web.rs                  # actix-web server
│   │   └── lib.rs                  # Module re-exports
│   ├── tests/                      # 124 unit + integration tests
│   └── fixtures/                   # 35 public fixtures
│
├── challenge-3-sherlock/           # Chain analysis engine
│   ├── src/
│   │   ├── main.rs                 # CLI entry point
│   │   ├── parser.rs               # Block/undo binary parser, XOR decode
│   │   ├── analysis.rs             # 9 heuristics + classification engine
│   │   ├── output.rs               # JSON schema builder + Markdown reports
│   │   └── bin/web.rs              # HTTP server with inline SPA
│   ├── fixtures/                   # Compressed block files (.dat.gz)
│   ├── out/                        # Committed analysis reports
│   └── APPROACH.md                 # Heuristic documentation (20KB)
```

Each challenge is self-contained with its own `Cargo.toml`, `cli.sh`, `web.sh`, and `setup.sh`. All web UIs are embedded directly in the Rust binary — no separate frontend build step required.

---

## Getting Started

```bash
git clone https://github.com/pradhyum6144/summer-of-bitcoin-2026.git
cd summer-of-bitcoin-2026
```

### Challenge 1 — Chain Lens

```bash
cd challenge-1-chain-lens
./setup.sh
./cli.sh fixtures/transactions/tx_legacy_p2pkh.json    # Parse a transaction
./cli.sh --block fixtures/blocks/blk*.dat fixtures/blocks/rev*.dat fixtures/blocks/xor.dat  # Parse blocks
./web.sh                                                # Start visualizer at :3000
```

### Challenge 2 — Coin Smith

```bash
cd challenge-2-coin-smith
./setup.sh
./cli.sh fixtures/basic_change_p2wpkh.json             # Build a PSBT
cargo test                                              # Run 124 tests
./web.sh                                                # Start visualizer at :3000
```

### Challenge 3 — Sherlock

```bash
cd challenge-3-sherlock
./setup.sh                                              # Decompress block fixtures
./cli.sh --block fixtures/blk04330.dat fixtures/rev04330.dat fixtures/xor.dat
cargo test                                              # Run 79 tests
./web.sh                                                # Start dashboard at :3000
```

---

## License

MIT

---

<p align="center">
  Built by <strong>Pradhyum</strong> · <a href="https://www.summerofbitcoin.org/">Summer of Bitcoin 2026</a>
</p>
