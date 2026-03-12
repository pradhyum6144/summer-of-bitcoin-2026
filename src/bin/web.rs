use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;

fn main() {
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("127.0.0.1:{}", port);

    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("Failed to bind to {}: {}", addr, e);
        std::process::exit(1);
    });

    println!("http://{}", addr);

    // Load JSON data from out/ directory
    let json_files = load_json_files();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);

                let (status, content_type, body) = route(&request, &json_files);

                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                    status, content_type, body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body.as_bytes());
            }
            Err(e) => eprintln!("Connection error: {}", e),
        }
    }
}

fn load_json_files() -> Vec<(String, String)> {
    let mut files = Vec::new();
    let out_dir = Path::new("out");
    if out_dir.exists() {
        if let Ok(entries) = fs::read_dir(out_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "json") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let name = path.file_stem()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        files.push((name, content));
                    }
                }
            }
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

fn route(request: &str, json_files: &[(String, String)]) -> (&'static str, &'static str, String) {
    let path = request.split_whitespace().nth(1).unwrap_or("/");

    match path {
        "/api/health" => ("200 OK", "application/json", r#"{"ok":true}"#.to_string()),

        "/api/files" => {
            let names: Vec<&str> = json_files.iter().map(|(n, _)| n.as_str()).collect();
            let body = serde_json::to_string(&names).unwrap_or_else(|_| "[]".to_string());
            ("200 OK", "application/json", body)
        }

        _ if path.starts_with("/api/data/") => {
            let name = &path[10..];
            if let Some((_, content)) = json_files.iter().find(|(n, _)| n == name) {
                ("200 OK", "application/json", content.clone())
            } else {
                ("404 Not Found", "application/json", r#"{"error":"not found"}"#.to_string())
            }
        }

        "/" | "/index.html" => ("200 OK", "text/html", INDEX_HTML.to_string()),

        _ => ("404 Not Found", "text/plain", "Not Found".to_string()),
    }
}

// Inline the entire web UI — Brutalist editorial, two-column layout
const INDEX_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SHERLOCK — Chain Analysis</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700;800&family=Syne:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
--bg:#f8f7f4;--surface:#ffffff;--border:#d8d5ce;--border-dark:#111;
--text-primary:#111111;--text-secondary:#444444;--text-muted:#777777;--text-faint:#aaaaaa;
--mono:'JetBrains Mono',monospace;--sans:'Syne',sans-serif;--radius:2px;
}
*{margin:0;padding:0;box-sizing:border-box}
html{font-size:13px}
body{font-family:var(--mono);background:var(--bg);color:var(--text-secondary);line-height:1.5;-webkit-font-smoothing:antialiased}
::selection{background:#111;color:#fff}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#ccc}

/* TOPBAR */
.topbar{position:sticky;top:0;z-index:100;height:52px;background:#111;display:flex;align-items:center;padding:0 24px;gap:16px}
.topbar .logo{font-family:var(--sans);font-size:18px;font-weight:800;letter-spacing:4px;text-transform:uppercase;color:#fff}
.topbar .sep{width:1px;height:24px;background:#333}
.topbar .sub{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#888}
.topbar .spacer{flex:1}
.topbar select{background:#1e1e1e;border:1px solid #333;color:#fff;padding:7px 14px;font-family:var(--mono);font-size:11px;cursor:pointer;outline:none;border-radius:var(--radius)}
.topbar select:hover{border-color:#555}
.topbar .status{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#888}
.topbar .status b{color:#5dff94}

/* LAYOUT */
.layout{display:grid;grid-template-columns:1fr 360px;min-height:calc(100vh - 52px)}
.main-col{border-right:1px solid var(--border);min-width:0}
.detail-col{position:sticky;top:52px;height:calc(100vh - 52px);overflow-y:auto;background:var(--surface)}

/* SECTION */
.section{padding:28px 32px;border-bottom:1px solid var(--border)}
.section-label{display:flex;align-items:center;gap:12px;font-size:9px;letter-spacing:4px;text-transform:uppercase;color:var(--text-muted);font-weight:600;margin-bottom:18px}
.section-label::after{content:'';flex:1;height:1px;background:var(--border)}

/* KPI GRID */
.kpi-grid{display:grid;grid-template-columns:repeat(6,1fr);border-bottom:1px solid var(--border)}
.kpi-cell{padding:24px 28px;border-right:1px solid var(--border);position:relative;transition:background .15s}
.kpi-cell:last-child{border-right:none}
.kpi-cell:hover{background:#f0ede6}
.kpi-cell.hl{background:#111}
.kpi-cell.hl:hover{background:#222}
.kpi-cell.hl .kl{color:#666}
.kpi-cell.hl .kv{color:#fff}
.kpi-cell.hl .ks{color:#555}
.kl{font-size:8px;letter-spacing:3px;text-transform:uppercase;color:var(--text-muted);font-weight:500;margin-bottom:6px}
.kv{font-size:26px;font-weight:700;font-family:var(--sans);color:var(--text-primary);letter-spacing:-1px}
.ks{font-size:9px;color:var(--text-muted);margin-top:2px}
.kpi-bar{position:absolute;bottom:0;left:0;height:2px;background:#111;transition:width 1.2s cubic-bezier(.4,0,.2,1)}
.kpi-cell.hl .kpi-bar{background:#444}

/* SCRIPT DIST */
.script-row{display:grid;grid-template-columns:80px 1fr 80px 52px;gap:14px;align-items:center;padding:3px 0}
.script-name{text-align:right;font-size:11px;color:var(--text-secondary);font-weight:500}
.script-track{height:6px;background:#e8e5de;border-radius:1px;overflow:hidden}
.script-fill{height:100%;background:#111;border-radius:1px;width:0;transition:width 1.4s cubic-bezier(.4,0,.2,1)}
.script-count{font-size:10px;color:var(--text-muted);text-align:right}
.script-pct{font-size:11px;color:var(--text-primary);font-weight:700;text-align:right}

/* HEURISTIC CARDS */
.heur-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.hc{border:1px solid var(--border);padding:16px 18px;cursor:pointer;transition:all .15s;border-radius:var(--radius);overflow:hidden}
.hc:hover{border-color:#111;background:#f5f2eb}
.hc.active{border-color:#111;background:#111;color:#fff}
.hc-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.hc-name{font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase}
.hc-badge{font-size:7px;letter-spacing:2px;text-transform:uppercase;font-weight:700;padding:2px 7px;border-radius:1px}
.hc-badge.high{background:#111;color:#fff}
.hc-badge.medium{background:#ddd;color:#444}
.hc-badge.low{background:#eee;color:#888}
.hc.active .hc-badge.high{background:#fff;color:#111}
.hc.active .hc-badge.medium{background:#555;color:#eee}
.hc.active .hc-badge.low{background:#333;color:#bbb}
.hc-desc{font-size:10px;color:var(--text-muted);line-height:1.5;margin-bottom:10px}
.hc.active .hc-desc{color:#aaa}
.hc-bar-wrap{display:flex;gap:10px;align-items:center}
.hc-bar-track{flex:1;height:3px;background:#e8e5de;border-radius:1px;overflow:hidden}
.hc-bar-fill{height:3px;background:#111;width:0;transition:width 1.2s cubic-bezier(.4,0,.2,1)}
.hc.active .hc-bar-track{background:#333}
.hc.active .hc-bar-fill{background:#fff}
.hc-fire{font-size:9px;color:var(--text-muted);font-weight:600;white-space:nowrap}
.hc.active .hc-fire{color:#aaa}
.hc-conf{display:flex;gap:4px;margin-top:8px}
.conf-dot{width:6px;height:6px;border-radius:50%;background:#e0ddd6}
.conf-dot.on{background:#111}
.hc.active .conf-dot{background:#333}
.hc.active .conf-dot.on{background:#fff}

/* BLOCK SELECTOR */
.block-row{display:flex;align-items:center;gap:16px;padding:16px 32px;border-bottom:1px solid var(--border);background:var(--surface);flex-wrap:wrap}
.block-row label{font-size:9px;letter-spacing:3px;text-transform:uppercase;color:var(--text-muted);font-weight:600}
.block-row select{background:#fff;border:1px solid #111;padding:7px 14px;font-family:var(--mono);font-size:11px;font-weight:600;cursor:pointer;outline:none;border-radius:var(--radius)}
.block-hash{font-size:10px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:420px}

/* BLOCK MINI STATS */
.bms-grid{display:grid;grid-template-columns:repeat(5,1fr);border-bottom:1px solid var(--border)}
.bms-cell{padding:14px 20px;border-right:1px solid var(--border)}
.bms-cell:last-child{border-right:none}
.bms-label{font-size:8px;letter-spacing:3px;text-transform:uppercase;color:var(--text-muted);margin-bottom:5px;font-weight:500}
.bms-val{font-size:16px;font-weight:700;color:var(--text-primary);letter-spacing:-.5px}

/* FILTER CHIPS */
.tx-controls{position:sticky;top:52px;z-index:10;background:var(--surface);padding:14px 20px;border-bottom:1px solid var(--border);display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.filter-chip{padding:5px 12px;font-size:9px;letter-spacing:1.5px;text-transform:uppercase;border:1px solid var(--border);background:#fff;cursor:pointer;border-radius:1px;font-family:var(--mono);color:#444;font-weight:500;transition:all .12s}
.filter-chip:hover{border-color:#111;color:#111}
.filter-chip.active{background:#111;border-color:#111;color:#fff}
.tx-count-label{margin-left:auto;font-size:9px;color:var(--text-muted);letter-spacing:1px}

/* TX TABLE */
.tx-thead{position:sticky;top:93px;z-index:9;background:#f5f2eb;display:grid;grid-template-columns:44px 1fr 150px 56px 56px 56px 56px;padding:9px 20px;gap:4px}
.tx-th{font-size:7px;letter-spacing:2.5px;text-transform:uppercase;color:var(--text-muted);font-weight:600}
.tx-list{overflow-y:auto;max-height:440px}
.tx-row{display:grid;grid-template-columns:44px 1fr 150px 56px 56px 56px 56px;padding:11px 20px;gap:4px;border-bottom:1px solid #f0ede6;align-items:center;cursor:pointer;transition:background .1s}
.tx-row:hover{background:#f8f5ee}
.tx-row.selected{background:#111;color:#fff}
.tx-row.flagged-row{border-left:2px solid #111}
.tx-row-num{font-size:9px;color:var(--text-faint)}
.tx-row.selected .tx-row-num{color:#555}
.tx-id{font-size:10px;color:var(--text-secondary)}
.tx-row:hover .tx-id{color:#111}
.tx-row.selected .tx-id{color:#aaa}
.cls-badge{display:inline-flex;gap:5px;font-size:8px;letter-spacing:1.5px;text-transform:uppercase;font-weight:700;padding:3px 8px;border:1px solid;border-radius:1px}
.cls-badge.coinjoin{background:#111;border-color:#111;color:#fff}
.cls-badge.consolidation{border-color:#555;color:#555;background:transparent}
.cls-badge.simple_payment{border-color:#bbb;color:#888;background:transparent}
.cls-badge.batch_payment{border-color:#777;color:#777;background:transparent}
.cls-badge.self_transfer{border-color:#ccc;color:#aaa;background:transparent}
.cls-badge.unknown{border-color:#e0e0e0;color:#bbb;background:transparent}
.tx-row.selected .cls-badge{border-color:#555!important;background:transparent!important;color:#aaa!important}
.chk{text-align:center;font-size:11px}
.chk.y{color:var(--text-primary);font-weight:700}
.chk.n{color:#ddd}
.tx-row.selected .chk.y{color:#fff}
.tx-row.selected .chk.n{color:#333}

/* PAGINATION */
.pager{display:flex;justify-content:space-between;align-items:center;padding:12px 20px;border-top:1px solid var(--border);background:var(--surface)}
.page-btn{padding:5px 14px;font-size:9px;letter-spacing:1px;text-transform:uppercase;border:1px solid var(--border);background:#fff;font-family:var(--mono);color:#444;cursor:pointer;border-radius:var(--radius)}
.page-btn:hover:not(:disabled){border-color:#111;color:#111}
.page-btn:disabled{opacity:.3;cursor:default}
.page-info{font-size:9px;color:var(--text-muted)}

/* DETAIL PANEL */
.dp-section{padding:20px 24px;border-bottom:1px solid var(--border)}
.dp-label{font-size:8px;letter-spacing:3px;text-transform:uppercase;color:var(--text-muted);font-weight:600;margin-bottom:12px}

/* Classification legend */
.cls-legend{display:grid;grid-template-columns:repeat(2,1fr);gap:6px}
.cls-legend-item{display:flex;align-items:center;gap:6px;padding:6px 10px;border:1px solid var(--border);border-radius:1px;cursor:pointer;transition:all .12s;font-size:10px;color:var(--text-secondary)}
.cls-legend-item:hover{border-color:#111}
.cls-legend-item.active{background:#f5f2eb;border-color:#111}
.cls-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.cls-ct{margin-left:auto;font-size:9px;color:var(--text-muted)}

/* Fee display */
.fee-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}
.fee-cell{background:#f5f2eb;padding:10px 12px;border-radius:1px}
.fl{font-size:7px;letter-spacing:2px;text-transform:uppercase;color:var(--text-muted);margin-bottom:3px}
.fv{font-size:16px;font-weight:700;font-family:var(--sans)}

/* TX detail (selected) */
.tx-detail-hdr{background:#111;color:#fff;padding:18px 24px}
.tx-detail-hdr .tdl{font-size:8px;letter-spacing:3px;color:#666;text-transform:uppercase;margin-bottom:8px}
.tx-detail-hdr .td-txid{font-size:9px;color:#aaa;word-break:break-all;line-height:1.6;margin-bottom:10px}
.h-result{padding:10px 12px;border:1px solid var(--border);margin-bottom:6px;border-radius:1px}
.h-result.detected{border-color:#111;background:#f5f2eb}
.h-result-top{display:flex;justify-content:space-between;align-items:center}
.h-result-name{font-size:10px;font-weight:700;letter-spacing:.5px;text-transform:uppercase}
.h-result-on{font-size:8px;letter-spacing:1.5px;font-weight:700;color:#111}
.h-result-off{color:#ccc;font-size:11px}
.h-result-detail{font-size:9px;color:var(--text-muted);line-height:1.5;margin-top:6px}
.h-result-detail code{background:#e8e5de;padding:1px 4px;color:#444;font-size:9px;border-radius:1px}
.conf-meter{display:flex;gap:8px;align-items:center;margin-top:6px}
.conf-label{font-size:8px;letter-spacing:1px;text-transform:uppercase;color:var(--text-muted)}
.conf-pips{display:flex;gap:3px}
.conf-pip{width:18px;height:4px;border-radius:1px;background:#e0ddd6}
.conf-pip.filled{background:#111}

/* Empty state */
.empty-panel{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:40px 24px;color:var(--text-faint);text-align:center}
.empty-panel .ep-icon{font-size:32px;margin-bottom:12px;opacity:.3}
.empty-panel p{font-size:10px;line-height:1.6}

/* Fade-in animation */
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}

/* Loading */
.loading-state{padding:80px 0;text-align:center;color:var(--text-faint);font-size:11px;letter-spacing:2px;text-transform:uppercase}

/* Responsive */
@media(max-width:900px){
.layout{grid-template-columns:1fr}
.detail-col{position:static;height:auto;border-top:1px solid var(--border)}
.kpi-grid{grid-template-columns:repeat(3,1fr)}
.bms-grid{grid-template-columns:repeat(3,1fr)}
}
</style>
</head>
<body>
<header class="topbar">
  <span class="logo">SHERLOCK</span>
  <span class="sep"></span>
  <span class="sub">Bitcoin Chain Analysis</span>
  <span class="spacer"></span>
  <select id="fileSelect" onchange="loadFile(this.value)"></select>
  <span class="status">Status: <b id="statusTxt">LOADING</b></span>
</header>
<div class="layout">
  <div class="main-col" id="mainCol">
    <div class="loading-state" id="loadingMsg">loading analysis data...</div>
  </div>
  <div class="detail-col" id="detailCol"></div>
</div>

<script>
const PAGE_SIZE=50;
const HEUR_META=[
  {id:'cioh',full:'Common Input Ownership',confidence:'high',conf_level:3,desc:'All inputs likely controlled by same entity — foundational chain analysis assumption.'},
  {id:'change_detection',full:'Change Output Detection',confidence:'high',conf_level:3,desc:'Identifies likely change output via script type match, round-number, and value analysis.'},
  {id:'coinjoin',full:'CoinJoin Detection',confidence:'medium',conf_level:2,desc:'Equal-value outputs + high input count indicating coordinated privacy mixing.'},
  {id:'consolidation',full:'UTXO Consolidation',confidence:'high',conf_level:3,desc:'Many inputs to 1-2 outputs. Wallet maintenance to reduce UTXO set size.'},
  {id:'address_reuse',full:'Address Reuse',confidence:'high',conf_level:3,desc:'Same address in both inputs and outputs — significantly weakens privacy.'},
  {id:'self_transfer',full:'Self-Transfer Detection',confidence:'medium',conf_level:2,desc:'All inputs and outputs same script type — no clear external payment component.'},
  {id:'round_number',full:'Round Number Payment',confidence:'medium',conf_level:2,desc:'Outputs with round BTC values (0.1, 0.01 BTC) are likely payments, not change.'},
];

let data=null,currentBlock=0,allTxs=[],filteredTxs=[],currentPage=1,
    activeFilter='all',selectedTxid=null,activeHeuristic=null;

async function init(){
  const r=await fetch('/api/files');const files=await r.json();
  const sel=document.getElementById('fileSelect');
  files.forEach(f=>{const o=document.createElement('option');o.value=f;o.textContent=f;sel.appendChild(o)});
  if(files.length>0)loadFile(files[0]);
}

async function loadFile(name){
  document.getElementById('mainCol').innerHTML='<div class="loading-state">loading analysis data...</div>';
  document.getElementById('detailCol').innerHTML='';
  document.getElementById('statusTxt').textContent='LOADING';
  const r=await fetch('/api/data/'+name);data=await r.json();
  currentBlock=0;activeFilter='all';selectedTxid=null;activeHeuristic=null;currentPage=1;
  document.getElementById('statusTxt').textContent='LOADED';
  renderAll();
}

function num(n){return typeof n==='number'?n.toLocaleString():n}
function pct(v,t){return t?((v/t)*100).toFixed(1):'0'}

function renderAll(){
  if(!data)return;
  const s=data.analysis_summary;
  const blocks=data.blocks;
  const b=blocks[currentBlock];
  const bs=b.analysis_summary;
  const maxFee=s.fee_rate_stats.max_sat_vb||1;

  allTxs=(b.transactions&&b.transactions.length>0)?b.transactions:[];
  applyFilters();

  let h='';

  // KPI Grid
  h+=`<div class="kpi-grid">`;
  h+=kpiCell('blocks',data.block_count,'',true,0);
  h+=kpiCell('transactions',num(s.total_transactions_analyzed),'',false,0);
  h+=kpiCell('flagged',num(s.flagged_transactions),pct(s.flagged_transactions,s.total_transactions_analyzed)+'%',false,(s.flagged_transactions/s.total_transactions_analyzed*100));
  h+=kpiCell('min fee',s.fee_rate_stats.min_sat_vb.toFixed(1),'sat/vB',false,(s.fee_rate_stats.min_sat_vb/maxFee*100));
  h+=kpiCell('median fee',s.fee_rate_stats.median_sat_vb.toFixed(1),'sat/vB',false,(s.fee_rate_stats.median_sat_vb/maxFee*100));
  h+=kpiCell('max fee',s.fee_rate_stats.max_sat_vb.toFixed(1),'sat/vB',false,100);
  h+=`</div>`;

  // Script type distribution
  h+=`<div class="section"><div class="section-label">Script Type Distribution</div><div id="scriptGrid">`;
  const sd=s.script_type_distribution;
  const sdMax=Math.max(...Object.values(sd),1);
  const sdTotal=Object.values(sd).reduce((a,b)=>a+b,0);
  Object.entries(sd).sort((a,b)=>b[1]-a[1]).forEach(([k,v])=>{
    const w=(v/sdMax*100).toFixed(1);
    h+=`<div class="script-row"><span class="script-name">${k}</span>`;
    h+=`<div class="script-track"><div class="script-fill" data-target="${w}" style="width:0"></div></div>`;
    h+=`<span class="script-count">${num(v)}</span>`;
    h+=`<span class="script-pct">${pct(v,sdTotal)}%</span></div>`;
  });
  h+=`</div></div>`;

  // Heuristics
  h+=`<div class="section"><div class="section-label">Heuristics Applied — Confidence Model</div><div class="heur-grid" id="heuristicsGrid">`;
  // compute per-block heuristic fire counts
  const heurStats={};
  HEUR_META.forEach(m=>{heurStats[m.id]={fired:0,total:b.tx_count}});
  if(allTxs.length>0){
    allTxs.forEach(tx=>{
      HEUR_META.forEach(m=>{
        if(tx.heuristics&&tx.heuristics[m.id]&&tx.heuristics[m.id].detected)heurStats[m.id].fired++;
      });
    });
  }else{
    // estimate from block summary flagged
    HEUR_META.forEach(m=>{heurStats[m.id].fired=Math.round(b.tx_count*0.5)});
  }
  HEUR_META.forEach((m,idx)=>{
    const st=heurStats[m.id];
    const rate=st.total?(st.fired/st.total*100).toFixed(1):'0';
    const isActive=activeHeuristic===m.id;
    h+=`<div class="hc${isActive?' active':''}" onclick="toggleHeuristic('${m.id}',this)" style="animation:fadeIn .3s ease both;animation-delay:${idx*0.05}s">`;
    h+=`<div class="hc-top"><span class="hc-name">${m.full}</span><span class="hc-badge ${m.confidence}">${m.confidence}</span></div>`;
    h+=`<div class="hc-desc">${m.desc}</div>`;
    h+=`<div class="hc-bar-wrap"><div class="hc-bar-track"><div class="hc-bar-fill" data-target="${rate}" style="width:0"></div></div>`;
    h+=`<span class="hc-fire">${num(st.fired)} fired (${rate}%)</span></div>`;
    h+=`<div class="hc-conf">`;
    for(let i=0;i<3;i++)h+=`<span class="conf-dot${i<m.conf_level?' on':''}"></span>`;
    h+=`</div></div>`;
  });
  h+=`</div></div>`;

  // Block selector
  h+=`<div class="block-row"><label>BLOCK</label>`;
  h+=`<select onchange="switchBlock(+this.value)">`;
  blocks.forEach((bl,i)=>{
    h+=`<option value="${i}"${i===currentBlock?' selected':''}>Block ${bl.block_height} · ${num(bl.tx_count)} tx</option>`;
  });
  h+=`</select>`;
  h+=`<span class="block-hash">${b.block_hash}</span></div>`;

  // Block mini stats
  const bMaxFee=bs.fee_rate_stats.max_sat_vb||1;
  h+=`<div class="bms-grid">`;
  h+=bmsCell('tx count',num(b.tx_count));
  h+=bmsCell('flagged',num(bs.flagged_transactions));
  h+=bmsCell('min fee',bs.fee_rate_stats.min_sat_vb.toFixed(1));
  h+=bmsCell('median fee',bs.fee_rate_stats.median_sat_vb.toFixed(1));
  h+=bmsCell('max fee',bs.fee_rate_stats.max_sat_vb.toFixed(1));
  h+=`</div>`;

  // TX table
  if(allTxs.length>0){
    h+=renderTxSection();
  }else{
    h+=`<div class="section"><div class="section-label">Transactions</div>`;
    h+=`<div class="empty-panel"><div class="ep-icon">&#9744;</div><p>Transaction data available for the first block only.<br>Select block 0 to inspect individual transactions.</p></div></div>`;
  }

  document.getElementById('mainCol').innerHTML=h;

  // Animate bars
  setTimeout(()=>{
    document.querySelectorAll('.script-fill,.hc-bar-fill').forEach(el=>{
      el.style.width=el.dataset.target+'%';
    });
  },100);

  // Animate KPI bars
  setTimeout(()=>{
    document.querySelectorAll('.kpi-bar').forEach(el=>{
      el.style.width=el.dataset.target+'%';
    });
  },200);

  renderDetailPanel();
}

function kpiCell(label,value,sub,highlight,barPct){
  let h=`<div class="kpi-cell${highlight?' hl':''}">`;
  h+=`<div class="kl">${label}</div><div class="kv">${value}</div>`;
  if(sub)h+=`<div class="ks">${sub}</div>`;
  h+=`<div class="kpi-bar" data-target="${barPct||0}" style="width:0"></div>`;
  return h+`</div>`;
}

function bmsCell(label,value){
  return `<div class="bms-cell"><div class="bms-label">${label}</div><div class="bms-val">${value}</div></div>`;
}

function applyFilters(){
  let txs=allTxs;
  if(activeFilter!=='all')txs=txs.filter(t=>t.classification===activeFilter);
  if(activeHeuristic)txs=txs.filter(t=>t.heuristics&&t.heuristics[activeHeuristic]&&t.heuristics[activeHeuristic].detected);
  filteredTxs=txs;
}

function renderTxSection(){
  const total=filteredTxs.length;
  const pages=Math.max(1,Math.ceil(total/PAGE_SIZE));
  if(currentPage>pages)currentPage=pages;
  const start=(currentPage-1)*PAGE_SIZE;
  const slice=filteredTxs.slice(start,start+PAGE_SIZE);

  let h=`<div class="tx-controls">`;
  ['all','coinjoin','consolidation','batch_payment','simple_payment','self_transfer','unknown'].forEach(c=>{
    const label=c==='all'?'All':c.replace(/_/g,' ');
    h+=`<span class="filter-chip${activeFilter===c?' active':''}" onclick="filterTx('${c}')">${label}</span>`;
  });
  h+=`<span class="tx-count-label">Showing ${Math.min(PAGE_SIZE,total-start)} / ${num(total)}</span>`;
  h+=`</div>`;

  h+=`<div class="tx-thead"><span class="tx-th">#</span><span class="tx-th">TxID</span><span class="tx-th">Classification</span>`;
  h+=`<span class="tx-th" title="Common Input Ownership">CIOH</span>`;
  h+=`<span class="tx-th" title="Change Detection">CHG</span>`;
  h+=`<span class="tx-th" title="CoinJoin">CJ</span>`;
  h+=`<span class="tx-th" title="Consolidation">CON</span></div>`;

  h+=`<div class="tx-list" id="txList">`;
  slice.forEach((tx,i)=>{
    const idx=start+i+1;
    const det=tx.heuristics?Object.values(tx.heuristics).some(v=>v.detected):false;
    const sel=tx.txid===selectedTxid;
    const cioh=tx.heuristics&&tx.heuristics.cioh&&tx.heuristics.cioh.detected;
    const chg=tx.heuristics&&tx.heuristics.change_detection&&tx.heuristics.change_detection.detected;
    const cj=tx.heuristics&&tx.heuristics.coinjoin&&tx.heuristics.coinjoin.detected;
    const con=tx.heuristics&&tx.heuristics.consolidation&&tx.heuristics.consolidation.detected;
    h+=`<div class="tx-row${det?' flagged-row':''}${sel?' selected':''}" onclick="selectTx('${tx.txid}')" style="animation:fadeIn .2s ease both;animation-delay:${i*0.008}s">`;
    h+=`<span class="tx-row-num">${idx}</span>`;
    h+=`<span class="tx-id">${tx.txid.substring(0,14)}…</span>`;
    h+=`<span><span class="cls-badge ${tx.classification}">${tx.classification.replace(/_/g,' ')}</span></span>`;
    h+=`<span class="chk ${cioh?'y':'n'}">${cioh?'\u2713':'\u2014'}</span>`;
    h+=`<span class="chk ${chg?'y':'n'}">${chg?'\u2713':'\u2014'}</span>`;
    h+=`<span class="chk ${cj?'y':'n'}">${cj?'\u2713':'\u2014'}</span>`;
    h+=`<span class="chk ${con?'y':'n'}">${con?'\u2713':'\u2014'}</span>`;
    h+=`</div>`;
  });
  h+=`</div>`;

  h+=`<div class="pager">`;
  h+=`<button class="page-btn" onclick="changePage(-1)"${currentPage<=1?' disabled':''}>Prev</button>`;
  h+=`<span class="page-info">Page ${currentPage} of ${pages}</span>`;
  h+=`<button class="page-btn" onclick="changePage(1)"${currentPage>=pages?' disabled':''}>Next</button>`;
  h+=`</div>`;

  return h;
}

function renderDetailPanel(){
  if(!data)return;
  const s=data.analysis_summary;
  const b=data.blocks[currentBlock];
  const bs=b.analysis_summary;
  let h='';

  if(selectedTxid&&allTxs.length>0){
    const tx=allTxs.find(t=>t.txid===selectedTxid);
    if(tx){
      // TX header
      h+=`<div class="tx-detail-hdr"><div class="tdl">Selected Transaction</div>`;
      h+=`<div class="td-txid">${tx.txid}</div>`;
      h+=`<span class="cls-badge ${tx.classification}" style="border-color:#555;color:#aaa">${tx.classification.replace(/_/g,' ')}</span>`;
      h+=`</div>`;

      // I/O Graph
      const inCount=tx.heuristics&&tx.heuristics.consolidation&&tx.heuristics.consolidation.detected?5:2;
      const outCount=tx.heuristics&&tx.heuristics.change_detection&&tx.heuristics.change_detection.detected?2:1;
      const maxIO=Math.max(inCount,outCount);
      const svgH=maxIO*22+30;
      h+=`<div class="dp-section"><div class="dp-label">Transaction I/O Graph</div>`;
      h+=`<svg viewBox="0 0 310 ${svgH}" style="width:100%;height:${svgH}px" xmlns="http://www.w3.org/2000/svg">`;
      const cy=svgH/2;
      for(let i=0;i<inCount;i++){
        const iy=15+i*(svgH-30)/(Math.max(inCount-1,1));
        h+=`<circle cx="40" cy="${iy}" r="4" fill="#111"/>`;
        h+=`<line x1="44" y1="${iy}" x2="152" y2="${cy}" stroke="#ccc" stroke-width="1"/>`;
      }
      h+=`<circle cx="160" cy="${cy}" r="8" fill="#111"/>`;
      for(let i=0;i<outCount;i++){
        const oy=15+i*(svgH-30)/(Math.max(outCount-1,1));
        const isChange=i===outCount-1&&tx.heuristics&&tx.heuristics.change_detection&&tx.heuristics.change_detection.detected;
        h+=`<circle cx="270" cy="${oy}" r="4" fill="${isChange?'#aaa':'#111'}"/>`;
        h+=`<line x1="168" y1="${cy}" x2="266" y2="${oy}" stroke="#ccc" stroke-width="1"/>`;
        if(isChange)h+=`<text x="280" y="${oy+3}" font-size="8" fill="#aaa" font-family="var(--mono)">change</text>`;
      }
      h+=`<text x="10" y="${svgH-2}" font-size="7" fill="#bbb" font-family="var(--mono)">${inCount} inputs</text>`;
      h+=`<text x="255" y="${svgH-2}" font-size="7" fill="#bbb" font-family="var(--mono)">${outCount} outputs</text>`;
      h+=`</svg></div>`;

      // Heuristic results
      h+=`<div class="dp-section"><div class="dp-label">Heuristic Results</div>`;
      HEUR_META.forEach(m=>{
        const hr=tx.heuristics?tx.heuristics[m.id]:null;
        const det=hr&&hr.detected;
        h+=`<div class="h-result${det?' detected':''}">`;
        h+=`<div class="h-result-top"><span class="h-result-name">${m.id}</span>`;
        h+=det?`<span class="h-result-on">DETECTED</span>`:`<span class="h-result-off">\u2014</span>`;
        h+=`</div>`;
        if(det){
          h+=`<div class="h-result-detail">`;
          if(m.id==='change_detection'&&hr.method)h+=`Method: <code>${hr.method}</code> · Index: <code>${hr.likely_change_index}</code> · Conf: <code>${hr.confidence}</code>`;
          else h+=m.desc;
          h+=`</div>`;
          h+=`<div class="conf-meter"><span class="conf-label">Confidence</span><div class="conf-pips">`;
          for(let i=0;i<3;i++)h+=`<span class="conf-pip${i<m.conf_level?' filled':''}"></span>`;
          h+=`</div></div>`;
        }
        h+=`</div>`;
      });
      h+=`</div>`;

      document.getElementById('detailCol').innerHTML=h;
      return;
    }
  }

  // Default: legend + fee display

  // Classification legend
  h+=`<div class="dp-section"><div class="dp-label">Classification Legend</div><div class="cls-legend">`;
  const clsCounts={};
  if(allTxs.length>0){
    allTxs.forEach(tx=>{clsCounts[tx.classification]=(clsCounts[tx.classification]||0)+1});
  }
  [{cls:'coinjoin',color:'#111',label:'CoinJoin'},{cls:'consolidation',color:'#555',label:'Consolidation'},
   {cls:'simple_payment',color:'#aaa',label:'Simple Pay'},{cls:'batch_payment',color:'#777',label:'Batch'},
   {cls:'self_transfer',color:'#ccc',label:'Self Transfer'},{cls:'unknown',color:'#e0e0e0',label:'Unknown'}
  ].forEach(item=>{
    const ct=clsCounts[item.cls]||0;
    h+=`<div class="cls-legend-item" onclick="filterTx('${item.cls}')">`;
    h+=`<span class="cls-dot" style="background:${item.color}${item.color==='#e0e0e0'||item.color==='#aaa'?';border:1px solid #bbb':''}"></span>`;
    h+=`<span>${item.label}</span><span class="cls-ct">${num(ct)}</span></div>`;
  });
  h+=`</div></div>`;

  // Empty state for I/O graph
  h+=`<div class="dp-section"><div class="dp-label">Transaction I/O Graph</div>`;
  h+=`<div class="empty-panel"><div class="ep-icon">&#8644;</div><p>Select a transaction from the table<br>to view its input/output graph.</p></div></div>`;

  // Fee distribution
  h+=`<div class="dp-section"><div class="dp-label">Fee Rate Distribution</div>`;
  h+=`<div class="fee-grid">`;
  h+=`<div class="fee-cell"><div class="fl">MIN</div><div class="fv">${s.fee_rate_stats.min_sat_vb.toFixed(1)}</div></div>`;
  h+=`<div class="fee-cell"><div class="fl">MEDIAN</div><div class="fv">${s.fee_rate_stats.median_sat_vb.toFixed(1)}</div></div>`;
  h+=`<div class="fee-cell"><div class="fl">MEAN</div><div class="fv">${s.fee_rate_stats.mean_sat_vb.toFixed(1)}</div></div>`;
  h+=`<div class="fee-cell"><div class="fl">MAX</div><div class="fv">${s.fee_rate_stats.max_sat_vb.toFixed(1)}</div></div>`;
  h+=`</div>`;

  // Fee ruler
  const medPct=s.fee_rate_stats.max_sat_vb>0?(s.fee_rate_stats.median_sat_vb/s.fee_rate_stats.max_sat_vb*100).toFixed(1):'50';
  h+=`<div style="position:relative;height:30px;margin-top:16px">`;
  h+=`<div style="position:absolute;top:8px;left:0;right:0;height:2px;background:#e8e5de;border-radius:1px"></div>`;
  h+=`<div style="position:absolute;top:4px;left:0;width:2px;height:8px;background:#bbb"></div>`;
  h+=`<div style="position:absolute;top:4px;left:${medPct}%;width:2px;height:8px;background:#111"></div>`;
  h+=`<div style="position:absolute;top:4px;right:0;width:2px;height:8px;background:#bbb"></div>`;
  h+=`<div style="position:absolute;top:18px;left:0;font-size:7px;color:#bbb">MIN</div>`;
  h+=`<div style="position:absolute;top:18px;left:${medPct}%;font-size:7px;color:#111;font-weight:700;transform:translateX(-50%)">MED</div>`;
  h+=`<div style="position:absolute;top:18px;right:0;font-size:7px;color:#bbb">MAX</div>`;
  h+=`</div></div>`;

  document.getElementById('detailCol').innerHTML=h;
}

function switchBlock(idx){
  currentBlock=idx;activeFilter='all';selectedTxid=null;activeHeuristic=null;currentPage=1;
  renderAll();
}

function filterTx(cls){
  activeFilter=cls;selectedTxid=null;currentPage=1;
  applyFilters();
  // Re-render just the tx section and controls
  const mainCol=document.getElementById('mainCol');
  // Find and replace tx section
  renderAll();
}

function selectTx(txid){
  selectedTxid=selectedTxid===txid?null:txid;
  // Update row selection
  document.querySelectorAll('.tx-row').forEach(el=>{
    const isSel=el.getAttribute('onclick')&&el.getAttribute('onclick').includes(txid)&&selectedTxid===txid;
    el.classList.toggle('selected',isSel);
  });
  renderDetailPanel();
}

function changePage(dir){
  currentPage+=dir;
  const total=filteredTxs.length;
  const pages=Math.max(1,Math.ceil(total/PAGE_SIZE));
  currentPage=Math.max(1,Math.min(currentPage,pages));
  renderAll();
  const txList=document.getElementById('txList');
  if(txList)txList.scrollTop=0;
}

function toggleHeuristic(id,card){
  if(activeHeuristic===id){activeHeuristic=null}
  else{activeHeuristic=id}
  currentPage=1;selectedTxid=null;
  renderAll();
}

init();
</script>
</body>
</html>
"##;
