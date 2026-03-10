#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# grader/grade_analysis.sh — JSON output validation for chain analysis
#
# For each block file fixture triple (blk/rev/xor):
#   1. Run ./cli.sh --block with 180s timeout
#   2. Validate per-block-file JSON schema and consistency
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

check_jq

REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

FIXTURES_DIR="$REPO_ROOT/fixtures"
XOR_FILE="$FIXTURES_DIR/xor.dat"

print_header "Chain Analysis — JSON Output Validation"

# Check xor.dat exists
if [[ ! -f "$XOR_FILE" ]]; then
  print_fail "xor.dat exists" "File not found: $XOR_FILE"
  print_summary
  exit 1
fi

# Discover block fixture pairs (blk*.dat / rev*.dat)
blk_files=()
for blk in "$FIXTURES_DIR"/blk*.dat; do
  [[ -f "$blk" ]] || continue
  blk_files+=("$blk")
done

if [[ ${#blk_files[@]} -eq 0 ]]; then
  print_fail "Block fixtures found" "No blk*.dat files in $FIXTURES_DIR (run setup.sh first)"
  print_summary
  exit 1
fi

print_pass "Block fixtures found (${#blk_files[@]} blk files)"

for blk_file in "${blk_files[@]}"; do
  blk_base=$(basename "$blk_file")
  blk_stem="${blk_base%.dat}"
  # Derive rev file: blk04330.dat -> rev04330.dat
  rev_base="${blk_base/blk/rev}"
  rev_file="$FIXTURES_DIR/$rev_base"

  print_section "Testing $blk_base"

  if [[ ! -f "$rev_file" ]]; then
    print_fail "Undo file exists" "Expected $rev_base but not found"
    continue
  fi

  # Clean out/ before running
  rm -rf out/

  # Run CLI
  run_cli --block "$blk_file" "$rev_file" "$XOR_FILE"

  if [[ $CLI_EXIT -ne 0 ]]; then
    print_fail "cli.sh exits 0" "Exit code: $CLI_EXIT, stderr: $CLI_STDERR"
    continue
  fi
  print_pass "cli.sh exits 0"

  # Check expected output file exists
  json_file="out/${blk_stem}.json"
  if [[ ! -f "$json_file" ]]; then
    print_fail "JSON output exists: ${blk_stem}.json" "File not found: $json_file"
    continue
  fi
  print_pass "JSON output exists: ${blk_stem}.json"

  json_content=$(cat "$json_file")
  json_base="${blk_stem}.json"

  # Check valid JSON
  if ! is_valid_json "$json_content"; then
    print_fail "$json_base is valid JSON"
    continue
  fi
  print_pass "$json_base is valid JSON"

  # -----------------------------------------------------------------------
  # Top-level field validation
  # -----------------------------------------------------------------------
  assert_field_equals_json "$json_content" ".ok" "true" "$json_base: ok == true" || true
  assert_field_equals "$json_content" ".mode" "chain_analysis" "$json_base: mode == chain_analysis" || true
  assert_field_exists "$json_content" ".file" "$json_base: file field exists" || true
  assert_field_type "$json_content" ".block_count" "number" "$json_base: block_count is number" || true
  assert_field_type "$json_content" ".blocks" "array" "$json_base: blocks is array" || true
  assert_field_exists "$json_content" ".analysis_summary" "$json_base: file-level analysis_summary exists" || true

  # Verify block_count == blocks array length
  block_count=$(echo "$json_content" | jq '.block_count' 2>/dev/null) || block_count="null"
  blocks_len=$(echo "$json_content" | jq '.blocks | length' 2>/dev/null) || blocks_len="null"
  if [[ "$block_count" != "null" && "$blocks_len" != "null" && "$block_count" == "$blocks_len" ]]; then
    print_pass "$json_base: block_count ($block_count) == blocks length"
  else
    print_fail "$json_base: block_count == blocks length" "block_count=$block_count, blocks length=$blocks_len"
  fi

  # -----------------------------------------------------------------------
  # Per-block validation
  # -----------------------------------------------------------------------
  if [[ "$blocks_len" == "null" || "$blocks_len" == "0" ]]; then
    print_fail "$json_base: blocks array is non-empty"
    continue
  fi

  for block_idx in $(seq 0 $((blocks_len - 1))); do
    block_prefix="$json_base: blocks[$block_idx]"
    block_json=$(echo "$json_content" | jq ".blocks[$block_idx]" 2>/dev/null)

    # Per-block field checks
    assert_field_matches "$block_json" ".block_hash" "$HEX64_REGEX" "$block_prefix: block_hash is hex64" || true
    assert_field_type "$block_json" ".tx_count" "number" "$block_prefix: tx_count is number" || true
    assert_field_exists "$block_json" ".analysis_summary" "$block_prefix: analysis_summary exists" || true

    # Validate transactions array only for the first block (perf: skip for others)
    if [[ "$block_idx" -eq 0 ]]; then
      assert_field_type "$block_json" ".transactions" "array" "$block_prefix: transactions is array" || true

      tx_array_len=$(echo "$block_json" | jq '.transactions | length' 2>/dev/null) || tx_array_len="null"
      if [[ "$tx_count" != "null" && "$tx_array_len" != "null" && "$tx_count" == "$tx_array_len" ]]; then
        print_pass "$block_prefix: transactions length ($tx_array_len) == tx_count ($tx_count)"
      else
        print_fail "$block_prefix: transactions length == tx_count" "tx_count=$tx_count, array length=$tx_array_len"
      fi
    fi

    # Check heuristics_applied has at least 5 distinct IDs
    heuristic_count=$(echo "$block_json" | jq '.analysis_summary.heuristics_applied | length' 2>/dev/null) || heuristic_count=0
    if [[ "$heuristic_count" -ge 5 ]]; then
      print_pass "$block_prefix: at least 5 heuristics applied ($heuristic_count)"
    else
      print_fail "$block_prefix: at least 5 heuristics applied" "Found $heuristic_count"
    fi

    # Check cioh and change_detection are in heuristics_applied
    has_cioh=$(echo "$block_json" | jq '.analysis_summary.heuristics_applied | index("cioh") != null' 2>/dev/null) || has_cioh="false"
    has_change=$(echo "$block_json" | jq '.analysis_summary.heuristics_applied | index("change_detection") != null' 2>/dev/null) || has_change="false"
    if [[ "$has_cioh" == "true" ]]; then
      print_pass "$block_prefix: cioh in heuristics_applied"
    else
      print_fail "$block_prefix: cioh in heuristics_applied"
    fi
    if [[ "$has_change" == "true" ]]; then
      print_pass "$block_prefix: change_detection in heuristics_applied"
    else
      print_fail "$block_prefix: change_detection in heuristics_applied"
    fi

    # Validate fee_rate_stats consistency: min <= median <= max, all non-negative
    fee_valid=$(echo "$block_json" | jq '
      .analysis_summary.fee_rate_stats |
      if . == null then false
      elif .min_sat_vb == null or .max_sat_vb == null or .median_sat_vb == null or .mean_sat_vb == null then false
      elif .min_sat_vb < 0 or .max_sat_vb < 0 or .median_sat_vb < 0 or .mean_sat_vb < 0 then false
      elif .min_sat_vb > .median_sat_vb then false
      elif .median_sat_vb > .max_sat_vb then false
      else true
      end
    ' 2>/dev/null) || fee_valid="false"
    if [[ "$fee_valid" == "true" ]]; then
      print_pass "$block_prefix: fee_rate_stats consistent (min <= median <= max, non-negative)"
    else
      print_fail "$block_prefix: fee_rate_stats consistency"
    fi

    # Check flagged_transactions is a non-negative integer <= tx_count
    reported_flagged=$(echo "$block_json" | jq '.analysis_summary.flagged_transactions' 2>/dev/null) || reported_flagged="null"
    if [[ "$reported_flagged" != "null" && "$tx_count" != "null" ]]; then
      flagged_valid=$(echo "$block_json" | jq --argjson tc "$tx_count" '
        .analysis_summary.flagged_transactions |
        if type != "number" then false
        elif . < 0 then false
        elif . > $tc then false
        else true end
      ' 2>/dev/null) || flagged_valid="false"
      if [[ "$flagged_valid" == "true" ]]; then
        print_pass "$block_prefix: flagged_transactions ($reported_flagged) is valid (0 <= n <= tx_count)"
      else
        print_fail "$block_prefix: flagged_transactions" "Expected 0 <= n <= $tx_count, got $reported_flagged"
      fi
    else
      print_fail "$block_prefix: flagged_transactions" "Field missing or null"
    fi
  done

  # -----------------------------------------------------------------------
  # File-level aggregation checks
  # -----------------------------------------------------------------------
  print_section "File-level aggregation for $blk_base"

  # total_transactions_analyzed == sum of per-block tx_counts
  sum_tx=$(echo "$json_content" | jq '[.blocks[].tx_count] | add' 2>/dev/null) || sum_tx="null"
  file_total=$(echo "$json_content" | jq '.analysis_summary.total_transactions_analyzed' 2>/dev/null) || file_total="null"
  if [[ "$sum_tx" != "null" && "$file_total" != "null" && "$sum_tx" == "$file_total" ]]; then
    print_pass "$json_base: file-level total_transactions_analyzed ($file_total) == sum of block tx_counts"
  else
    print_fail "$json_base: file-level total_transactions_analyzed" "Expected $sum_tx, got $file_total"
  fi

  # flagged_transactions == sum of per-block flagged
  sum_flagged=$(echo "$json_content" | jq '[.blocks[].analysis_summary.flagged_transactions] | add' 2>/dev/null) || sum_flagged="null"
  file_flagged=$(echo "$json_content" | jq '.analysis_summary.flagged_transactions' 2>/dev/null) || file_flagged="null"
  if [[ "$sum_flagged" != "null" && "$file_flagged" != "null" && "$sum_flagged" == "$file_flagged" ]]; then
    print_pass "$json_base: file-level flagged_transactions ($file_flagged) == sum of per-block flagged"
  else
    print_fail "$json_base: file-level flagged_transactions" "Expected $sum_flagged, got $file_flagged"
  fi

  # File-level fee_rate_stats consistency
  file_fee_valid=$(echo "$json_content" | jq '
    .analysis_summary.fee_rate_stats |
    if . == null then false
    elif .min_sat_vb == null or .max_sat_vb == null or .median_sat_vb == null or .mean_sat_vb == null then false
    elif .min_sat_vb < 0 or .max_sat_vb < 0 or .median_sat_vb < 0 or .mean_sat_vb < 0 then false
    elif .min_sat_vb > .median_sat_vb then false
    elif .median_sat_vb > .max_sat_vb then false
    else true
    end
  ' 2>/dev/null) || file_fee_valid="false"
  if [[ "$file_fee_valid" == "true" ]]; then
    print_pass "$json_base: file-level fee_rate_stats consistent"
  else
    print_fail "$json_base: file-level fee_rate_stats consistency"
  fi

  # File-level heuristics_applied has at least 5
  file_heuristic_count=$(echo "$json_content" | jq '.analysis_summary.heuristics_applied | length' 2>/dev/null) || file_heuristic_count=0
  if [[ "$file_heuristic_count" -ge 5 ]]; then
    print_pass "$json_base: file-level at least 5 heuristics applied ($file_heuristic_count)"
  else
    print_fail "$json_base: file-level at least 5 heuristics applied" "Found $file_heuristic_count"
  fi

done

# Restore committed outputs (reports, etc.) so subsequent graders find them
git checkout -- out/ 2>/dev/null || true

print_summary
[[ $FAIL_COUNT -eq 0 ]]
