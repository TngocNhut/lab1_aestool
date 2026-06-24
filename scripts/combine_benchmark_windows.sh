#!/usr/bin/env bash
set -euo pipefail

OUT="artifacts/windows/benchmark/bench_all_windows.csv"

echo "os,mode,size_bytes,iterations,total_ms,avg_ms,throughput_mib_s" > "$OUT"

for f in artifacts/windows/benchmark/bench_*_windows.csv; do
  mode="$(basename "$f" | sed -E 's/bench_([a-z]+)_windows\.csv/\1/')"
  tail -n +2 "$f" | awk -F',' -v os="windows" -v mode="$mode" 'BEGIN{OFS=","} {print os,$0}'
done >> "$OUT"

echo "[OK] Combined Windows benchmark: $OUT"
