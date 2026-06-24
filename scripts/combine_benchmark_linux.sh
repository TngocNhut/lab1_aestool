#!/usr/bin/env bash
set -euo pipefail

OUT="artifacts/linux/benchmark/bench_all_linux.csv"

echo "os,mode,size_bytes,iterations,total_ms,avg_ms,throughput_mib_s" > "$OUT"

for f in artifacts/linux/benchmark/bench_*_linux.csv; do
  mode="$(basename "$f" | sed -E 's/bench_([a-z]+)_linux\.csv/\1/')"
  tail -n +2 "$f" | awk -F',' -v os="linux" -v mode="$mode" 'BEGIN{OFS=","} {print os,$0}'
done >> "$OUT"

echo "[OK] Combined Linux benchmark: $OUT"
