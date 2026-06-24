#!/usr/bin/env bash
set -euo pipefail

BIN="./build-windows-ucrt64/aestool.exe"
KEY="artifacts/windows/key256.bin"

mkdir -p artifacts/windows/benchmark

echo "===== SELFTEST ====="
$BIN selftest

echo
echo "===== KEYGEN / KEYINFO ====="
$BIN keygen --out "$KEY" --bits 256
$BIN keyinfo --key "$KEY"

echo
echo "===== CBC ROUNDTRIP ====="
$BIN encrypt --mode cbc --key "$KEY" --in samples/msg.txt --out artifacts/windows/demo_cbc.ct
$BIN decrypt --mode cbc --key "$KEY" --in artifacts/windows/demo_cbc.ct --meta artifacts/windows/demo_cbc.ct.json --out artifacts/windows/demo_cbc.dec.txt
diff -u samples/msg.txt artifacts/windows/demo_cbc.dec.txt
echo "[OK] CBC roundtrip"

echo
echo "===== CTR ROUNDTRIP ====="
rm -f artifacts/windows/nonce_registry.json
$BIN encrypt --mode ctr --key "$KEY" --in samples/msg.txt --out artifacts/windows/demo_ctr.ct
$BIN decrypt --mode ctr --key "$KEY" --in artifacts/windows/demo_ctr.ct --meta artifacts/windows/demo_ctr.ct.json --out artifacts/windows/demo_ctr.dec.txt
diff -u samples/msg.txt artifacts/windows/demo_ctr.dec.txt
echo "[OK] CTR roundtrip"

echo
echo "===== GCM ROUNDTRIP ====="
$BIN encrypt --mode gcm --key "$KEY" --in samples/msg.txt --out artifacts/windows/demo_gcm.ct --aad-text "student=TranNgocNhat;lab=1"
$BIN decrypt --mode gcm --key "$KEY" --in artifacts/windows/demo_gcm.ct --meta artifacts/windows/demo_gcm.ct.json --out artifacts/windows/demo_gcm.dec.txt
diff -u samples/msg.txt artifacts/windows/demo_gcm.dec.txt
echo "[OK] GCM roundtrip"

echo
echo "===== GCM TAMPER TEST ====="
cp artifacts/windows/demo_gcm.ct artifacts/windows/demo_gcm_tampered.ct
python3 - <<'PY'
from pathlib import Path
p = Path("artifacts/windows/demo_gcm_tampered.ct")
data = bytearray(p.read_bytes())
data[0] ^= 0x01
p.write_bytes(data)
print("[OK] Tampered demo_gcm_tampered.ct")
PY

set +e
$BIN decrypt --mode gcm --key "$KEY" --in artifacts/windows/demo_gcm_tampered.ct --meta artifacts/windows/demo_gcm.ct.json --out artifacts/windows/demo_gcm_tampered.dec.txt
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] GCM tamper test unexpectedly succeeded"
  exit 1
fi
echo "[OK] GCM tamper test failed closed"

echo
echo "===== ECB MISUSE TEST ====="
python3 - <<'PY'
from pathlib import Path
Path("samples/demo_large_20k.txt").write_bytes(b"A" * 20000)
print("[OK] Created samples/demo_large_20k.txt")
PY

set +e
$BIN encrypt --mode ecb --key "$KEY" --in samples/demo_large_20k.txt --out artifacts/windows/demo_large_ecb.ct
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] ECB large-file misuse test unexpectedly succeeded"
  exit 1
fi
echo "[OK] ECB large-file misuse test rejected"

echo
echo "===== NONCE REUSE TEST ====="
rm -f artifacts/windows/nonce_registry.json
$BIN encrypt --mode ctr --key "$KEY" --in samples/msg.txt --out artifacts/windows/demo_reuse_ctr_1.ct --iv-hex 33333333333333333333333333333333

set +e
$BIN encrypt --mode ctr --key "$KEY" --in samples/msg.txt --out artifacts/windows/demo_reuse_ctr_2.ct --iv-hex 33333333333333333333333333333333
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] CTR nonce reuse test unexpectedly succeeded"
  exit 1
fi
echo "[OK] CTR nonce reuse rejected"

echo
echo "===== BENCH QUICK CTR ====="
$BIN bench --mode ctr --key "$KEY" --out artifacts/windows/benchmark/demo_bench_ctr_windows.csv

echo
echo "[OK] Windows demo completed successfully."
