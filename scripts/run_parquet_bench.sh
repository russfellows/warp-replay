#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_parquet_bench.sh  —  Run warp parquet benchmark against s3-ultra
#
# Reads existing DLRM Parquet objects already in s3-ultra (no upload, no
# cleanup).  The --full flag enables per-request op-log tracing so every
# GET (and the prepare-phase LIST + footer GETs) can be inspected in the
# resulting .csv.zst file.
#
# Usage:
#   bash run_parquet_bench.sh [duration] [--rg-sequential]
#
#   duration         Optional warp duration string, e.g. 1m0s, 5m0s (default: 1m0s)
#   --rg-sequential  Read rg-reads consecutive RGs per op (DLRM-style sequential
#                    access) instead of the default random-without-replacement.
#
# Op types in the trace:
#   LIST        — initial bucket listing (prepare phase)
#   GET-FOOTER  — per-object footer byte-range GET (prepare phase)
#   GET         — benchmark loop row-group byte-range GETs
#
# To inspect the op log after the run:
#   zstdcat warp-parquet-*.csv.zst | awk -F'\t' 'NR>1{print $3}' | sort | uniq -c
#   zstdcat warp-parquet-*.csv.zst | awk -F'\t' 'NR==1||$3!="GET"' | head -80
# ---------------------------------------------------------------------------

set -euo pipefail

DURATION="${1:-1m0s}"
RG_SEQUENTIAL=""
for arg in "$@"; do
    if [[ "$arg" == "--rg-sequential" ]]; then
        RG_SEQUENTIAL="--rg-sequential"
    fi
done

HOST="127.0.0.1:9000"
ACCESS_KEY="test"
SECRET_KEY="test"
BUCKET="mlp-flux"
RG_READS=4

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WARP="${SCRIPT_DIR}/warp"

if [[ ! -x "${WARP}" ]]; then
    echo "ERROR: warp binary not found at ${WARP}" >&2
    exit 1
fi

echo "================================================================"
echo " warp parquet benchmark — s3-ultra (${HOST})"
echo "  bucket:        ${BUCKET}"
echo "  rg-reads:      ${RG_READS}"
echo "  rg-sequential: ${RG_SEQUENTIAL:-false (random without replacement)}"
echo "  duration:      ${DURATION}"
echo "  list-existing: true  (no upload, no cleanup)"
echo "  --full:        enabled (per-request op-log tracing)"
echo "================================================================"
echo ""

"${WARP}" parquet \
    --host="${HOST}" \
    --access-key="${ACCESS_KEY}" \
    --secret-key="${SECRET_KEY}" \
    --tls=false \
    --bucket="${BUCKET}" \
    --rg-reads="${RG_READS}" \
    --list-existing=true \
    --keep-data=true \
    --duration="${DURATION}" \
    --full \
    ${RG_SEQUENTIAL}
