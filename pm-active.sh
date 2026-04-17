#!/usr/bin/env bash

# PM – Active Testing Module (Pentest Layer)
# Author: Prashant M.

set -euo pipefail

########################################
# CONFIG
########################################
THREADS=5
TIMEOUT=20
SQLMAP_LEVEL=1
SQLMAP_RISK=1

########################################
# INPUT
########################################
INPUT_FILE="${1:-}"

if [[ -z "$INPUT_FILE" || ! -f "$INPUT_FILE" ]]; then
  echo "Usage: $0 <alive.txt>"
  exit 1
fi

BASE_DIR=$(dirname "$INPUT_FILE")/../active
mkdir -p "$BASE_DIR"/{urls,sqlmap,nuclei,logs}

LOG="$BASE_DIR/logs/run.log"

log() {
  echo "[$(date '+%F %T')] $*" | tee -a "$LOG"
}

########################################
# DEPENDENCIES
########################################
ensure_tool() {
  if ! command -v "$1" &>/dev/null; then
    echo "[+] Installing $1..."
    sudo apt update -qq
    sudo apt install -y "$1"
  fi
}

for t in curl grep awk; do
  ensure_tool "$t"
done

########################################
# CHECK OPTIONAL TOOLS
########################################
HAS_SQLMAP=false
HAS_NUCLEI=false

command -v sqlmap &>/dev/null && HAS_SQLMAP=true
command -v nuclei &>/dev/null && HAS_NUCLEI=true

########################################
# STEP 1: COLLECT URLS
########################################
log "Collecting URLs..."

> "$BASE_DIR/urls/all.txt"

while IFS='|' read -r host ip; do
  url="https://$host"

  # Basic crawling (homepage links)
  html=$(curl -k -s --max-time $TIMEOUT "$url" || true)

  echo "$html" | grep -Eo 'href="[^"]+"' |
    cut -d'"' -f2 |
    grep -E "^/|^http" |
    sed "s|^/|$url/|" |
    tee -a "$BASE_DIR/urls/all.txt"

done < "$INPUT_FILE"

sort -u "$BASE_DIR/urls/all.txt" -o "$BASE_DIR/urls/all.txt"

log "URLs collected: $(wc -l < "$BASE_DIR/urls/all.txt")"

########################################
# STEP 2: FILTER PARAM URLS
########################################
log "Filtering parameterized URLs..."

grep '=' "$BASE_DIR/urls/all.txt" > "$BASE_DIR/urls/params.txt" || true

log "Param URLs: $(wc -l < "$BASE_DIR/urls/params.txt")"

########################################
# STEP 3: SQLMAP
########################################
if [[ "$HAS_SQLMAP" == true ]]; then
  log "Running SQLMap..."

  while read -r url; do
    log "SQLi testing: $url"

    sqlmap -u "$url" \
      --batch \
      --level="$SQLMAP_LEVEL" \
      --risk="$SQLMAP_RISK" \
      --random-agent \
      --threads="$THREADS" \
      --output-dir="$BASE_DIR/sqlmap" \
      >> "$LOG" 2>&1 || true

  done < "$BASE_DIR/urls/params.txt"
else
  log "SQLMap not installed, skipping..."
fi

########################################
# STEP 4: NUCLEI SCAN
########################################
if [[ "$HAS_NUCLEI" == true ]]; then
  log "Running Nuclei..."

  cut -d'|' -f1 "$INPUT_FILE" > "$BASE_DIR/hosts.txt"

  nuclei -l "$BASE_DIR/hosts.txt" \
    -o "$BASE_DIR/nuclei/results.txt" \
    -severity low,medium,high,critical \
    >> "$LOG" 2>&1 || true
else
  log "Nuclei not installed, skipping..."
fi

########################################
# DONE
########################################
log "Active testing completed"
echo "✔ Results in: $BASE_DIR"
