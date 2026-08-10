#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# CONFIG
# ============================================================

BASE_URL="https://genlabs.st/wp-content/uploads/"
OUTPUT_DIR="./genlabs-uploads"

# Network behaviour
WAIT_SECONDS=1
TIMEOUT=30
RETRIES=5
RETRY_WAIT=5

# Do not hammer the production server
RATE_LIMIT="2m"

# ============================================================
# ARGUMENTS
# ============================================================

URL="${1:-$BASE_URL}"
DEST="${2:-$OUTPUT_DIR}"

# Normalize URL
[[ "$URL" == */ ]] || URL="${URL}/"

# ============================================================
# COLORS
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[+]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# ============================================================
# CLEANUP
# ============================================================

cleanup() {
    echo
    warn "Interrupted."
    warn "Already downloaded files are preserved."
    exit 130
}

trap cleanup INT TERM

# ============================================================
# DEPENDENCY CHECK
# ============================================================

log "Checking dependencies..."

if ! command -v wget >/dev/null 2>&1; then
    error "wget is not installed."
    echo
    echo "Install it with:"
    echo "  sudo apt update"
    echo "  sudo apt install wget"
    exit 1
fi

if ! command -v du >/dev/null 2>&1; then
    error "du is not available."
    exit 1
fi

if ! command -v find >/dev/null 2>&1; then
    error "find is not available."
    exit 1
fi

# ============================================================
# PREPARE
# ============================================================

mkdir -p "$DEST"

DEST="$(realpath "$DEST")"

echo
log "Source : $URL"
log "Output : $DEST"
echo

# ============================================================
# CONNECTIVITY TEST
# ============================================================

log "Testing source..."

HTTP_CODE="$(
    curl -k -L \
        --silent \
        --output /dev/null \
        --write-out '%{http_code}' \
        --max-time "$TIMEOUT" \
        "$URL" 2>/dev/null || true
)"

if [[ "$HTTP_CODE" == "200" ]]; then
    log "Source directory is reachable."
else
    warn "Directory returned HTTP $HTTP_CODE."
    warn "Continuing anyway; wget may still be able to retrieve files."
fi

# ============================================================
# DOWNLOAD
# ============================================================

log "Starting recursive download..."
echo
echo "Press Ctrl+C to stop. Already downloaded files will remain."
echo

wget \
    --recursive \
    --no-parent \
    --no-host-directories \
    --cut-dirs=2 \
    --continue \
    --timestamping \
    --retry-on-http-error=429,500,502,503,504 \
    --tries="$RETRIES" \
    --waitretry="$RETRY_WAIT" \
    --timeout="$TIMEOUT" \
    --wait="$WAIT_SECONDS" \
    --limit-rate="$RATE_LIMIT" \
    --user-agent="Mozilla/5.0 (compatible; Genlabs-Backup/1.0)" \
    --directory-prefix="$DEST" \
    "$URL"

STATUS=$?

echo

if [[ "$STATUS" -ne 0 ]]; then
    warn "wget finished with exit code $STATUS."
    warn "Some files may have failed; run the script again to resume."
else
    log "Download completed."
fi

# ============================================================
# REPORT
# ============================================================

echo
log "Generating local inventory..."

FILE_COUNT="$(find "$DEST" -type f | wc -l)"
TOTAL_SIZE="$(du -sh "$DEST" | awk '{print $1}')"

echo
echo "=========================================="
echo " DOWNLOAD SUMMARY"
echo "=========================================="
echo "Source       : $URL"
echo "Destination  : $DEST"
echo "Files        : $FILE_COUNT"
echo "Total size   : $TOTAL_SIZE"
echo "=========================================="
echo

# ============================================================
# IMPORTANT FILE INVENTORY
# ============================================================

log "Looking for potentially sensitive files..."

SENSITIVE_LIST="$DEST/_sensitive-files.txt"

find "$DEST" -type f \
    \( \
        -iname "*.csv" \
        -o -iname "*.log" \
        -o -iname "*.sql" \
        -o -iname "*.sql.gz" \
        -o -iname "*.zip" \
        -o -iname "*.tar" \
        -o -iname "*.tar.gz" \
        -o -iname "*.bak" \
        -o -iname "*.old" \
        -o -iname "*.env" \
        -o -iname "*.json" \
    \) \
    -print | sort > "$SENSITIVE_LIST"

SENSITIVE_COUNT="$(wc -l < "$SENSITIVE_LIST")"

echo
warn "Potentially sensitive files found: $SENSITIVE_COUNT"
echo "Inventory:"
echo "  $SENSITIVE_LIST"

# ============================================================
# CSV SUMMARY
# ============================================================

CSV_LIST="$DEST/_csv-files.txt"

find "$DEST" -type f -iname "*.csv" -print | sort > "$CSV_LIST"

CSV_COUNT="$(wc -l < "$CSV_LIST")"

echo
log "CSV files: $CSV_COUNT"

if [[ "$CSV_COUNT" -gt 0 ]]; then
    echo
    echo "CSV files:"
    cat "$CSV_LIST"
fi

# ============================================================
# HASH INVENTORY
# ============================================================

log "Creating SHA256 inventory..."

(
    cd "$DEST"

    find . -type f \
        ! -name "_sha256.txt" \
        ! -name "_sensitive-files.txt" \
        ! -name "_csv-files.txt" \
        -print0 |
    sort -z |
    xargs -0 sha256sum
) > "$DEST/_sha256.txt"

log "SHA256 inventory: $DEST/_sha256.txt"

# ============================================================
# DONE
# ============================================================

echo
log "DONE."

echo
echo "Downloaded files:"
echo "  $DEST"

echo
echo "Useful commands:"
echo
echo "  Total size:"
echo "    du -sh \"$DEST\""
echo
echo "  File count:"
echo "    find \"$DEST\" -type f | wc -l"
echo
echo "  CSV files:"
echo "    cat \"$DEST/_csv-files.txt\""
echo
echo "  Sensitive-file inventory:"
echo "    cat \"$DEST/_sensitive-files.txt\""
echo
