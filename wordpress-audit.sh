#!/usr/bin/env bash

set -euo pipefail

########################################
# CONFIG
########################################

DOMAIN=""
ENABLE_PORT_SCAN=false
ENABLE_NUCLEI=true

THREADS=20
WORDLIST="/usr/share/wordlists/subdomains.txt"

# WPScan API token can be supplied through environment:
# export WPSCAN_API_TOKEN="..."
WPSCAN_API_TOKEN="${WPSCAN_API_TOKEN:-}"

# Do not crawl huge amounts of content.
MAX_BODY_SIZE="5M"

########################################
# ARG PARSE
########################################

usage() {
    cat <<EOF

Usage:
  $0 <domain> [options]

Example:
  $0 genlabs.st

Options:
  --ports        Run nmap top-1000 port scan
  --no-nuclei    Disable nuclei
  --wordlist     Subdomain wordlist

Examples:
  $0 genlabs.st
  $0 genlabs.st --ports
  $0 genlabs.st --no-nuclei
  $0 genlabs.st --wordlist /path/to/wordlist

EOF
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --ports)
            ENABLE_PORT_SCAN=true
            shift
            ;;

        --no-nuclei)
            ENABLE_NUCLEI=false
            shift
            ;;

        --wordlist)
            [[ $# -ge 2 ]] || {
                echo "Missing value for --wordlist"
                exit 1
            }

            WORDLIST="$2"
            shift 2
            ;;

        -h|--help)
            usage
            exit 0
            ;;

        -*)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;

        *)
            if [[ -z "$DOMAIN" ]]; then
                DOMAIN="$1"
            else
                echo "Unexpected argument: $1"
                exit 1
            fi

            shift
            ;;
    esac
done

[[ -n "$DOMAIN" ]] || {
    usage
    exit 1
}

# Normalize input.
DOMAIN="${DOMAIN#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"

########################################
# PATHS
########################################

TS=$(date +"%Y%m%d-%H%M%S")

BASE="recon/${DOMAIN}-${TS}"

SUB="$BASE/subdomains"
HTTP="$BASE/http"
PORTS="$BASE/ports"
META="$BASE/meta"
VULN="$BASE/vulns"
WP="$BASE/wordpress"

LOG="$BASE/run.log"
JSON="$BASE/output.json"

mkdir -p \
    "$SUB" \
    "$HTTP" \
    "$PORTS" \
    "$META" \
    "$VULN" \
    "$WP"

########################################
# LOGGING
########################################

log() {
    echo "[+] $*" | tee -a "$LOG"
}

warn() {
    echo "[!] $*" | tee -a "$LOG"
}

fail() {
    echo "[X] $*" | tee -a "$LOG"
}

########################################
# DEPENDENCY CHECK
########################################

log "Checking dependencies..."

REQUIRED_COMMANDS=(
    curl
    jq
    dig
    whois
    sed
    grep
    awk
    sort
    tr
)

for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Missing dependency: $cmd"
        exit 1
    fi
done

########################################
# TARGET URL
########################################

TARGET="https://${DOMAIN}"

log "Target: $TARGET"
log "Output: $BASE"

########################################
# CT ENUMERATION
########################################

log "Certificate Transparency enumeration..."

CRT_JSON="$SUB/crt.json"

if curl -fsSL \
    --max-time 30 \
    "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
    -o "$CRT_JSON"; then

    if jq empty "$CRT_JSON" >/dev/null 2>&1; then

        jq -r '.[].name_value' "$CRT_JSON" |
            tr '\r' '\n' |
            sed 's/\*\.//g' |
            grep -E "^[A-Za-z0-9.-]+$" |
            grep -E "(^|\.)${DOMAIN//./\\.}$" |
            sort -u > "$SUB/all.txt"

    else
        warn "crt.sh returned invalid JSON"
        : > "$SUB/all.txt"
    fi

else
    warn "Certificate Transparency lookup failed"
    : > "$SUB/all.txt"
fi

########################################
# BRUTE SUBDOMAINS
########################################

log "Subdomain bruteforce..."

if [[ -f "$WORDLIST" ]]; then

    while IFS= read -r word; do

        [[ -z "$word" ]] && continue
        [[ "$word" == \#* ]] && continue

        if host "${word}.${DOMAIN}" >/dev/null 2>&1; then
            echo "${word}.${DOMAIN}" >> "$SUB/all.txt"
        fi

    done < "$WORDLIST"

else
    warn "Wordlist not found: $WORDLIST"
fi

########################################
# FINALIZE SUBDOMAINS
########################################

echo "$DOMAIN" >> "$SUB/all.txt"

sed '/^[[:space:]]*$/d' "$SUB/all.txt" |
    sort -u > "$SUB/all.tmp"

mv "$SUB/all.tmp" "$SUB/all.txt"

log "Total discovered hosts: $(wc -l < "$SUB/all.txt")"

########################################
# DNS RESOLUTION
########################################

log "Resolving hosts..."

: > "$SUB/alive.txt"

while IFS= read -r host; do

    ip=$(dig +short "$host" A | grep -E '^[0-9.]+$' | head -n1 || true)

    if [[ -n "$ip" ]]; then
        echo "$host|$ip" >> "$SUB/alive.txt"
    fi

done < "$SUB/all.txt"

sort -u "$SUB/alive.txt" -o "$SUB/alive.txt"

log "Alive hosts: $(wc -l < "$SUB/alive.txt")"

########################################
# IP COLLECTION
########################################

cut -d'|' -f2 "$SUB/alive.txt" |
    sort -u > "$META/ips.txt"

########################################
# REVERSE DNS
########################################

log "Reverse DNS..."

: > "$META/reverse.txt"

while IFS= read -r ip; do

    result=$(dig -x "$ip" +short 2>/dev/null || true)

    if [[ -n "$result" ]]; then
        echo "$ip => $result" >> "$META/reverse.txt"
    fi

done < "$META/ips.txt"

########################################
# WHOIS / ASN
########################################

log "ASN / ownership information..."

: > "$META/asn.txt"

while IFS= read -r ip; do

    whois "$ip" 2>/dev/null |
        grep -Ei \
            'origin|originas|orgname|org-name|netname|descr|country' \
        >> "$META/asn.txt" || true

done < "$META/ips.txt"

########################################
# HTTP PROBING
########################################

log "HTTP probing..."

: > "$META/panels.txt"
: > "$META/http.txt"

while IFS='|' read -r host ip; do

    safe_host=$(echo "$host" | tr -cd '[:alnum:]._-')

    body_file="$HTTP/${safe_host}.body"
    header_file="$HTTP/${safe_host}.headers"

    log "HTTP: $host"

    curl \
        -k \
        -sS \
        --max-time 15 \
        --max-filesize "$MAX_BODY_SIZE" \
        -A "Mozilla/5.0 (compatible; Genlabs-Security-Audit/1.0)" \
        -D "$header_file" \
        -o "$body_file" \
        "https://${host}/" \
        2>>"$LOG" || true

    if [[ -f "$header_file" ]]; then

        status=$(awk 'NR==1 {print $2}' "$header_file" 2>/dev/null || true)

        echo "$host|$status|$ip" >> "$META/http.txt"

    fi

    if [[ -f "$body_file" ]]; then

        if grep -qiE \
            'wp-content|wp-includes|wp-json|woocommerce|elementor' \
            "$body_file"; then

            echo "$host => probable WordPress" >> "$META/panels.txt"

        fi

        if grep -qiE \
            '<title>.*(login|admin|dashboard|sign in).*<\/title>|wp-login|wp-admin' \
            "$body_file"; then

            echo "$host => possible admin/login panel" \
                >> "$META/panels.txt"
        fi

    fi

done < "$SUB/alive.txt"

########################################
# WORDPRESS DETECTION
########################################

log "Checking WordPress..."

WP_DETECTED=false

if curl \
    -k \
    -fsSL \
    --max-time 15 \
    -o "$WP/home.html" \
    "$TARGET/"; then

    if grep -qiE \
        'wp-content|wp-includes|wp-json|woocommerce' \
        "$WP/home.html"; then

        WP_DETECTED=true
        log "WordPress detected."

    else
        warn "WordPress could not be confirmed from homepage."

    fi

else
    warn "Unable to fetch WordPress homepage."
fi

########################################
# WORDPRESS CORE VERSION
########################################

log "Checking WordPress core version..."

CORE_VERSION=""

# Try generator metadata first.
CORE_VERSION=$(
    grep -oiE \
        '<meta[^>]+name=["'"'"']generator["'"'"'][^>]+content=["'"'"']WordPress [0-9.]+' \
        "$WP/home.html" 2>/dev/null |
    grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' |
    head -n1 || true
)

echo "generator_version=${CORE_VERSION:-unknown}" \
    > "$WP/core-version.txt"

########################################
# WORDPRESS STANDARD ENDPOINTS
########################################

log "Checking WordPress endpoints..."

: > "$WP/endpoints.txt"

check_endpoint() {

    local name="$1"
    local path="$2"

    local status
    status=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{http_code}" \
            --max-time 10 \
            "${TARGET}${path}" \
            2>/dev/null || echo "000"
    )

    echo "$name|$path|$status" >> "$WP/endpoints.txt"

    log "WP endpoint: $path => $status"
}

check_endpoint "wp-login" "/wp-login.php"
check_endpoint "wp-admin" "/wp-admin/"
check_endpoint "wp-json" "/wp-json/"
check_endpoint "xmlrpc" "/xmlrpc.php"
check_endpoint "wp-cron" "/wp-cron.php"

########################################
# SENSITIVE FILE CHECK
########################################

log "Checking common sensitive files..."

: > "$WP/sensitive-files.txt"

check_file() {

    local path="$1"

    local status
    local size

    status=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{http_code}" \
            --max-time 10 \
            "${TARGET}${path}" \
            2>/dev/null || echo "000"
    )

    size=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{size_download}" \
            --max-time 10 \
            "${TARGET}${path}" \
            2>/dev/null || echo "0"
    )

    echo "$path|$status|$size" >> "$WP/sensitive-files.txt"

    if [[ "$status" == "200" ]]; then
        warn "POTENTIALLY EXPOSED: $path => HTTP $status ($size bytes)"
    fi
}

check_file "/wp-config.php"
check_file "/wp-config.php.bak"
check_file "/wp-config.php.old"
check_file "/wp-config.php.save"
check_file "/.env"
check_file "/.git/HEAD"
check_file "/debug.log"
check_file "/wp-content/debug.log"
check_file "/wp-content/uploads/debug.log"
check_file "/readme.html"
check_file "/license.txt"

########################################
# UPLOADS DIRECTORY CHECK
########################################

log "Checking /wp-content/uploads/ ..."

UPLOADS="$WP/uploads"

mkdir -p "$UPLOADS"

UPLOADS_STATUS=$(
    curl \
        -k \
        -sS \
        -o "$UPLOADS/index.html" \
        -w "%{http_code}" \
        --max-time 15 \
        "${TARGET}/wp-content/uploads/" \
        2>/dev/null || echo "000"
)

echo "directory|$UPLOADS_STATUS" > "$UPLOADS/status.txt"

log "Uploads directory => HTTP $UPLOADS_STATUS"

########################################
# DIRECTORY LISTING DETECTION
########################################

if [[ "$UPLOADS_STATUS" == "200" ]]; then

    if grep -qiE \
        'Index of /wp-content/uploads|Directory listing|Parent Directory' \
        "$UPLOADS/index.html"; then

        warn "DIRECTORY LISTING ENABLED: /wp-content/uploads/"
        echo "DIRECTORY_LISTING=true" > "$UPLOADS/finding.txt"

    else

        echo "DIRECTORY_LISTING=false" > "$UPLOADS/finding.txt"
        log "Uploads directory does not appear to expose an index listing."

    fi
fi

########################################
# UPLOADS FILE TESTS
########################################

log "Checking common dangerous/static file types in uploads..."

: > "$UPLOADS/files.txt"

UPLOAD_PATHS=(
    "test.php"
    "index.php"
    "shell.php"
    "cmd.php"
    "test.phtml"
    "test.phar"
    "backup.zip"
    "database.sql"
    "debug.log"
)

for filename in "${UPLOAD_PATHS[@]}"; do

    status=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{http_code}" \
            --max-time 10 \
            "${TARGET}/wp-content/uploads/${filename}" \
            2>/dev/null || echo "000"
    )

    echo "$filename|$status" >> "$UPLOADS/files.txt"

done

########################################
# FIND PHP REFERENCES IN UPLOADS HTML
########################################

if [[ -f "$UPLOADS/index.html" ]]; then

    grep -oiE \
        'href=["'\''][^"'\'']+\.(php|phtml|phar)(\?[^"'\'']*)?' \
        "$UPLOADS/index.html" \
        2>/dev/null |
        sort -u > "$UPLOADS/php-references.txt" || true

fi

########################################
# PHP FILE CANDIDATE CHECK
########################################

log "Checking common WordPress upload PHP locations..."

: > "$UPLOADS/php-checks.txt"

PHP_NAMES=(
    "index.php"
    "test.php"
    "upload.php"
    "image.php"
    "ajax.php"
    "shell.php"
)

for phpfile in "${PHP_NAMES[@]}"; do

    result=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{http_code}|%{content_type}" \
            --max-time 10 \
            "${TARGET}/wp-content/uploads/${phpfile}" \
            2>/dev/null || echo "000|unknown"
    )

    echo "$phpfile|$result" >> "$UPLOADS/php-checks.txt"

done

########################################
# UPLOADS COMMON SENSITIVE EXTENSIONS
########################################

log "Checking publicly accessible upload artifacts..."

: > "$UPLOADS/artifact-checks.txt"

ARTIFACTS=(
    ".zip"
    ".tar.gz"
    ".sql"
    ".sql.gz"
    ".bak"
    ".old"
    ".log"
    ".env"
    ".json"
    ".csv"
    ".xml"
)

for ext in "${ARTIFACTS[@]}"; do

    echo "Extension ${ext}: requires filename discovery; no wildcard request performed." \
        >> "$UPLOADS/artifact-checks.txt"

done

########################################
# SECURITY HEADERS
########################################

log "Checking security headers..."

curl \
    -k \
    -sS \
    -D "$WP/security-headers.txt" \
    -o /dev/null \
    --max-time 15 \
    "$TARGET/" \
    2>/dev/null || true

{
    echo "Security header assessment"
    echo "=========================="

    for header in \
        "strict-transport-security" \
        "content-security-policy" \
        "x-content-type-options" \
        "x-frame-options" \
        "referrer-policy" \
        "permissions-policy"; do

        if grep -qi "^${header}:" "$WP/security-headers.txt"; then
            echo "[PRESENT] $header"
        else
            echo "[MISSING] $header"
        fi

    done

} > "$WP/security-header-summary.txt"

########################################
# HTTP METHODS
########################################

log "Checking HTTP methods..."

curl \
    -k \
    -sS \
    -i \
    -X OPTIONS \
    --max-time 10 \
    "$TARGET/" \
    > "$WP/options.txt" \
    2>/dev/null || true

########################################
# WORDPRESS REST API INFORMATION
########################################

log "Checking REST API exposure..."

curl \
    -k \
    -fsSL \
    --max-time 15 \
    "${TARGET}/wp-json/" \
    -o "$WP/wp-json.json" \
    2>/dev/null || true

if [[ -s "$WP/wp-json.json" ]]; then

    if jq empty "$WP/wp-json.json" >/dev/null 2>&1; then

        jq '{
            name: .name,
            description: .description,
            url: .url,
            home: .home,
            namespaces: .namespaces
        }' \
        "$WP/wp-json.json" \
        > "$WP/wp-json-summary.json" \
        2>/dev/null || true

    fi
fi

########################################
# XML-RPC CHECK
########################################

log "Checking XML-RPC..."

XMLRPC_HEADERS=$(
    curl \
        -k \
        -sS \
        -D - \
        -o /dev/null \
        --max-time 10 \
        "${TARGET}/xmlrpc.php" \
        2>/dev/null || true
)

printf '%s\n' "$XMLRPC_HEADERS" > "$WP/xmlrpc.txt"

########################################
# WPSCAN
########################################

if [[ "$ENABLE_WPSCAN" == true ]]; then

    if command -v wpscan >/dev/null 2>&1; then

        log "Running WPScan..."

        WPSCAN_ARGS=(
            "--url" "$TARGET"
            "--enumerate" "ap,at,cb,dbe,u"
            "--plugins-detection" "mixed"
            "--format" "cli-no-color"
            "--output" "$VULN/wpscan.txt"
        )

        if [[ -n "$WPSCAN_API_TOKEN" ]]; then

            WPSCAN_ARGS+=(
                "--api-token"
                "$WPSCAN_API_TOKEN"
            )

        else

            warn "WPSCAN_API_TOKEN not set. Vulnerability database results may be limited."

        fi

        wpscan "${WPSCAN_ARGS[@]}" \
            >> "$LOG" 2>&1 || true

    else

        warn "WPScan not installed; skipping."

    fi
fi

########################################
# NUCLEI
########################################

if [[ "$ENABLE_NUCLEI" == true ]]; then

    if command -v nuclei >/dev/null 2>&1; then

        log "Running Nuclei WordPress-focused scan..."

        cut -d'|' -f1 "$SUB/alive.txt" > "$SUB/hosts.txt"

        nuclei \
            -l "$SUB/hosts.txt" \
            -tags wordpress,wp-plugin,wp-theme \
            -severity info,low,medium,high,critical \
            -rate-limit "$THREADS" \
            -o "$VULN/nuclei-wordpress.txt" \
            -silent \
            >> "$LOG" 2>&1 || true

    else

        warn "Nuclei not installed; skipping."

    fi
fi

########################################
# OPTIONAL PORT SCAN
########################################

if [[ "$ENABLE_PORT_SCAN" == true ]]; then

    if command -v nmap >/dev/null 2>&1; then

        log "Running nmap top-1000 scan..."

        while IFS='|' read -r host ip; do

            safe_host=$(echo "$host" | tr -cd '[:alnum:]._-')

            nmap \
                -Pn \
                --top-ports 1000 \
                --open \
                "$ip" \
                -oN "$PORTS/${safe_host}.txt" \
                >> "$LOG" 2>&1 || true

        done < "$SUB/alive.txt"

    else

        warn "nmap not installed; skipping."

    fi
fi

########################################
# WORDPRESS PLUGIN FILE DISCOVERY
########################################

log "Checking common WordPress plugin/theme exposure..."

: > "$WP/plugin-files.txt"

COMMON_WP_FILES=(
    "/wp-content/plugins/"
    "/wp-content/themes/"
    "/wp-content/uploads/"
    "/wp-content/debug.log"
    "/wp-includes/"
    "/wp-admin/"
)

for path in "${COMMON_WP_FILES[@]}"; do

    status=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{http_code}" \
            --max-time 10 \
            "${TARGET}${path}" \
            2>/dev/null || echo "000"
    )

    echo "$path|$status" >> "$WP/plugin-files.txt"

done

########################################
# WP USER ENUMERATION CHECK
########################################

log "Checking REST user endpoint..."

USER_STATUS=$(
    curl \
        -k \
        -sS \
        -o "$WP/users.json" \
        -w "%{http_code}" \
        --max-time 10 \
        "${TARGET}/wp-json/wp/v2/users?per_page=5" \
        2>/dev/null || echo "000"
)

echo "$USER_STATUS" > "$WP/user-endpoint-status.txt"

if [[ "$USER_STATUS" == "200" ]]; then

    warn "REST API user endpoint returned HTTP 200."
    echo "USER_ENDPOINT_ACCESSIBLE=true" \
        > "$WP/user-endpoint-finding.txt"

else

    echo "USER_ENDPOINT_ACCESSIBLE=false" \
        > "$WP/user-endpoint-finding.txt"

fi

########################################
# JSON OUTPUT
########################################

log "Generating JSON..."

SUBS_JSON=$(
    jq -R -s '
        split("\n")
        | map(select(length > 0))
    ' "$SUB/all.txt"
)

IPS_JSON=$(
    jq -R -s '
        split("\n")
        | map(select(length > 0))
    ' "$META/ips.txt"
)

UPLOAD_STATUS_JSON=$(
    jq -R -s '
        split("\n")
        | map(select(length > 0))
    ' "$UPLOADS/status.txt"
)

WP_DETECTED_JSON="false"

if [[ "$WP_DETECTED" == true ]]; then
    WP_DETECTED_JSON="true"
fi

jq -n \
    --arg domain "$DOMAIN" \
    --arg target "$TARGET" \
    --arg timestamp "$TS" \
    --argjson wordpress "$WP_DETECTED_JSON" \
    --argjson subdomains "$SUBS_JSON" \
    --argjson ips "$IPS_JSON" \
    --argjson uploads "$UPLOAD_STATUS_JSON" \
    '{
        domain: $domain,
        target: $target,
        timestamp: $timestamp,

        wordpress_detected: $wordpress,

        subdomains: $subdomains,
        ips: $ips,

        wordpress_checks: {
            uploads: $uploads
        }
    }' > "$JSON"

########################################
# SIMPLE FINDINGS SUMMARY
########################################

SUMMARY="$BASE/security-summary.txt"

{
    echo "========================================"
    echo " GENLABS WORDPRESS SECURITY AUDIT"
    echo "========================================"
    echo
    echo "Target: $TARGET"
    echo "Date:   $(date)"
    echo
    echo "========================================"
    echo " WORDPRESS"
    echo "========================================"
    echo

    if [[ "$WP_DETECTED" == true ]]; then
        echo "[+] WordPress detected"
    else
        echo "[?] WordPress not confirmed"
    fi

    echo
    echo "========================================"
    echo " UPLOADS"
    echo "========================================"
    echo

    if [[ "$UPLOADS_STATUS" == "200" ]]; then
        echo "[!] /wp-content/uploads/ returned HTTP 200"
        echo "    Review uploads/index.html"
    elif [[ "$UPLOADS_STATUS" == "403" ]]; then
        echo "[+] /wp-content/uploads/ returned HTTP 403"
    elif [[ "$UPLOADS_STATUS" == "404" ]]; then
        echo "[+] /wp-content/uploads/ returned HTTP 404"
    else
        echo "[?] /wp-content/uploads/ returned HTTP $UPLOADS_STATUS"
    fi

    echo
    echo "========================================"
    echo " SENSITIVE FILES"
    echo "========================================"
    echo

    if grep -qE '\|200\|' "$WP/sensitive-files.txt"; then
        echo "[!] Possible publicly accessible sensitive file(s):"
        grep -E '\|200\|' "$WP/sensitive-files.txt"
    else
        echo "[+] No tested sensitive file returned HTTP 200"
    fi

    echo
    echo "========================================"
    echo " UPLOAD PHP CHECK"
    echo "========================================"
    echo

    if grep -Eq '\|(200|206)\|' "$UPLOADS/php-checks.txt"; then
        echo "[!] PHP candidate returned successful HTTP response:"
        grep -E '\|(200|206)\|' "$UPLOADS/php-checks.txt"
    else
        echo "[+] No tested PHP candidate returned HTTP 200/206"
    fi

    echo
    echo "========================================"
    echo " USER ENUMERATION"
    echo "========================================"
    echo

    if [[ "$USER_STATUS" == "200" ]]; then
        echo "[!] REST user endpoint returned HTTP 200"
    else
        echo "[+] REST user endpoint did not return HTTP 200"
    fi

    echo
    echo "========================================"
    echo " SCANNERS"
    echo "========================================"
    echo

    [[ -f "$VULN/wpscan.txt" ]] &&
        echo "[+] WPScan completed"

    [[ -f "$VULN/nuclei-wordpress.txt" ]] &&
        echo "[+] Nuclei completed"

    echo
    echo "========================================"
    echo " OUTPUT"
    echo "========================================"
    echo
    echo "$BASE"
    echo

} > "$SUMMARY"

########################################
# DIFF SCAN
########################################

PREV=$(
    find "recon" \
        -maxdepth 1 \
        -type d \
        -name "${DOMAIN}-*" \
        -printf '%T@ %p\n' \
        2>/dev/null |
    sort -nr |
    awk 'NR==2 {$1=""; sub(/^ /,""); print}'
)

if [[ -n "${PREV:-}" && -f "$PREV/subdomains/all.txt" ]]; then

    log "Comparing with previous scan..."

    diff \
        "$PREV/subdomains/all.txt" \
        "$SUB/all.txt" \
        > "$BASE/diff.txt" || true

fi

########################################
# FINAL OUTPUT
########################################

log "========================================"
log "AUDIT COMPLETE"
log "========================================"

echo
echo "Target:"
echo "  $TARGET"
echo
echo "Results:"
echo "  $BASE"
echo
echo "Security summary:"
echo "  $SUMMARY"
echo
echo "WPScan:"
echo "  $VULN/wpscan.txt"
echo
echo "Nuclei:"
echo "  $VULN/nuclei-wordpress.txt"
echo
echo "Uploads:"
echo "  $UPLOADS/"
echo
echo "JSON:"
echo "  $JSON"
echo
echo "🔥 WordPress security audit completed."
