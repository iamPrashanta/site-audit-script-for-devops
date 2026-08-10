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

MAX_BODY_SIZE="5M"
CURL_TIMEOUT=15

# Optional manually-created PHP canary.
#
# Example:
#   ./wordpress-audit.sh genlabs.st \
#       --php-canary-url /wp-content/uploads/security-canary.php
#
# IMPORTANT:
# The scanner NEVER uploads this file.
# You deliberately place the harmless canary yourself.
PHP_CANARY_URL=""

########################################
# USAGE
########################################

usage() {
    cat <<EOF

WordPress Security Audit

Usage:
  $0 <domain> [options]

Options:

  --ports
      Run nmap top-1000 TCP port scan.

  --no-nuclei
      Disable Nuclei.

  --wordlist <file>
      Subdomain wordlist.

  --php-canary-url <path>
      Test a manually-created harmless PHP canary.

      Example:
        --php-canary-url /wp-content/uploads/security-canary.php

      The scanner DOES NOT upload the file.

Examples:

  $0 genlabs.st

  $0 genlabs.st --ports

  $0 genlabs.st --no-nuclei

  $0 genlabs.st \
      --php-canary-url /wp-content/uploads/security-canary.php

EOF
}

########################################
# ARGUMENT PARSING
########################################

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

        --php-canary-url)

            [[ $# -ge 2 ]] || {
                echo "Missing value for --php-canary-url"
                exit 1
            }

            PHP_CANARY_URL="$2"
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

########################################
# NORMALIZE DOMAIN
########################################

DOMAIN="${DOMAIN#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"

TARGET="https://${DOMAIN}"

########################################
# OUTPUT
########################################

TS=$(date +"%Y%m%d-%H%M%S")

BASE="recon/${DOMAIN}-${TS}"

SUB="$BASE/subdomains"
HTTP="$BASE/http"
PORTS="$BASE/ports"
META="$BASE/meta"
VULN="$BASE/vulns"
WP="$BASE/wordpress"
UPLOADS="$WP/uploads"
SECURITY="$BASE/security"

LOG="$BASE/run.log"
JSON="$BASE/output.json"
SUMMARY="$BASE/security-summary.txt"

mkdir -p \
    "$SUB" \
    "$HTTP" \
    "$PORTS" \
    "$META" \
    "$VULN" \
    "$WP" \
    "$UPLOADS" \
    "$SECURITY"

########################################
# LOGGING
########################################

log() {
    echo "[+] $*" | tee -a "$LOG"
}

warn() {
    echo "[!] $*" | tee -a "$LOG"
}

########################################
# DEPENDENCIES
########################################

log "Checking dependencies..."

REQUIRED_COMMANDS=(
    curl
    jq
    dig
    host
    whois
    grep
    sed
    awk
    sort
    tr
    diff
)

for cmd in "${REQUIRED_COMMANDS[@]}"; do

    if ! command -v "$cmd" >/dev/null 2>&1; then

        echo
        echo "Missing dependency: $cmd"
        echo
        echo "Install basic dependencies with:"
        echo
        echo "sudo apt install -y jq curl dnsutils whois"
        echo

        exit 1
    fi

done

########################################
# START
########################################

log "========================================"
log "GENLABS WORDPRESS SECURITY AUDIT"
log "========================================"

log "Target: $TARGET"
log "Output: $BASE"

########################################
# CERTIFICATE TRANSPARENCY
########################################

log "Certificate Transparency enumeration..."

CRT_JSON="$SUB/crt.json"

: > "$SUB/all.txt"

if curl \
    -fsSL \
    --max-time 30 \
    "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
    -o "$CRT_JSON"; then

    if jq empty "$CRT_JSON" >/dev/null 2>&1; then

        jq -r '.[].name_value' "$CRT_JSON" |
            tr '\r' '\n' |
            sed 's/\*\.//g' |
            grep -E "^[A-Za-z0-9.-]+$" |
            grep -E "(^|\.)${DOMAIN//./\\.}$" |
            sort -u \
            >> "$SUB/all.txt"

    else

        warn "crt.sh returned invalid JSON"

    fi

else

    warn "Certificate Transparency lookup failed"

fi

########################################
# SUBDOMAIN BRUTEFORCE
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
    sort -u \
    > "$SUB/all.tmp"

mv "$SUB/all.tmp" "$SUB/all.txt"

log "Total discovered hosts: $(wc -l < "$SUB/all.txt")"

########################################
# DNS RESOLUTION
########################################

log "Resolving hosts..."

: > "$SUB/alive.txt"

while IFS= read -r host; do

    ip=$(
        dig +short "$host" A |
        grep -E '^[0-9.]+$' |
        head -n1 ||
        true
    )

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
    sort -u \
    > "$META/ips.txt"

########################################
# REVERSE DNS
########################################

log "Reverse DNS..."

: > "$META/reverse.txt"

while IFS= read -r ip; do

    result=$(dig -x "$ip" +short 2>/dev/null || true)

    [[ -n "$result" ]] &&
        echo "$ip => $result" >> "$META/reverse.txt"

done < "$META/ips.txt"

########################################
# ASN / WHOIS
########################################

log "ASN / ownership information..."

: > "$META/asn.txt"

while IFS= read -r ip; do

    whois "$ip" 2>/dev/null |
        grep -Ei \
        'origin|originas|orgname|org-name|netname|descr|country' \
        >> "$META/asn.txt" ||
        true

done < "$META/ips.txt"

########################################
# HTTP PROBING
########################################

log "HTTP probing..."

: > "$META/http.txt"
: > "$META/panels.txt"

while IFS='|' read -r host ip; do

    safe_host=$(echo "$host" | tr -cd '[:alnum:]._-')

    body_file="$HTTP/${safe_host}.body"
    header_file="$HTTP/${safe_host}.headers"

    log "HTTP: $host"

    curl \
        -k \
        -sS \
        --max-time "$CURL_TIMEOUT" \
        --max-filesize "$MAX_BODY_SIZE" \
        -A "Mozilla/5.0 (compatible; Genlabs-Security-Audit/1.0)" \
        -D "$header_file" \
        -o "$body_file" \
        "https://${host}/" \
        2>>"$LOG" ||
        true

    if [[ -f "$header_file" ]]; then

        status=$(
            awk 'NR==1 {print $2}' \
            "$header_file" \
            2>/dev/null ||
            true
        )

        echo "$host|$status|$ip" \
            >> "$META/http.txt"

    fi

    if [[ -f "$body_file" ]]; then

        if grep -qiE \
            'wp-content|wp-includes|wp-json|woocommerce|elementor' \
            "$body_file"; then

            echo "$host => probable WordPress" \
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
    --max-time "$CURL_TIMEOUT" \
    -o "$WP/home.html" \
    "$TARGET/"; then

    if grep -qiE \
        'wp-content|wp-includes|wp-json|woocommerce' \
        "$WP/home.html"; then

        WP_DETECTED=true
        log "WordPress detected."

    else

        warn "WordPress could not be confirmed."

    fi

else

    warn "Unable to fetch homepage."

fi

########################################
# WORDPRESS CORE VERSION
########################################

log "Checking WordPress core version..."

CORE_VERSION="unknown"

if [[ -f "$WP/home.html" ]]; then

    CORE_VERSION=$(
        grep -oiE \
            '<meta[^>]+name=["'"'"']generator["'"'"'][^>]+content=["'"'"']WordPress [0-9.]+' \
            "$WP/home.html" |
        grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' |
        head -n1 ||
        true
    )

fi

echo "$CORE_VERSION" > "$WP/core-version.txt"

########################################
# WP ENDPOINTS
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
            2>/dev/null ||
            echo "000"
    )

    echo "$name|$path|$status" \
        >> "$WP/endpoints.txt"

    log "WP endpoint: $path => $status"
}

check_endpoint "wp-login" "/wp-login.php"
check_endpoint "wp-admin" "/wp-admin/"
check_endpoint "wp-json" "/wp-json/"
check_endpoint "xmlrpc" "/xmlrpc.php"
check_endpoint "wp-cron" "/wp-cron.php"

########################################
# SENSITIVE FILES
########################################

log "Checking sensitive files..."

: > "$WP/sensitive-files.txt"

check_sensitive() {

    local path="$1"

    local status
    local size
    local type

    status=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{http_code}" \
            --max-time 10 \
            "${TARGET}${path}" \
            2>/dev/null ||
            echo "000"
    )

    size=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{size_download}" \
            --max-time 10 \
            "${TARGET}${path}" \
            2>/dev/null ||
            echo "0"
    )

    type=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{content_type}" \
            --max-time 10 \
            "${TARGET}${path}" \
            2>/dev/null ||
            echo "unknown"
    )

    echo "$path|$status|$size|$type" \
        >> "$WP/sensitive-files.txt"

    case "$status" in

        200|206)
            warn "EXPOSED: $path => $status ($size bytes)"
            ;;

        403)
            log "Protected: $path => 403"
            ;;

        404)
            log "Not found: $path"
            ;;

        *)
            log "Checked: $path => $status"
            ;;

    esac
}

check_sensitive "/wp-config.php"
check_sensitive "/wp-config.php.bak"
check_sensitive "/wp-config.php.old"
check_sensitive "/wp-config.php.save"
check_sensitive "/wp-config.php.swp"
check_sensitive "/.env"
check_sensitive "/.git/HEAD"
check_sensitive "/debug.log"
check_sensitive "/wp-content/debug.log"
check_sensitive "/wp-content/uploads/debug.log"

########################################
# NORMAL WORDPRESS PUBLIC FILES
########################################

: > "$WP/public-files.txt"

for path in \
    "/readme.html" \
    "/license.txt"; do

    status=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{http_code}" \
            --max-time 10 \
            "${TARGET}${path}" \
            2>/dev/null ||
            echo "000"
    )

    echo "$path|$status" >> "$WP/public-files.txt"

done

########################################
# UPLOAD DIRECTORY
########################################

log "Checking /wp-content/uploads/ ..."

UPLOADS_STATUS=$(
    curl \
        -k \
        -sS \
        -o "$UPLOADS/index.html" \
        -w "%{http_code}" \
        --max-time "$CURL_TIMEOUT" \
        "${TARGET}/wp-content/uploads/" \
        2>/dev/null ||
        echo "000"
)

echo "directory|$UPLOADS_STATUS" \
    > "$UPLOADS/status.txt"

log "Uploads directory => HTTP $UPLOADS_STATUS"

########################################
# DIRECTORY LISTING
########################################

DIRECTORY_LISTING=false

if [[ "$UPLOADS_STATUS" == "200" ]]; then

    if grep -qiE \
        'Index of /wp-content/uploads|Directory listing|Parent Directory' \
        "$UPLOADS/index.html"; then

        DIRECTORY_LISTING=true

        warn "DIRECTORY LISTING ENABLED"

    fi

fi

echo "DIRECTORY_LISTING=$DIRECTORY_LISTING" \
    > "$UPLOADS/finding.txt"

########################################
# EXTRACT VISIBLE UPLOAD FILES
########################################

log "Extracting files visible in uploads listing..."

: > "$UPLOADS/listed-files.txt"

if [[ "$DIRECTORY_LISTING" == true ]]; then

    grep -oiE \
        'href=["'"'"'][^"'"'"']+["'"'"']' \
        "$UPLOADS/index.html" |
    sed -E 's/^href=["'"'"']//' |
    sed -E 's/["'"'"']$//' |
    grep -vE '^(\.\.?|/)' |
    sort -u \
    > "$UPLOADS/listed-files.txt" ||
    true

fi

########################################
# CLASSIFY LISTED FILES
########################################

log "Classifying exposed upload files..."

: > "$UPLOADS/findings.txt"

while IFS= read -r file; do

    [[ -z "$file" ]] && continue

    case "$file" in

        *.php|*.php[0-9]|*.phtml|*.phar|*.inc)
            echo "CRITICAL_CANDIDATE|$file" \
                >> "$UPLOADS/findings.txt"
            ;;

        *.sql|*.sql.gz|*.zip|*.tar|*.tar.gz|*.tgz|*.bak|*.backup|*.old)
            echo "HIGH_SENSITIVITY|$file" \
                >> "$UPLOADS/findings.txt"
            ;;

        *.log|*.txt|*.json|*.csv|*.xml)
            echo "POTENTIAL_DATA_EXPOSURE|$file" \
                >> "$UPLOADS/findings.txt"
            ;;

        .env|*.env)
            echo "CRITICAL_CANDIDATE|$file" \
                >> "$UPLOADS/findings.txt"
            ;;

        *)
            echo "NORMAL|$file" \
                >> "$UPLOADS/findings.txt"
            ;;

    esac

done < "$UPLOADS/listed-files.txt"

########################################
# VERIFY INTERESTING UPLOAD FILES
########################################

log "Verifying interesting files..."

: > "$UPLOADS/verified-files.txt"

while IFS='|' read -r classification file; do

    [[ -z "$file" ]] && continue

    # Avoid external URLs.
    [[ "$file" =~ ^https?:// ]] && continue

    file="${file#/}"

    url="${TARGET}/wp-content/uploads/${file}"

    status=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{http_code}" \
            --max-time 10 \
            "$url" \
            2>/dev/null ||
            echo "000"
    )

    content_type=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{content_type}" \
            --max-time 10 \
            "$url" \
            2>/dev/null ||
            echo "unknown"
    )

    echo "$classification|$file|$status|$content_type" \
        >> "$UPLOADS/verified-files.txt"

    if [[ "$status" == "200" || "$status" == "206" ]]; then

        case "$classification" in

            CRITICAL_CANDIDATE)
                warn "CRITICAL CANDIDATE EXPOSED: $file"
                ;;

            HIGH_SENSITIVITY)
                warn "HIGH-SENSITIVITY FILE EXPOSED: $file"
                ;;

            POTENTIAL_DATA_EXPOSURE)
                warn "POTENTIAL DATA EXPOSURE: $file"
                ;;

        esac

    fi

done < "$UPLOADS/findings.txt"

########################################
# PHP CANDIDATE DISCOVERY
########################################

log "Checking common PHP locations..."

: > "$UPLOADS/php-checks.txt"

PHP_NAMES=(
    "index.php"
    "test.php"
    "upload.php"
    "image.php"
    "ajax.php"
    "security-canary.php"
)

for phpfile in "${PHP_NAMES[@]}"; do

    result=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{http_code}|%{content_type}|%{size_download}" \
            --max-time 10 \
            "${TARGET}/wp-content/uploads/${phpfile}" \
            2>/dev/null ||
            echo "000|unknown|0"
    )

    echo "$phpfile|$result" \
        >> "$UPLOADS/php-checks.txt"

done

########################################
# PHP EXECUTION CANARY
########################################

log "PHP execution canary..."

CANARY_RESULT="NOT_TESTED"

if [[ -n "$PHP_CANARY_URL" ]]; then

    if [[ "$PHP_CANARY_URL" != /* ]]; then
        warn "PHP canary path must start with /"
    else

        CANARY_URL="${TARGET}${PHP_CANARY_URL}"

        CANARY_BODY="$UPLOADS/php-canary-response.txt"
        CANARY_HEADERS="$UPLOADS/php-canary-headers.txt"

        curl \
            -k \
            -sS \
            --max-time 10 \
            -D "$CANARY_HEADERS" \
            -o "$CANARY_BODY" \
            "$CANARY_URL" \
            2>/dev/null ||
            true

        CANARY_STATUS=$(
            awk '
                $1 ~ /^HTTP\// {
                    status=$2
                }
                END {
                    print status
                }
            ' "$CANARY_HEADERS" 2>/dev/null ||
            echo "000"
        )

        if grep -qE 'GENLABS_PHP_CANARY_OK' "$CANARY_BODY"; then

            CANARY_RESULT="PHP_EXECUTED"

            warn "!!! PHP EXECUTION CONFIRMED !!!"
            warn "$CANARY_URL"

        elif [[ "$CANARY_STATUS" == "200" ]]; then

            CANARY_RESULT="HTTP_200_BUT_CANARY_NOT_EXECUTED"

            warn "Canary returned HTTP 200 but marker was not observed."

        elif [[ "$CANARY_STATUS" == "403" ]]; then

            CANARY_RESULT="BLOCKED_403"

            log "PHP canary blocked with HTTP 403."

        elif [[ "$CANARY_STATUS" == "404" ]]; then

            CANARY_RESULT="NOT_FOUND"

            log "PHP canary not found."

        else

            CANARY_RESULT="HTTP_${CANARY_STATUS}"

        fi

        echo "$CANARY_RESULT" \
            > "$UPLOADS/php-canary-result.txt"

    fi

else

    echo "NOT_TESTED" \
        > "$UPLOADS/php-canary-result.txt"

    log "PHP canary not configured."
    log "Use --php-canary-url for an explicit execution test."

fi

########################################
# REST API
########################################

log "Checking REST API..."

curl \
    -k \
    -fsSL \
    --max-time "$CURL_TIMEOUT" \
    "${TARGET}/wp-json/" \
    -o "$WP/wp-json.json" \
    2>/dev/null ||
    true

if [[ -s "$WP/wp-json.json" ]] &&
   jq empty "$WP/wp-json.json" >/dev/null 2>&1; then

    jq '{
        name: .name,
        description: .description,
        url: .url,
        home: .home,
        namespaces: .namespaces
    }' \
    "$WP/wp-json.json" \
    > "$WP/wp-json-summary.json" \
    2>/dev/null ||
    true

fi

########################################
# REST USER ENUMERATION
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
        2>/dev/null ||
        echo "000"
)

echo "$USER_STATUS" \
    > "$WP/user-endpoint-status.txt"

if [[ "$USER_STATUS" == "200" ]]; then

    warn "REST user endpoint returned HTTP 200."

    echo "USER_ENDPOINT_ACCESSIBLE=true" \
        > "$WP/user-endpoint-finding.txt"

else

    echo "USER_ENDPOINT_ACCESSIBLE=false" \
        > "$WP/user-endpoint-finding.txt"

fi

########################################
# XML-RPC
########################################

log "Checking XML-RPC..."

curl \
    -k \
    -sS \
    -D "$WP/xmlrpc.txt" \
    -o /dev/null \
    --max-time 10 \
    "${TARGET}/xmlrpc.php" \
    2>/dev/null ||
    true

########################################
# SECURITY HEADERS
########################################

log "Checking security headers..."

curl \
    -k \
    -sS \
    -D "$SECURITY/headers.txt" \
    -o /dev/null \
    --max-time "$CURL_TIMEOUT" \
    "$TARGET/" \
    2>/dev/null ||
    true

: > "$SECURITY/header-summary.txt"

for header in \
    strict-transport-security \
    content-security-policy \
    x-content-type-options \
    x-frame-options \
    referrer-policy \
    permissions-policy; do

    if grep -qi "^${header}:" "$SECURITY/headers.txt"; then

        echo "[PRESENT] $header" \
            >> "$SECURITY/header-summary.txt"

    else

        echo "[MISSING] $header" \
            >> "$SECURITY/header-summary.txt"

    fi

done

########################################
# HTTP OPTIONS
########################################

log "Checking HTTP methods..."

curl \
    -k \
    -sS \
    -i \
    -X OPTIONS \
    --max-time 10 \
    "$TARGET/" \
    > "$SECURITY/options.txt" \
    2>/dev/null ||
    true

########################################
# WORDPRESS COMMON DIRECTORIES
########################################

log "Checking WordPress directories..."

: > "$WP/directories.txt"

for path in \
    "/wp-admin/" \
    "/wp-includes/" \
    "/wp-content/" \
    "/wp-content/plugins/" \
    "/wp-content/themes/" \
    "/wp-content/uploads/"; do

    status=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{http_code}" \
            --max-time 10 \
            "${TARGET}${path}" \
            2>/dev/null ||
            echo "000"
    )

    echo "$path|$status" \
        >> "$WP/directories.txt"

done

########################################
# ROBOTS / SITEMAP
########################################

log "Checking robots.txt and sitemap..."

for path in \
    "/robots.txt" \
    "/sitemap.xml" \
    "/wp-sitemap.xml"; do

    status=$(
        curl \
            -k \
            -sS \
            -o /dev/null \
            -w "%{http_code}" \
            --max-time 10 \
            "${TARGET}${path}" \
            2>/dev/null ||
            echo "000"
    )

    echo "$path|$status" \
        >> "$WP/public-endpoints.txt"

done

########################################
# NUCLEI
########################################

if [[ "$ENABLE_NUCLEI" == true ]]; then

    if command -v nuclei >/dev/null 2>&1; then

        log "Running Nuclei..."

        cut -d'|' -f1 "$SUB/alive.txt" \
            > "$SUB/hosts.txt"

        nuclei \
            -l "$SUB/hosts.txt" \
            -severity info,low,medium,high,critical \
            -rate-limit "$THREADS" \
            -o "$VULN/nuclei.txt" \
            -silent \
            >> "$LOG" 2>&1 ||
            true

    else

        warn "Nuclei not installed; skipping."

    fi

fi

########################################
# PORT SCAN
########################################

if [[ "$ENABLE_PORT_SCAN" == true ]]; then

    if command -v nmap >/dev/null 2>&1; then

        log "Running nmap..."

        while IFS='|' read -r host ip; do

            safe_host=$(echo "$host" | tr -cd '[:alnum:]._-')

            nmap \
                -Pn \
                --top-ports 1000 \
                --open \
                "$ip" \
                -oN "$PORTS/${safe_host}.txt" \
                >> "$LOG" 2>&1 ||
                true

        done < "$SUB/alive.txt"

    else

        warn "nmap not installed; skipping."

    fi

fi

########################################
# FINDINGS
########################################

log "Building findings..."

: > "$SECURITY/findings.txt"

if [[ "$DIRECTORY_LISTING" == true ]]; then

    echo "HIGH|Directory listing enabled on /wp-content/uploads/" \
        >> "$SECURITY/findings.txt"

fi

if grep -Eq '^CRITICAL_CANDIDATE\|.*\|(200|206)\|' \
    "$UPLOADS/verified-files.txt" 2>/dev/null; then

    echo "CRITICAL|Executable/sensitive candidate exposed in uploads" \
        >> "$SECURITY/findings.txt"

fi

if grep -Eq '^HIGH_SENSITIVITY\|.*\|(200|206)\|' \
    "$UPLOADS/verified-files.txt" 2>/dev/null; then

    echo "HIGH|Backup/database/archive exposed in uploads" \
        >> "$SECURITY/findings.txt"

fi

if [[ "$CANARY_RESULT" == "PHP_EXECUTED" ]]; then

    echo "CRITICAL|PHP execution confirmed in tested upload location" \
        >> "$SECURITY/findings.txt"

fi

if [[ "$USER_STATUS" == "200" ]]; then

    echo "LOW|REST API user enumeration accessible" \
        >> "$SECURITY/findings.txt"

fi

########################################
# JSON
########################################

log "Generating JSON..."

SUBS_JSON=$(
    jq -R -s '
        split("\n") |
        map(select(length > 0))
    ' "$SUB/all.txt"
)

IPS_JSON=$(
    jq -R -s '
        split("\n") |
        map(select(length > 0))
    ' "$META/ips.txt"
)

WP_JSON=false

if [[ "$WP_DETECTED" == true ]]; then
    WP_JSON=true
fi

jq -n \
    --arg domain "$DOMAIN" \
    --arg target "$TARGET" \
    --arg timestamp "$TS" \
    --arg core_version "$CORE_VERSION" \
    --arg canary "$CANARY_RESULT" \
    --argjson wordpress "$WP_JSON" \
    --argjson subdomains "$SUBS_JSON" \
    --argjson ips "$IPS_JSON" \
    '{
        domain: $domain,
        target: $target,
        timestamp: $timestamp,

        wordpress_detected: $wordpress,
        wordpress_core_version: $core_version,

        php_upload_canary: $canary,

        subdomains: $subdomains,
        ips: $ips
    }' \
    > "$JSON"

########################################
# SECURITY SUMMARY
########################################

{
    echo "=============================================="
    echo " GENLABS WORDPRESS SECURITY AUDIT"
    echo "=============================================="
    echo
    echo "Target: $TARGET"
    echo "Date:   $(date)"
    echo
    echo "WordPress detected: $WP_DETECTED"
    echo "Core version:       $CORE_VERSION"
    echo
    echo "=============================================="
    echo " UPLOADS"
    echo "=============================================="
    echo
    echo "Directory HTTP:      $UPLOADS_STATUS"
    echo "Directory listing:   $DIRECTORY_LISTING"
    echo "PHP canary:          $CANARY_RESULT"
    echo

    if [[ -s "$UPLOADS/verified-files.txt" ]]; then

        echo "Verified interesting files:"
        cat "$UPLOADS/verified-files.txt"

    else

        echo "No interesting files discovered."

    fi

    echo
    echo "=============================================="
    echo " SENSITIVE FILES"
    echo "=============================================="
    echo

    grep -E '\|(200|206)\|' \
        "$WP/sensitive-files.txt" ||
        echo "No tested sensitive files returned 200/206."

    echo
    echo "=============================================="
    echo " REST API"
    echo "=============================================="
    echo
    echo "User endpoint: $USER_STATUS"
    echo

    echo "=============================================="
    echo " FINDINGS"
    echo "=============================================="
    echo

    if [[ -s "$SECURITY/findings.txt" ]]; then
        cat "$SECURITY/findings.txt"
    else
        echo "No automated findings."
    fi

    echo
    echo "=============================================="
    echo " OUTPUT"
    echo "=============================================="
    echo
    echo "$BASE"

} > "$SUMMARY"

########################################
# DIFF
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

if [[ -n "${PREV:-}" &&
      -f "$PREV/subdomains/all.txt" ]]; then

    log "Comparing with previous scan..."

    diff \
        "$PREV/subdomains/all.txt" \
        "$SUB/all.txt" \
        > "$BASE/diff.txt" ||
        true

fi

########################################
# COMPLETE
########################################

log "========================================"
log "AUDIT COMPLETE"
log "========================================"

echo
echo "Target:"
echo "  $TARGET"
echo
echo "Summary:"
echo "  $SUMMARY"
echo
echo "Uploads:"
echo "  $UPLOADS/"
echo
echo "Findings:"
echo "  $SECURITY/findings.txt"
echo
echo "JSON:"
echo "  $JSON"
echo
echo "Nuclei:"
echo "  $VULN/nuclei.txt"
echo
echo "🔥 Security audit completed."
