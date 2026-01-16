#!/usr/bin/env bash

# PM – Passive Monitoring & Recon Tool
# Author: Prashant M.

# Enforce bash
if [[ -z "${BASH_VERSION:-}" ]]; then
  echo "ERROR: This script must be run with bash"
  exit 1
fi

set -euo pipefail

# DEFAULT CONFIG (IMPORTANT: before arg parsing)
ENABLE_PORT_SCAN=false
SCAN_ORIGINS_ONLY=false
FULL_PORT_SCAN=false
DRY_RUN=false

NMAP_TIMING="-T2"
TOP_PORTS=1000
NMAP_TIMEOUT="5m"
PUBLIC_DNS="8.8.8.8"

# ARGUMENT PARSING
DOMAIN=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --ports)
      case "${2:-}" in
        full)
          ENABLE_PORT_SCAN=true
          FULL_PORT_SCAN=true
          ;;
        top)
          ENABLE_PORT_SCAN=true
          FULL_PORT_SCAN=false
          ;;
        *)
          echo "Invalid value for --ports (use top|full)"
          exit 1
          ;;
      esac
      shift 2
      ;;
    --scan-origins-only)
      SCAN_ORIGINS_ONLY=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    *)
      if [[ -z "$DOMAIN" ]]; then
        DOMAIN="$1"
      fi
      shift
      ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  echo "Usage: $0 <domain> [--ports top|full] [--scan-origins-only] [--dry-run]"
  exit 1
fi

# PATHS
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
BASE="site-audit/${DOMAIN}-${TIMESTAMP}"

DNS="$BASE/dns"
SUB="$BASE/subdomains"
HTTP="$BASE/http"
TLS="$BASE/tls"
META="$BASE/meta"
PORTS="$BASE/ports"
LOG="$BASE/logs/run.log"

mkdir -p "$DNS" "$SUB" "$HTTP" "$TLS" "$META" "$PORTS" "$BASE/logs"

# LOGGING
log() {
  echo "[$(date '+%F %T')] $*" >>"$LOG"
}

# LOGO
cat <<'EOF'

██████╗ ███╗   ███╗
██╔══██╗████╗ ████║
██████╔╝██╔████╔██║
██╔═══╝ ██║╚██╔╝██║
██║     ██║ ╚═╝ ██║
╚═╝     ╚═╝     ╚═╝

[PM] Passive Monitoring & Recon Tool by Prashant M.
------------------------------------------------

EOF

# PROGRESS BAR (UI SAFE)
progress_bar() {
  set +e
  local label="$1"
  local width=30
  for ((i=0;i<=width;i++)); do
    printf "\r%s [%-30s] %3d%%" "$label" "$(printf '=%.0s' $(seq 1 $i))>" "$((i*100/width))"
    sleep 0.04
  done
  echo
  set -e
}

progress_update() {
  local current="$1"
  local total="$2"
  local label="$3"
  local width=30

  # Handle division by zero or empty totals
  [[ "$total" -eq 0 ]] && return

  local percent=$(( current * 100 / total ))
  local filled=$(( percent * width / 100 ))

  printf "\r%s [" "$label"
  for ((i=1; i<=filled; i++)); do printf "="; done
  for ((i=filled+1; i<=width; i++)); do printf " "; done
  printf "] %3d%% (%d/%d)" "$percent" "$current" "$total"
}

# IP NORMALIZATION
is_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

normalize_ip() {
  local host="$1"
  local ip="$2"

  # If already a valid IPv4, keep it
  if is_ipv4 "$ip"; then
    echo "$ip"
    return
  fi

  # Otherwise resolve again (force IP)
  dig +short "$host" | grep -E '^[0-9.]+' | head -n1
}

# SUDO (ONCE)
if ! sudo -n true 2>/dev/null; then
  sudo -v
fi

# DEPENDENCIES
ensure_tool() {
  if ! command -v "$1" &>/dev/null; then
    log "Installing missing tool: $1"
    sudo apt-get update -qq
    sudo apt-get install -y "$1"
  fi
}

for t in dig jq curl whois openssl nmap bc timeout; do
  ensure_tool "$t"
done

# CDN DETECTION (CACHED)
declare -A CDN_CACHE
is_cdn_ip() {
  local ip="$1"

  # Only check real IPs
  if ! is_ipv4 "$ip"; then
    return 1
  fi

  [[ -n "${CDN_CACHE[$ip]:-}" ]] && return "${CDN_CACHE[$ip]}"
  if whois "$ip" | grep -qiE "cloudflare|akamai|fastly|cloudfront|globalaccelerator"; then
    CDN_CACHE[$ip]=0; return 0
  else
    CDN_CACHE[$ip]=1; return 1
  fi
}

# DNS COLLECTION
records=(A AAAA NS MX TXT)
total_dns=${#records[@]}
current_dns=0

for r in "${records[@]}"; do
  current_dns=$((current_dns + 1))
  progress_update "$current_dns" "$total_dns" "DNS collection "
  dig "$DOMAIN" "$r" @"$PUBLIC_DNS" >"$DNS/$r.txt" 2>>"$LOG" || true
done
echo

progress_bar "DNS trace      "
dig "$DOMAIN" +trace @"$PUBLIC_DNS" >"$DNS/TRACE.txt" 2>>"$LOG" || true

# CERTIFICATE TRANSPARENCY
progress_bar "CT subdomains  "
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" |
jq -r '.[].name_value' |
tr '\n' ',' | tr ',' '\n' |
sed 's/\*\.//' |
grep -E "\.${DOMAIN}$" |
sort -u >"$SUB/all.txt"

# RESOLVE SUBDOMAINS
progress_bar "Resolving hosts"
> "$SUB/alive.txt"
total_subs=$(wc -l < "$SUB/all.txt")
curr_sub=0

while read -r sub; do
  curr_sub=$((curr_sub + 1))
  progress_update "$curr_sub" "$total_subs" "Resolving hosts "
  ip=$(dig +short "$sub" | head -n1 || true)
  [[ -n "$ip" ]] && echo "$sub|$ip" >>"$SUB/alive.txt"
done <"$SUB/all.txt"
echo

# IP OWNERSHIP
progress_bar "IP ownership "
total_alive=$(wc -l < "$SUB/alive.txt")
curr_own=0

while IFS='|' read -r host ip; do
  curr_own=$((curr_own + 1))
  progress_update "$curr_own" "$total_alive" "IP ownership   "
  whois "$ip" 2>/dev/null |
  awk -F: '/OrgName|org-name|netname|country/ {print}' |
  sed "s/^/$host ($ip): /"
done <"$SUB/alive.txt" >"$META/ip_ownership.txt"
echo

# PORT SCANNING (REAL PROGRESS)
if [[ "$ENABLE_PORT_SCAN" == "true" && "$DRY_RUN" == "false" ]]; then
  echo
  echo "Port scanning (real progress):"

  total_hosts=$(grep -c '|' "$SUB/alive.txt")
  completed=0

  while IFS='|' read -r host ip; do
    # Normalize IP (IMPORTANT)
    ip=$(normalize_ip "$host" "$ip")

    # Skip if still no valid IP
    if ! is_ipv4 "$ip"; then
      log "Skipping $host – could not resolve valid IP"
      continue
    fi

    # Skip CDN if requested
    if [[ "$SCAN_ORIGINS_ONLY" == "true" ]] && is_cdn_ip "$ip"; then
      log "Skipping CDN IP $ip for $host"
      continue
    fi

    echo "  → Scanning $host ($ip)"
    log "Scanning $host ($ip)"

    # ICMP / discovery
    nmap -sn "$ip" \
      -oN "$PORTS/$host.ping" \
      --host-timeout "$NMAP_TIMEOUT" \
      >>"$LOG" 2>&1 || true

    # Port scan
    if [[ "$FULL_PORT_SCAN" == "true" ]]; then
      nmap -Pn "$NMAP_TIMING" -p- --open "$ip" \
        -oN "$PORTS/$host.nmap" \
        --host-timeout "$NMAP_TIMEOUT" \
        >>"$LOG" 2>&1 || true
    else
      nmap -Pn "$NMAP_TIMING" --top-ports "$TOP_PORTS" --open "$ip" \
        -oN "$PORTS/$host.nmap" \
        --host-timeout "$NMAP_TIMEOUT" \
        >>"$LOG" 2>&1 || true
    fi

    # NOW update progress (after work finishes)
    completed=$((completed + 1))
    progress_update "$completed" "$total_hosts" "Scanning ports  "
  done <"$SUB/alive.txt"

  echo    # newline after progress bar
else
  log "Port scanning disabled or dry-run enabled"
fi


# HTTP COLLECTION
progress_bar "HTTP data     "
total_http=$(wc -l < "$SUB/alive.txt")
curr_http=0

while IFS='|' read -r host ip; do
  curr_http=$((curr_http + 1))
  progress_update "$curr_http" "$total_http" "HTTP data      "
  curl -k -s -D "$HTTP/$host.headers" \
       -c "$HTTP/$host.cookies" \
       -o "$HTTP/$host.body" \
       -w "%{http_code}" \
       --max-time 15 \
       "https://$host" >"$HTTP/$host.status" || true
done <"$SUB/alive.txt"
echo

# TLS CERTIFICATES
progress_bar "TLS certs     "
total_tls=$(wc -l < "$SUB/alive.txt")
curr_tls=0

while IFS='|' read -r host ip; do
  curr_tls=$((curr_tls + 1))
  progress_update "$curr_tls" "$total_tls" "TLS certs      "
  cert_dir="$TLS/$host"
  mkdir -p "$cert_dir"

  timeout 15 openssl s_client -connect "$host:443" -servername "$host" -showcerts </dev/null \
    >"$cert_dir/chain.pem" 2>>"$LOG" || continue

  awk '/BEGIN CERTIFICATE/{f=1} f{print} /END CERTIFICATE/&&f{exit}' \
    "$cert_dir/chain.pem" >"$cert_dir/leaf.pem"

  openssl x509 -in "$cert_dir/leaf.pem" -noout -issuer -subject -dates -fingerprint \
    >"$cert_dir/info.txt" 2>>"$LOG" || true

  openssl x509 -in "$cert_dir/leaf.pem" -noout -enddate | cut -d= -f2 \
    >"$cert_dir/expiry.txt" || true

done <"$SUB/alive.txt"
echo

# TECHNOLOGY HEURISTICS
progress_bar "Tech Finger   "
> "$META/tech_report.txt"
> "$META/tech_scores.csv"

total_tech=$(wc -l < "$SUB/alive.txt")
curr_tech=0

while IFS='|' read -r host ip; do
  curr_tech=$((curr_tech + 1))
  progress_update "$curr_tech" "$total_tech" "Tech Finger    "
  php=0; node=0; java=0
  body="$HTTP/$host.body"
  headers="$HTTP/$host.headers"
  cookies="$HTTP/$host.cookies"

  grep -qi "laravel_session\|PHPSESSID" "$cookies" && ((php+=3))
  grep -qi "connect.sid" "$cookies" && ((node+=3))
  grep -qi "JSESSIONID" "$cookies" && ((java+=3))

  grep -qi "_next/static\|react" "$body" && ((node+=4))
  grep -qi "wp-content" "$body" && ((php+=5))

  echo "$host|php=$php|node=$node|java=$java" >>"$META/tech_scores.csv"

  {
    echo "[$host]"
    echo "  PHP:  $php"
    echo "  Node: $node"
    echo "  Java:$java"
    echo
  } >>"$META/tech_report.txt"

done <"$SUB/alive.txt"
echo

# DONE
log "Audit completed for $DOMAIN"
echo
echo "Audit completed for $DOMAIN"
