#!/usr/bin/env bash
set -euo pipefail

############################
# CONFIG
############################
DOMAIN="$1"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
BASE="site-audit/${DOMAIN}-${TIMESTAMP}"

DNS="$BASE/dns"
SUB="$BASE/subdomains"
HTTP="$BASE/http"
TLS="$BASE/tls"
META="$BASE/meta"
LOG="$BASE/logs/run.log"

PUBLIC_DNS="8.8.8.8"
MAX_RETRY=2

mkdir -p "$DNS" "$SUB" "$HTTP" "$TLS" "$META" "$BASE/logs"

############################
# LOGGING
############################
log() {
  echo "[$(date '+%F %T')] $*" | tee -a "$LOG"
}

############################
# SUDO (ONCE)
############################
if ! sudo -n true 2>/dev/null; then
  log "Requesting sudo access"
  sudo -v
fi

############################
# DEPENDENCY MANAGEMENT
############################
ensure_tool() {
  if ! command -v "$1" &>/dev/null; then
    log "Installing missing tool: $1"
    sudo apt-get update -qq
    sudo apt-get install -y "$1"
  fi
}

for t in dig jq curl whois openssl; do
  ensure_tool "$t"
done

############################
# DNS COLLECTION
############################
log "DNS collection started"

for r in A AAAA NS MX TXT; do
  dig "$DOMAIN" "$r" @"$PUBLIC_DNS" \
    >"$DNS/$r.txt" 2>>"$LOG" || true
done

# TRACE is optional (environment-dependent)
if dig "$DOMAIN" +trace @"$PUBLIC_DNS" \
  >"$DNS/TRACE.txt" 2>>"$LOG"; then
  log "DNS trace successful"
else
  log "DNS trace skipped (resolver restriction)"
fi

############################
# CERTIFICATE TRANSPARENCY
############################
log "Fetching CT subdomains"

curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" |
jq -r '.[].name_value' |
tr '\n' ',' |
tr ',' '\n' |
sed 's/\*\.//' |
grep -E "\.${DOMAIN}$" |
sort -u >"$SUB/all.txt"

############################
# RESOLVE SUBDOMAINS
############################
log "Resolving subdomains"

> "$SUB/alive.txt"

while read -r sub; do
  ip=$(dig +short "$sub" | head -n1 || true)
  [[ -n "$ip" ]] && echo "$sub|$ip" >>"$SUB/alive.txt"
done <"$SUB/all.txt"

############################
# IP OWNERSHIP / ASN
############################
log "Collecting IP ownership"

while IFS='|' read -r host ip; do
  whois "$ip" 2>/dev/null |
  awk -F: '
    /OrgName|org-name|netname|country/ {print}
  ' | sed "s/^/$host ($ip): /"
done <"$SUB/alive.txt" >"$META/ip_ownership.txt"

############################
# HTTP + BODY + COOKIES
############################
log "Fetching HTTP data"

while IFS='|' read -r host ip; do
  curl -k -s -D "$HTTP/$host.headers" \
       -c "$HTTP/$host.cookies" \
       -o "$HTTP/$host.body" \
       --max-time 15 \
       "https://$host" || true
done <"$SUB/alive.txt"

############################
# TLS CERT INFO
############################
log "Fetching TLS certificates"

while IFS='|' read -r host ip; do
  echo | openssl s_client -connect "$host:443" \
       -servername "$host" 2>/dev/null |
  openssl x509 -noout -issuer -subject -dates \
    >"$TLS/$host.cert" || true
done <"$SUB/alive.txt"

############################
# TECHNOLOGY HEURISTICS
############################
log "Technology fingerprinting"

> "$META/tech_report.txt"

while IFS='|' read -r host ip; do
  php=0
  node=0
  java=0

  body="$HTTP/$host.body"
  headers="$HTTP/$host.headers"
  cookies="$HTTP/$host.cookies"

  grep -qi "laravel_session" "$cookies" && ((php+=3))
  grep -qi "PHPSESSID" "$cookies" && ((php+=3))
  grep -qi "connect.sid" "$cookies" && ((node+=3))
  grep -qi "JSESSIONID" "$cookies" && ((java+=3))

  grep -qi "_next/static" "$body" && ((node+=4))
  grep -qi "wp-content" "$body" && ((php+=5))
  grep -qi "data-reactroot" "$body" && ((node+=2))
  grep -qi "angular" "$body" && ((node+=2))

  grep -qi "X-Powered-By: Express" "$headers" && ((node+=2))
  grep -qi "X-Powered-By: PHP" "$headers" && ((php+=2))

  echo "[$host]" >>"$META/tech_report.txt"
  echo "  PHP score : $php" >>"$META/tech_report.txt"
  echo "  Node score: $node" >>"$META/tech_report.txt"
  echo "  Java score: $java" >>"$META/tech_report.txt"

  if (( php > node && php > java )); then
    echo "  Likely backend: PHP (confidence: $php)" >>"$META/tech_report.txt"
  elif (( node > php && node > java )); then
    echo "  Likely backend: Node.js (confidence: $node)" >>"$META/tech_report.txt"
  elif (( java > 0 )); then
    echo "  Likely backend: Java (confidence: $java)" >>"$META/tech_report.txt"
  else
    echo "  Backend: Unknown / intentionally hidden" >>"$META/tech_report.txt"
  fi

  echo >>"$META/tech_report.txt"

done <"$SUB/alive.txt"

############################
# DONE
############################
log "Audit completed for $DOMAIN"
