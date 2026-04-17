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

########################################
# ARG PARSE
########################################
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --ports) ENABLE_PORT_SCAN=true; shift ;;
    --no-nuclei) ENABLE_NUCLEI=false; shift ;;
    *) DOMAIN="$1"; shift ;;
  esac
done

[[ -z "$DOMAIN" ]] && { echo "Usage: $0 <domain>"; exit 1; }

########################################
# PATHS
########################################
TS=$(date +"%Y%m%d-%H%M%S")
BASE="recon/$DOMAIN-$TS"

SUB="$BASE/subdomains"
HTTP="$BASE/http"
PORTS="$BASE/ports"
META="$BASE/meta"
VULN="$BASE/vulns"
LOG="$BASE/run.log"
JSON="$BASE/output.json"

mkdir -p "$SUB" "$HTTP" "$PORTS" "$META" "$VULN"

log() { echo "[+] $*" | tee -a "$LOG"; }

########################################
# DEP CHECK
########################################
for cmd in dig curl jq whois; do
  command -v "$cmd" &>/dev/null || {
    echo "❌ Missing dependency: $cmd"
    exit 1
  }
done

########################################
# CT ENUM
########################################
log "CT enum..."

crt=$(curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" || true)

if echo "$crt" | jq . >/dev/null 2>&1; then
  echo "$crt" | jq -r '.[].name_value' |
    tr '\n' ',' | tr ',' '\n' |
    sed 's/\*\.//' |
    grep -E "^[a-zA-Z0-9.-]+$" |
    sort -u > "$SUB/all.txt"
else
  log "⚠ CT failed"
  > "$SUB/all.txt"
fi

########################################
# BRUTE SUBDOMAINS
########################################
log "Bruteforce subdomains..."

if [[ -f "$WORDLIST" ]]; then
  while read -r w; do
    host "$w.$DOMAIN" &>/dev/null && echo "$w.$DOMAIN" >> "$SUB/all.txt"
  done < "$WORDLIST"
else
  log "⚠ Wordlist not found"
fi

########################################
# FINALIZE SUBDOMAINS
########################################
echo "$DOMAIN" >> "$SUB/all.txt"
sort -u "$SUB/all.txt" -o "$SUB/all.txt"

if [[ ! -s "$SUB/all.txt" ]]; then
  log "⚠ No subdomains found, using root"
  echo "$DOMAIN" > "$SUB/all.txt"
fi

log "Total subs: $(wc -l < "$SUB/all.txt")"

########################################
# RESOLVE
########################################
log "Resolving..."

> "$SUB/alive.txt"

while read -r sub; do
  ip=$(dig +short "$sub" | head -n1 || true)

  if [[ -n "$ip" ]]; then
    echo "$sub|$ip" >> "$SUB/alive.txt"
  fi
done < "$SUB/all.txt"

sort -u "$SUB/alive.txt" -o "$SUB/alive.txt"

if [[ ! -s "$SUB/alive.txt" ]]; then
  log "⚠ No alive hosts found"
fi

########################################
# IP COLLECTION
########################################
cut -d'|' -f2 "$SUB/alive.txt" | sort -u > "$META/ips.txt"

########################################
# REVERSE IP
########################################
log "Reverse IP..."

> "$META/reverse.txt"

while read -r ip; do
  dig -x "$ip" +short >> "$META/reverse.txt" 2>/dev/null || true
done < "$META/ips.txt"

########################################
# ASN INFO
########################################
log "ASN lookup..."

> "$META/asn.txt"

while read -r ip; do
  whois "$ip" | grep -E "origin|OrgName|netname" >> "$META/asn.txt" || true
done < "$META/ips.txt"

########################################
# HTTP + PANEL DETECTION
########################################
log "HTTP probing..."

> "$META/panels.txt"

while IFS='|' read -r host ip; do
  safe_host=$(echo "$host" | tr -cd '[:alnum:]._-')
  body_file="$HTTP/$safe_host.body"
  header_file="$HTTP/$safe_host.headers"
  header_file="$HTTP/$host.headers"

  if [[ "$host" =~ [^a-zA-Z0-9.-] ]]; then
    log "Skipping invalid host: $host"
    continue
  fi
  curl -s -k \
       -H "User-Agent: Mozilla/5.0" \
       --max-time 10 \
       -D "$header_file" \
       -o "$body_file" \
       "https://$host" || true

  # ✅ Only check if files exist
  if [[ -f "$body_file" || -f "$header_file" ]]; then
    if grep -qiE "login|admin|cpanel|dashboard|signin" \
       "$body_file" "$header_file" 2>/dev/null; then
      echo "$host => possible panel" >> "$META/panels.txt"
    fi
  else
    log "⚠ HTTP failed for $host"
  fi

done < "$SUB/alive.txt"

########################################
# PORT SCAN
########################################
if [[ "$ENABLE_PORT_SCAN" == true ]]; then
  if command -v nmap &>/dev/null; then
    log "Port scanning..."

    while IFS='|' read -r host ip; do
      nmap -Pn --top-ports 1000 "$ip" \
        -oN "$PORTS/$host.txt" >>"$LOG" 2>&1 || true
    done < "$SUB/alive.txt"
  else
    log "⚠ nmap not installed, skipping"
  fi
fi

########################################
# NUCLEI SCAN
########################################
if [[ "$ENABLE_NUCLEI" == true ]]; then
  if command -v nuclei &>/dev/null; then
    log "Running nuclei..."

    cut -d'|' -f1 "$SUB/alive.txt" > "$SUB/hosts.txt"

    nuclei -l "$SUB/hosts.txt" \
      -o "$VULN/nuclei.txt" \
      -silent || true
  else
    log "⚠ nuclei not installed, skipping"
  fi
fi

########################################
# JSON OUTPUT
########################################
log "Generating JSON..."

jq -n \
  --arg domain "$DOMAIN" \
  --arg subs "$(tr '\n' ',' < "$SUB/all.txt")" \
  --arg ips "$(tr '\n' ',' < "$META/ips.txt")" \
  '{
    domain: $domain,
    subdomains: ($subs | split(",") | map(select(. != ""))),
    ips: ($ips | split(",") | map(select(. != "")))
  }' > "$JSON"

########################################
# DIFF SCAN
########################################
PREV=$(ls -td recon/$DOMAIN-* 2>/dev/null | sed -n '2p' || true)

if [[ -n "$PREV" && -f "$PREV/subdomains/all.txt" ]]; then
  log "Diff with previous scan..."

  diff "$PREV/subdomains/all.txt" "$SUB/all.txt" > "$BASE/diff.txt" || true
fi

########################################
# DONE
########################################
log "DONE → $BASE"
echo "🔥 Recon completed successfully"
