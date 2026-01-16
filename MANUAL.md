# Site Audit Script Manual

## Overview
The `site_audit.sh` script is an automated reconnaissance tool designed to perform a comprehensive audit of a target domain. It gathers DNS records, subdomains, HTTP headers, TLS certificates, and technology stack information.

## Prerequisites
- **Operating System**: Linux (Debian/Ubuntu-based recommended due to `apt-get` usage).
- **Dependencies**: The script automatically checks for and installs the following tools if they are missing:
  - `dig` (DNS lookup)
  - `jq` (JSON processor)
  - `curl` (HTTP client)
  - `whois` (Domain/IP ownership)
  - `openssl` (TLS/SSL toolkit)

## How to Run

### Basic Usage
To run the audit against a domain (e.g., `example.com`), execute the script from your terminal:

```bash
./site_audit.sh example.com
```

### Running with Sudo
The script requires `sudo` privileges **only if** it needs to install missing dependencies (like `curl` or `jq`). It attempts to refresh sudo credentials at the start.

If you know dependencies are missing, or just to be safe, you can run it as:

```bash
./site_audit.sh example.com
```

(The script will prompt for your password if needed via `sudo -v`).

Alternatively, you can run the entire script as root (though not strictly required if dependencies are present):
```bash
sudo ./site_audit.sh example.com
```

### Port Scanning (Optional)

Run with top ports (recommended):
```bash
./site_audit.sh example.com --ports top
```

Run full scan (ONLY when appropriate):
```bash
./site_audit.sh example.com --ports full
```

### Advanced Port Scanning Options

**Scan Origins Only (Skip CDNs)**
To avoid scanning Cloudflare/Akamai/etc. and focus only on origin IPs:
```bash
./site_audit.sh example.com --ports top --scan-origins-only
```

| Setting               | Why                                |
| --------------------- | ---------------------------------- |
| `-T2`                 | Slow enough to avoid IDS spikes    |
| `--top-ports`         | Minimal footprint                  |
| `--open`              | No noise from closed ports         |
| `--host-timeout`      | No hanging                         |
| `--scan-origins-only` | Skips CDNs (Cloudflare, Fastly, etc)|
| `--dry-run`           | Skip heavy operations like port scans|
| `Port Diffing`        | Automatically compares with last run|

## Data Storage & Output Structure
All gathered data is stored in a timestamped directory structure under `site-audit/`.

**Format**: `site-audit/<DOMAIN>-<TIMESTAMP>/`

### Directory Layout

#### 1. `dns/` (DNS Records)
Contains raw output from `dig`:
- `A.txt`, `AAAA.txt`: IP addresses.
- `NS.txt`: Nameservers.
- `MX.txt`: Mail exchangers.
- `TXT.txt`: Text records (SPF, verification, etc.).
- `TRACE.txt`: Recursive DNS trace (if successful).

#### 2. `subdomains/` (Subdomain Enumeration)
- `all.txt`: List of all potential subdomains found via Certificate Transparency logs.
- `alive.txt`: List of subdomains that actively resolved to an IP address (`host|ip` format).

#### 3. `http/` (HTTP Analysis)
For each active host:
- `*.headers`: HTTP response headers.
- `*.cookies`: Cookies set by the server.
- `*.body`: Full HTML response body.

#### 4. `tls/` (TLS/SSL Certificates)
For each active host:
- `chain.pem`: Full certificate chain.
- `leaf.pem`: The specific server certificate.
- `info.txt`: Human-readable certificate details (Issuer, Subject, Dates, Fingerprint).
- `expiry.txt`: Expiration date of the certificate.
- `verify.txt`: Verification status checking the chain of trust.

#### 5. `meta/` (Metadata & Reports)
- `ip_ownership.txt`: WHOIS information for resolved IP addresses.
- `tech_report.txt`: Heuristic analysis of the technology stack (e.g., guessing use of PHP, Node.js, Java) based on cookies and headers.
- `port_diff.txt`: Comparison of open ports between the current run and the most recent previous run. Logs `[CHANGE]`, `[NEW]`, and `[OLD]` results.

#### 6. `ports/` (Port Scanning)
- `*.ping`: Host discovery results (ICMP/Ping).
- `*.nmap`: Nmap scan results (open ports, protocols).

#### 7. `logs/`
- `run.log`: Detailed execution log of the script run.

## Troubleshooting
- **Permission Denied**: Ensure the script is executable: `chmod +x site_audit.sh`.
- **Missing Dependencies**: If the script fails to install tools, ensure you have internet access and sudo privileges.
- **Empty Output**: Check `logs/run.log` for errors. Some domains may block repetitive scanning or have strict firewalls.

