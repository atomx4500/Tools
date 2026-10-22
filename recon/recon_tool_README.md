# Recon Tool — README

**Authorized use only.** Run this only against domains you own or have written permission to test.

## What it does

A four-phase attack-surface recon script for the reconnaissance stage of a pentest:

1. **Subdomain enumeration** — pulls subdomains from crt.sh certificate transparency logs. Fully passive; no traffic hits the target.
2. **Live host check** — tests HTTP/HTTPS on each subdomain, captures status code and server header.
3. **Port scan** — checks common ports (or a custom range) using raw sockets, grabs service banners. No exploit payloads.
4. **Security header audit** — flags missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options.

Output: a console summary plus a full JSON report.

## Requirements

- Python 3.7+
- No third-party libraries — standard library only

## Usage

```bash
python recon_tool.py example.com
```

You'll be prompted to retype the domain to confirm authorization before anything runs.

### Options

| Flag | Default | Description |
|---|---|---|
| `-o, --output` | `recon_report.json` | Output file path |
| `--ports` | `common` | `common` (default list) or a range like `1-1000` |
| `--threads` | `50` | Concurrent thread count |
| `--max-hosts` | `15` | Cap on subdomains to live-check and port-scan |

### Example

```bash
python recon_tool.py example.com --ports 1-1000 --threads 100 -o example_recon.json
```

## Reading the output

- `hosts.<host>.http` — scheme, status, server header
- `hosts.<host>.missing_security_headers` — list of absent security headers
- `hosts.<host>.open_ports` — port number → banner/service string

Use these findings to guide **manual, authorized** follow-up testing. This tool identifies exposure; it does not exploit anything.

## Legal note

Unauthorized port scanning and enumeration can violate computer-crime law (e.g., the U.S. CFAA) even without exploitation. Always have written authorization — a signed scope document or bug bounty program rules — before running this against any target.
