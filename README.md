# Joomla Recon — Unified Joomla Vulnerability Scanner

A standalone Python 3 tool combining the best of **JoomlaScan** and **droopescan**, with added brute-force login and live NVD CVE lookup.

## Features

| Feature | Details |
|---|---|
| **Version fingerprinting** | Vote-based MD5 matching across 1,314 file hashes (Joomla 1.5 → 4.x) |
| **Component enumeration** | 1,235 known Joomla components with sub-file and directory listing checks |
| **Component version detection** | Reads XML manifests to extract installed component versions |
| **Interesting URL detection** | 37 sensitive paths including `.git`, config backups, admin panel |
| **Fake-200 detection** | Warns when the server returns 200 for all URLs (soft-404) |
| **Redirect following** | Automatically follows HTTP→HTTPS and www redirects |
| **Brute-force login** | Multi-threaded, streaming wordlist, lockout detection, CSRF-aware |
| **Live NVD CVE lookup** | Real-time NIST NVD API queries for core and component CVEs |
| **WAF evasion** | User-Agent rotation, proxy support, rate limiting, exponential back-off |
| **JSON output** | Save results to file or stdout |

## Requirements

- Python 3.9+
- `requests`
- `beautifulsoup4`

## Installation

```bash
git clone https://github.com/yourname/joomla-recon.git
cd joomla-recon
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 joomla_recon.py -u https://target.com

# With threading and proxy
python3 joomla_recon.py -u https://target.com -t 30 --proxy http://127.0.0.1:8080

# Brute-force admin login
python3 joomla_recon.py -u https://target.com --brute -usr admin -w /usr/share/wordlists/rockyou.txt

# Brute-force with username list
python3 joomla_recon.py -u https://target.com --brute -U users.txt -w passwords.txt --brute-threads 5

# Live CVE lookup (requires internet)
python3 joomla_recon.py -u https://target.com --live-cve

# Live CVE with NVD API key (50 req/30s instead of 5/30s)
python3 joomla_recon.py -u https://target.com --live-cve --nvd-key YOUR_KEY

# Save results as JSON
python3 joomla_recon.py -u https://target.com --output json --output-file results.json

# WAF evasion mode
python3 joomla_recon.py -u https://target.com --rotate-ua --rate-limit 2 --delay 0.5

# Skip slow phases
python3 joomla_recon.py -u https://target.com --no-components --no-version
```

## All Options

```
Core:
  -u URL              Target URL (required)
  -t THREADS          Threads for component scan (default: 10)
  --timeout SECS      Request timeout in seconds (default: 10)
  --user-agent UA     Custom User-Agent string

Proxy / Session:
  --proxy URL         HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)
  --cookie COOKIES    Cookies to inject (format: key=val; key2=val2)
  --header HEADER     Extra headers (repeatable: --header "X-Foo: bar")

WAF Evasion:
  --rotate-ua         Rotate User-Agent per request
  --rate-limit RPS    Max requests per second (default: unlimited)
  --delay SECS        Fixed delay between requests (default: 0)

Brute-Force Login (Phase 5):
  --brute             Enable brute-force login
  -w WORDLIST         Password wordlist file
  -usr USERNAME       Single username
  -U USERLIST         Username list file
  --brute-threads N   Threads for brute-force (default: 1)
  --brute-delay SECS  Delay between attempts (default: 0)
  --lockout-pause N   Pause seconds on lockout detection (default: 60)

Live CVE Lookup (Phase 5b):
  --live-cve          Query NIST NVD API for live CVEs
  --nvd-key KEY       NVD API key for higher rate limits

Output:
  --output FORMAT     text (default) | json | stdout-json
  --output-file FILE  JSON output file path

Skip Phases:
  --no-components     Skip component enumeration
  --no-version        Skip version fingerprinting
  --no-redirect-follow  Do not follow HTTP redirects
```

## Data Files

All data files are in the `data/` directory:

| File | Description |
|---|---|
| `data/versions.xml` | 1,314 MD5 fingerprint hashes for Joomla 1.5–4.x version detection |
| `data/comptotestdb.txt` | 1,235 known Joomla component names for enumeration |

## Legal

This tool is intended for authorized security testing only. Always obtain written permission before scanning any system you do not own.
