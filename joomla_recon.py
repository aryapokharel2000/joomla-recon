#!/usr/bin/env python3
"""
joomla_recon.py — Unified Joomla Vulnerability Scanner
Combines JoomlaScan + droopescan + brute-force login + live NVD CVE lookup.

Usage:
    python3 joomla_recon.py -u https://target.com [options]
    python3 joomla_recon.py -u https://target.com --brute -usr admin -w rockyou.txt
    python3 joomla_recon.py -u https://target.com --live-cve
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
import threading
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

# ─────────────────────────────────────────────────────────────────────────────
# ANSI Colours
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def red(s):     return f"{C.RED}{s}{C.RESET}"
def yellow(s):  return f"{C.YELLOW}{s}{C.RESET}"
def green(s):   return f"{C.GREEN}{s}{C.RESET}"
def cyan(s):    return f"{C.CYAN}{s}{C.RESET}"
def blue(s):    return f"{C.BLUE}{s}{C.RESET}"
def magenta(s): return f"{C.MAGENTA}{s}{C.RESET}"
def bold(s):    return f"{C.BOLD}{s}{C.RESET}"
def dim(s):     return f"{C.DIM}{s}{C.RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# Paths (relative to this script's location)
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_DIR      = os.path.join(SCRIPT_DIR, "data")
COMPONENTS_DB = os.path.join(DATA_DIR, "comptotestdb.txt")
VERSIONS_XML  = os.path.join(DATA_DIR, "versions.xml")

VERSION = "3.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# User-Agent pool for WAF evasion rotation
# ─────────────────────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
]

# ─────────────────────────────────────────────────────────────────────────────
# Bundled CVE database for common Joomla components + core versions
# Format: { "component_name": [ { cve, severity, cvss, affects, description } ] }
# Severity: CRITICAL, HIGH, MEDIUM, LOW
# affects: version range string shown to user (not parsed — just informational)
# ─────────────────────────────────────────────────────────────────────────────
CVE_DB: dict = {
    # ── Joomla Core ──────────────────────────────────────────────────────────
    "__core__": [
        {
            "cve": "CVE-2023-23752",
            "severity": "CRITICAL",
            "cvss": 7.5,
            "affects": "4.0.0 – 4.2.7",
            "description": "Improper access check allows unauthenticated read of webservice endpoints, leaking DB credentials via /api/index.php/v1/config/application.",
        },
        {
            "cve": "CVE-2015-8562",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affects": "1.5.0 – 3.4.5",
            "description": "Remote Code Execution via HTTP User-Agent header deserialization (unserialise). Widely exploited in the wild.",
        },
        {
            "cve": "CVE-2017-8917",
            "severity": "HIGH",
            "cvss": 8.8,
            "affects": "3.7.0",
            "description": "SQL Injection in com_fields com_fields list controller (ordering parameter) — unauthenticated.",
        },
        {
            "cve": "CVE-2019-10945",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affects": "1.5.0 – 3.9.4",
            "description": "Path Traversal and Remote Code Execution via com_media file manager — authenticated admin required.",
        },
        {
            "cve": "CVE-2022-23793",
            "severity": "HIGH",
            "cvss": 7.5,
            "affects": "3.0.0 – 3.10.6 / 4.0.0 – 4.1.0",
            "description": "Path traversal in Joomla core — potential arbitrary file read.",
        },
        {
            "cve": "CVE-2024-21726",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affects": "4.0.0 – 4.4.2 / 5.0.0 – 5.0.2",
            "description": "Inadequate content filtering leads to XSS in multiple core components. Trivially escalates to RCE in some configurations.",
        },
    ],
    # ── Extensions ───────────────────────────────────────────────────────────
    "com_jce": [
        {
            "cve": "CVE-2011-1669",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "affects": "< 2.0.10",
            "description": "Arbitrary file upload via JCE editor — unauthenticated. Allows PHP webshell upload.",
        },
        {
            "cve": "CVE-2012-1116",
            "severity": "HIGH",
            "cvss": 7.5,
            "affects": "< 2.0.14",
            "description": "Directory traversal in JCE file browser allows reading arbitrary files.",
        },
    ],
    "com_akeeba": [
        {
            "cve": "CVE-2012-6601",
            "severity": "CRITICAL",
            "cvss": 9.3,
            "affects": "< 3.3.4",
            "description": "Unauthenticated remote code execution via backup task scheduler endpoint.",
        },
    ],
    "com_k2": [
        {
            "cve": "CVE-2018-6376",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affects": "< 2.8.1",
            "description": "Arbitrary file upload via K2 component — authenticated low-privilege user sufficient.",
        },
    ],
    "com_virtuemart": [
        {
            "cve": "CVE-2015-5443",
            "severity": "HIGH",
            "cvss": 7.5,
            "affects": "< 3.0.14",
            "description": "SQL injection in VirtueMart product listing — unauthenticated.",
        },
    ],
    "com_zoo": [
        {
            "cve": "CVE-2022-26958",
            "severity": "HIGH",
            "cvss": 8.8,
            "affects": "< 3.3.7",
            "description": "Authenticated SSTI (Server-Side Template Injection) via ZOO application templates.",
        },
    ],
    "com_easyblog": [
        {
            "cve": "CVE-2022-29265",
            "severity": "HIGH",
            "cvss": 7.2,
            "affects": "< 6.0.0",
            "description": "Stored XSS via blog post content — authenticated author role sufficient.",
        },
    ],
    "com_fabrik": [
        {
            "cve": "CVE-2021-26027",
            "severity": "HIGH",
            "cvss": 7.5,
            "affects": "< 3.9.11",
            "description": "Path traversal leading to arbitrary file read — unauthenticated.",
        },
    ],
    "com_jdownloads": [
        {
            "cve": "CVE-2019-12744",
            "severity": "HIGH",
            "cvss": 8.8,
            "affects": "< 3.2.63",
            "description": "Arbitrary file upload leading to remote code execution — authenticated upload role required.",
        },
    ],
    "com_rsfirewall": [
        {
            "cve": "CVE-2023-25564",
            "severity": "MEDIUM",
            "cvss": 5.4,
            "affects": "< 3.1.12",
            "description": "Reflected XSS via firewall log viewer — authenticated admin required.",
        },
    ],
    "com_hikashop": [
        {
            "cve": "CVE-2020-13994",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affects": "< 4.0.0",
            "description": "SQL injection in HikaShop order controller — unauthenticated.",
        },
    ],
    "com_sh404sef": [
        {
            "cve": "CVE-2022-23203",
            "severity": "HIGH",
            "cvss": 7.2,
            "affects": "< 4.5.7",
            "description": "Open redirect via misconfigured URL rewriting — may aid phishing.",
        },
    ],
    "com_joomgallery": [
        {
            "cve": "CVE-2021-35370",
            "severity": "HIGH",
            "cvss": 8.1,
            "affects": "< 3.4.0",
            "description": "SQL injection in gallery category parameter — authenticated editor role.",
        },
    ],
    "com_redshop": [
        {
            "cve": "CVE-2019-15008",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affects": "< 1.5.0",
            "description": "Unauthenticated arbitrary file upload in redSHOP component allows PHP shell.",
        },
    ],
    "com_phocagallery": [
        {
            "cve": "CVE-2010-1476",
            "severity": "HIGH",
            "cvss": 7.5,
            "affects": "< 2.7.3",
            "description": "Directory traversal in Phoca Gallery — unauthenticated file read.",
        },
    ],
    "com_jfbconnect": [
        {
            "cve": "CVE-2022-40218",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "affects": "< 8.6.1",
            "description": "Authentication bypass via JFBConnect social login token — account takeover.",
        },
    ],
    "com_sexycontactform": [
        {
            "cve": "CVE-2012-5221",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "affects": "< 2.0",
            "description": "Arbitrary file upload (no authentication) — allows PHP webshell upload.",
        },
    ],
    "com_civicrm": [
        {
            "cve": "CVE-2023-30943",
            "severity": "HIGH",
            "cvss": 8.1,
            "affects": "< 5.60.1",
            "description": "SQL injection in CiviCRM contact search — authenticated low-privilege user.",
        },
    ],
    "com_jshopping": [
        {
            "cve": "CVE-2020-28896",
            "severity": "HIGH",
            "cvss": 7.5,
            "affects": "< 4.3.0",
            "description": "Path traversal allows reading arbitrary files via product image field.",
        },
    ],
    "com_adsmanager": [
        {
            "cve": "CVE-2016-1000149",
            "severity": "HIGH",
            "cvss": 7.5,
            "affects": "< 3.1.1",
            "description": "SQL injection in AdsManager — unauthenticated, affects ad listing queries.",
        },
    ],
}

SEVERITY_COLOUR = {
    "CRITICAL": red,
    "HIGH":     yellow,
    "MEDIUM":   cyan,
    "LOW":      dim,
}

# ─────────────────────────────────────────────────────────────────────────────
# Live CVE lookup via NIST NVD API v2  (no key required, rate-limited to 5/30s)
# Docs: https://nvd.nist.gov/developers/vulnerabilities
# ─────────────────────────────────────────────────────────────────────────────
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _nvd_severity(metrics: dict) -> tuple:
    """Extract (severity, cvss_score) from NVD metrics blob."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        bucket = metrics.get(key, [])
        if bucket:
            data = bucket[0]
            cvss = data.get("cvssData", {})
            return (
                cvss.get("baseSeverity", "UNKNOWN").upper(),
                float(cvss.get("baseScore", 0.0)),
            )
    return ("UNKNOWN", 0.0)


def nvd_search(keyword: str, max_results: int = 10,
               timeout: int = 15,
               api_key: str = None) -> list:
    """
    Query NVD for CVEs matching *keyword*.
    Returns a list of dicts compatible with CVE_DB format.
    Pass api_key for 50 req/30s instead of the default 5 req/30s.
    """
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
            "startIndex": 0,
        }
        if api_key:
            params["apiKey"] = api_key
        resp = requests.get(NVD_API, params=params, timeout=timeout)
        if resp.status_code == 403:
            if api_key:
                print(yellow("  [!] NVD key rejected or rate-limit hit."))
            else:
                print(yellow("  [!] NVD rate-limit hit (5 req/30s). Wait 30s or add --nvd-key."))
            return []
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(yellow(f"  [!] NVD API error: {e}"))
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve_obj  = item.get("cve", {})
        cve_id   = cve_obj.get("id", "UNKNOWN")
        metrics  = cve_obj.get("metrics", {})
        severity, score = _nvd_severity(metrics)

        # Description — prefer English
        descriptions = cve_obj.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        # Affected version ranges (from configurations CPE data)
        affects = "See NVD for version ranges"
        configs = cve_obj.get("configurations", [])
        ranges = []
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    start = cpe_match.get("versionStartIncluding", "")
                    end   = cpe_match.get("versionEndIncluding",
                             cpe_match.get("versionEndExcluding", ""))
                    if start or end:
                        ranges.append(f"{start or '?'} – {end or '?'}")
        if ranges:
            affects = "; ".join(ranges[:3])

        results.append({
            "cve":         cve_id,
            "severity":    severity if severity != "UNKNOWN" else "MEDIUM",
            "cvss":        score,
            "affects":     affects,
            "description": desc[:200] + ("…" if len(desc) > 200 else ""),
            "source":      "NVD (live)",
        })
    return results


def live_cve_scan(session, base_url: str, found_components: list,
                  detected_version: str, timeout: int,
                  api_key: str = None) -> dict:
    """
    Run live NVD queries for:
      - Joomla core (using detected version if available)
      - Each found component
    Returns { component_name: [cve_entries] }
    """
    print_section("Phase 5b — Live NVD CVE Lookup")
    print(dim("  Querying NIST NVD API (rate-limit: 5 requests / 30 seconds)…"))
    if api_key:
        print(dim("  API key provided — using 50 req/30s rate limit."))

    live_results = {}
    # Sleep between calls: 6s without key (5/30s), 0.7s with key (50/30s)
    sleep_between = 0.7 if api_key else 6.0

    # Core query
    core_keyword = f"joomla {detected_version}" if detected_version else "joomla cms"
    print(dim(f"  Searching: '{core_keyword}'"))
    core_cves = nvd_search(core_keyword, max_results=10, timeout=timeout, api_key=api_key)
    if core_cves:
        live_results["__core__"] = core_cves
        print(green(f"  [✓] Core: {len(core_cves)} CVE(s) found"))
        print_cves(core_cves, indent="    ")
    else:
        print(dim("  No live core CVEs returned."))

    # Per-component queries (rate-limited — sleep between calls)
    for comp in found_components:
        name = comp["name"]
        # Strip "com_" prefix for a cleaner search term
        keyword = f"joomla {name.replace('com_', '')}"
        print(dim(f"  Searching: '{keyword}'"))
        time.sleep(sleep_between)
        cves = nvd_search(keyword, max_results=5, timeout=timeout, api_key=api_key)
        if cves:
            live_results[name] = cves
            print(green(f"  [✓] {name}: {len(cves)} CVE(s)"))
            print_cves(cves, indent="    ")
        else:
            print(dim(f"  [-] {name}: no results"))

    return live_results


# ─────────────────────────────────────────────────────────────────────────────
# Brute-force engine
# ─────────────────────────────────────────────────────────────────────────────
class BruteResult:
    """Carries the outcome of a single credential attempt."""
    __slots__ = ("username", "password", "success", "locked_out")

    def __init__(self, username: str, password: str,
                 success: bool = False, locked_out: bool = False):
        self.username   = username
        self.password   = password
        self.success    = success
        self.locked_out = locked_out


def _get_csrf_token(session: requests.Session, admin_url: str,
                    timeout: int) -> Optional[str]:
    """
    Fetch the Joomla admin login page and extract the CSRF token.
    Joomla embeds a hidden input whose *name* is the token (value=1).
    Returns the token name string, or None on failure.
    """
    try:
        resp = session.get(admin_url, timeout=timeout)
        soup = BeautifulSoup(resp.text, "html.parser")
        # Joomla's CSRF token: last hidden input, 32-char hex name, value="1"
        hidden = soup.find_all("input", type="hidden")
        for inp in reversed(hidden):
            name = inp.get("name", "")
            val  = inp.get("value", "")
            if re.fullmatch(r"[0-9a-f]{32}", name) and val == "1":
                return name
        # Fallback: last hidden input
        if hidden:
            return hidden[-1].get("name")
    except Exception:
        pass
    return None


def _detect_lockout(html: str) -> bool:
    """
    Heuristic check for account lockout / CAPTCHA responses.
    Returns True if the response strongly suggests a lockout.
    """
    indicators = [
        "too many login attempts",
        "account has been blocked",
        "please wait",
        "captcha",
        "locked out",
        "your account is blocked",
    ]
    lower = html.lower()
    return any(phrase in lower for phrase in indicators)


def _is_login_failure(soup: BeautifulSoup) -> bool:
    """Return True if the page contains a Joomla login error alert."""
    # Joomla 3.x / 4.x error containers
    for cls in ("alert-error", "alert-danger", "alert-message", "error"):
        if soup.find(class_=cls):
            return True
    # Generic: check for "Invalid" in alerts
    alerts = soup.find_all("div", class_=re.compile(r"alert"))
    for a in alerts:
        if "invalid" in a.get_text().lower():
            return True
    return False


def _try_credential(session: requests.Session, admin_url: str,
                    username: str, password: str,
                    timeout: int, verbose: bool) -> BruteResult:
    """
    Attempt a single Joomla admin login.
    Fetches a fresh CSRF token each time (Joomla rotates them).
    """
    token = _get_csrf_token(session, admin_url, timeout)
    if not token:
        # Can't proceed without a token — transient error
        if verbose:
            print(dim(f"    [?] CSRF fetch failed for {username}:{password} — skipping"))
        return BruteResult(username, password)

    data = {
        "username": username,
        "passwd":   password,
        "option":   "com_login",
        "task":     "login",
        "return":   "aW5kZXgucGhw",
        token:      "1",
    }

    try:
        resp = session.post(admin_url, data=data, timeout=timeout,
                            allow_redirects=True)
    except Exception:
        return BruteResult(username, password)

    if _detect_lockout(resp.text):
        return BruteResult(username, password, locked_out=True)

    soup    = BeautifulSoup(resp.text, "html.parser")
    failure = _is_login_failure(soup)

    # Success signals: redirected to /administrator/index.php with no error,
    # or the page title changed away from "Log in"
    title = (soup.title.string or "") if soup.title else ""
    logged_in = (
        not failure
        and "log in" not in title.lower()
        and resp.url.rstrip("/").endswith("administrator")
    )

    return BruteResult(username, password, success=logged_in)


def run_brute(args, session: requests.Session) -> list:
    """
    Phase 5 — Credential brute-force.

    Features:
      - Streams wordlist (doesn't load into RAM)
      - Threaded (--brute-threads, default 1 for stealth)
      - Lockout detection with automatic pause
      - Stops per-user on first success
      - Supports single username or username list
      - Verbose mode shows failures
    """
    admin_url  = normalize_url(args.url) + "administrator/"
    timeout    = args.timeout
    verbose    = args.verbose
    found_creds: list = []
    stop_event = threading.Event()

    # Build username list
    if args.userlist:
        try:
            with open(args.userlist, "r", errors="ignore") as f:
                usernames = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            print(red(f"  [✗] Username list not found: {args.userlist}"))
            return []
    elif args.username:
        usernames = [args.username]
    else:
        print(yellow("  [!] No username provided (use -usr or -U)"))
        return []

    # Verify wordlist exists
    if not os.path.exists(args.wordlist):
        print(red(f"  [✗] Wordlist not found: {args.wordlist}"))
        return []

    lock           = threading.Lock()
    lockout_until  = [0.0]   # shared mutable: epoch time to resume after lockout

    def attempt(username: str, password: str) -> Optional[BruteResult]:
        if stop_event.is_set():
            return None

        # Honour lockout pause
        wait = lockout_until[0] - time.monotonic()
        if wait > 0:
            time.sleep(wait)

        result = _try_credential(session, admin_url, username,
                                 password, timeout, verbose)

        if result.locked_out:
            pause = args.lockout_pause
            with lock:
                lockout_until[0] = time.monotonic() + pause
            print(yellow(f"\n  [!] Lockout detected for '{username}' — pausing {pause}s"))
            time.sleep(pause)
            return None

        if result.success:
            with lock:
                found_creds.append(result)
            stop_event.set()   # signal outer loop to stop after this user
            print(green(f"\n  [✓] VALID CREDENTIAL: {bold(username)}:{bold(password)}"))
        elif verbose:
            print(dim(f"  [-] {username}:{password}"))

        return result

    print(dim(f"  Admin URL  : {admin_url}"))
    print(dim(f"  Usernames  : {len(usernames)}"))
    print(dim(f"  Wordlist   : {args.wordlist}"))
    print(dim(f"  Threads    : {args.brute_threads}  |  Delay: {args.brute_delay}s"))
    print()

    for username in usernames:
        if stop_event.is_set():
            break
        user_found = threading.Event()
        print(cyan(f"  [»] Trying username: {bold(username)}"))

        with ThreadPoolExecutor(max_workers=args.brute_threads) as ex:
            futures = {}

            def _stream_passwords():
                with open(args.wordlist, "r", errors="ignore") as wf:
                    for line in wf:
                        pw = line.rstrip("\n\r")
                        if pw and not user_found.is_set():
                            if args.brute_delay > 0:
                                time.sleep(args.brute_delay)
                            yield pw

            # FIX: check stop/found events BEFORE each submit so we don't
            # flood the thread pool with millions of futures for large wordlists.
            for pw in _stream_passwords():
                if user_found.is_set() or stop_event.is_set():
                    break
                fut = ex.submit(attempt, username, pw)
                futures[fut] = pw

            for fut in as_completed(futures):
                res = fut.result()
                if res and res.success:
                    user_found.set()
                    break

    return found_creds

BANNER = f"""
{C.MAGENTA}{C.BOLD}
   ██╗ ██████╗  ██████╗ ███╗   ███╗██╗      █████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
   ██║██╔═══██╗██╔═══██╗████╗ ████║██║     ██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
   ██║██║   ██║██║   ██║██╔████╔██║██║     ███████║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██ ██║██║   ██║██║   ██║██║╚██╔╝██║██║     ██╔══██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚█████╔╝╚██████╔╝╚██████╔╝██║ ╚═╝ ██║███████╗██║  ██║    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.RESET}
{C.CYAN} Joomla Vulnerability Scanner v{VERSION}{C.RESET}
{C.DIM}  by arya_pokharel{C.RESET}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Interesting URLs
# ─────────────────────────────────────────────────────────────────────────────
INTERESTING_URLS = [
    ("joomla.xml",                                          "Default Joomla changelog"),
    ("administrator/manifests/files/joomla.xml",            "Detailed version information"),
    ("administrator/",                                      "Admin login panel"),
    ("libraries/simplepie/README.txt",                      "SimplePie README (version leak)"),
    ("LICENSE.txt",                                         "License file"),
    ("plugins/system/cache/cache.xml",                      "Version attribute in cache plugin XML"),
    ("configuration.php",                                   "Configuration file (should be 403/blank)"),
    ("configuration.php.bak",                               "Configuration backup (critical!)"),
    ("robots.txt",                                          "Robots.txt"),
    ("error_log",                                           "PHP error log (info disclosure)"),
    ("web.config.txt",                                      "IIS web.config sample"),
    ("htaccess.txt",                                        ".htaccess sample"),
    ("README.txt",                                          "Joomla README"),
    ("administrator/components/com_joomlaupdate/",          "Joomla Update component"),
    ("administrator/index.php",                             "Admin panel index"),
    ("tmp/",                                                "Temp directory (may be browsable)"),
    ("cache/",                                              "Cache directory (may be browsable)"),
    ("logs/",                                               "Logs directory (may be browsable)"),
    ("images/",                                             "Images directory"),
    ("components/",                                         "Components directory"),
    ("modules/",                                            "Modules directory"),
    ("plugins/",                                            "Plugins directory"),
    ("templates/",                                          "Templates directory"),
    ("libraries/",                                          "Libraries directory"),
    ("includes/",                                           "Includes directory"),
    ("language/",                                           "Language directory"),
    ("media/",                                              "Media directory"),
    ("api/",                                                "Joomla 4.x API endpoint"),
]

COMPONENT_SUBFILES = [
    ("README.txt",    "README"),
    ("readme.txt",    "README"),
    ("README.md",     "README"),
    ("readme.md",     "README"),
    ("LICENSE.txt",   "LICENSE"),
    ("license.txt",   "LICENSE"),
    ("CHANGELOG.txt", "CHANGELOG"),
    ("changelog.txt", "CHANGELOG"),
    ("MANIFEST.xml",  "MANIFEST"),
    ("manifest.xml",  "MANIFEST"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Rate limiter
# ─────────────────────────────────────────────────────────────────────────────
class RateLimiter:
    """Token-bucket rate limiter — thread-safe."""

    def __init__(self, rps: float):
        self._min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def acquire(self):
        if self._min_interval == 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()


# ─────────────────────────────────────────────────────────────────────────────
# Thread-safe atomic counter (replaces done[0] mutable-list hack)
# ─────────────────────────────────────────────────────────────────────────────
class AtomicCounter:
    def __init__(self):
        self._val = 0
        self._lock = threading.Lock()

    def increment(self) -> int:
        with self._lock:
            self._val += 1
            return self._val

    @property
    def value(self) -> int:
        with self._lock:
            return self._val


# ─────────────────────────────────────────────────────────────────────────────
# Timer-based progress display (no per-future flicker)
# ─────────────────────────────────────────────────────────────────────────────
class ProgressBar:
    """Redraws at a fixed interval from a background thread."""

    def __init__(self, total: int, label: str = "Scanning", interval: float = 0.25):
        self._total = total
        self._label = label
        self._interval = interval
        self._counter = AtomicCounter()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def tick(self) -> int:
        return self._counter.increment()

    def stop(self):
        self._stop.set()
        self._thread.join()
        # Clear the progress line
        print(f"\r{' ' * 80}\r", end="", flush=True)

    def _run(self):
        while not self._stop.is_set():
            self._redraw()
            self._stop.wait(self._interval)
        self._redraw()  # final draw

    def _redraw(self):
        done = self._counter.value
        pct  = done * 100 // self._total if self._total else 0
        bar_w = 30
        filled = bar_w * done // self._total if self._total else 0
        bar = "█" * filled + "░" * (bar_w - filled)
        print(f"\r  {dim(self._label)} [{cyan(bar)}] {done}/{self._total} ({pct}%)   ",
              end="", flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url):
        url = "http://" + url
    if "?" in url:
        url = url.split("?")[0]
    # Strip any trailing slashes then add exactly one — prevents double-slash
    url = url.rstrip("/") + "/"
    return url


def make_session(args) -> requests.Session:
    """Build a requests.Session from CLI args (UA, proxy, cookies, headers)."""
    s = requests.Session()
    s.headers["User-Agent"] = args.user_agent
    s.verify = False

    # Proxy support
    if args.proxy:
        proxy_url = args.proxy
        if not re.match(r"^https?://", proxy_url):
            proxy_url = "http://" + proxy_url
        s.proxies = {"http": proxy_url, "https": proxy_url}
        print(dim(f"  [proxy] Routing through: {proxy_url}"))

    # Cookie support
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                s.cookies.set(k.strip(), v.strip())

    # Extra headers
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                s.headers[k.strip()] = v.strip()

    adapter = requests.adapters.HTTPAdapter(pool_maxsize=200)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


_ua_index = 0
_ua_lock  = threading.Lock()

def _next_ua() -> str:
    global _ua_index
    with _ua_lock:
        ua = USER_AGENTS[_ua_index % len(USER_AGENTS)]
        _ua_index += 1
        return ua


def _request(method: str, session: requests.Session, url: str, timeout: int,
             rate_limiter: RateLimiter, rotate_ua: bool,
             retries: int = 3, backoff: float = 1.5):
    """
    Unified HTTP request with:
      - rate limiting
      - optional UA rotation
      - retry with exponential back-off on transient failures
      - WAF detection (429 / 503) with automatic slow-down
    """
    rate_limiter.acquire()
    fn = session.head if method == "HEAD" else session.get

    for attempt in range(retries):
        try:
            kwargs = {"timeout": timeout, "allow_redirects": True}
            if rotate_ua:
                kwargs["headers"] = {"User-Agent": _next_ua()}
            resp = fn(url, **kwargs)

            # WAF / rate-limit signal — back off and retry
            if resp.status_code in (429, 503):
                retry_after = int(resp.headers.get("Retry-After", backoff * (attempt + 1)))
                time.sleep(min(retry_after, 30))
                continue

            return resp
        except requests.exceptions.ConnectionError:
            time.sleep(backoff * (attempt + 1))
        except requests.exceptions.Timeout:
            time.sleep(backoff * (attempt + 1))
        except Exception:
            break
    return None


def head(session, url, timeout, rl, rotate_ua):
    return _request("HEAD", session, url, timeout, rl, rotate_ua)


def get(session, url, timeout, rl, rotate_ua):
    return _request("GET", session, url, timeout, rl, rotate_ua)


def md5_content(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


def is_index_of(html: str) -> bool:
    try:
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.string if soup.title else ""
        return bool(title and "Index of" in title)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Fake-200 detection (droopescan feature)
# Servers that return 200 for *every* URL make component detection unreliable.
# We probe a known-nonexistent path; if it returns 200 with similar content
# length to a known-good file, we warn and switch to content-based detection.
# ─────────────────────────────────────────────────────────────────────────────
NOT_FOUND_PROBE   = "misc/test/error/404/joomla_recon_probe_a1b2c3.html"
KNOWN_GOOD_FILE   = "media/system/js/validate.js"   # always present on Joomla
FAKE_200_THRESHOLD = 25   # byte-length difference below which we consider it fake

def detect_fake_200(session, base_url: str, timeout: int,
                    rl: "RateLimiter", rotate_ua: bool) -> bool:
    """
    Returns True if the server appears to return 200 for all URLs (soft-404).
    Also prints a warning so the user knows detection may be unreliable.
    """
    probe_url = base_url + NOT_FOUND_PROBE
    good_url  = base_url + KNOWN_GOOD_FILE

    probe_resp = get(session, probe_url, timeout, rl, rotate_ua)
    good_resp  = get(session, good_url,  timeout, rl, rotate_ua)

    if probe_resp is None or good_resp is None:
        return False

    if probe_resp.status_code != 200:
        return False   # normal 404 behaviour

    # Both returned 200 — check if content lengths are similar
    probe_len = len(probe_resp.content)
    good_len  = len(good_resp.content)
    diff      = abs(probe_len - good_len)

    if diff <= FAKE_200_THRESHOLD:
        print(yellow(
            "  [!] WARNING: Server returns HTTP 200 for non-existent URLs (soft-404 / catch-all).\n"
            "      Component detection may produce false positives.\n"
            "      Consider verifying findings manually or using --no-components."
        ))
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Redirect following — determine the real base URL after redirects
# ─────────────────────────────────────────────────────────────────────────────
def follow_redirect(session, url: str, timeout: int) -> str:
    """
    Follow HTTP redirects and return the final base URL (with trailing slash).
    Handles double-redirects (HTTP→HTTPS, www→non-www, etc.).
    """
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        final = resp.url
        # Strip path back to root
        parsed = urlparse(final)
        base = f"{parsed.scheme}://{parsed.netloc}/"
        if base != url:
            print(cyan(f"  [→] Redirect followed: {url} → {base}"))
        return base
    except Exception:
        return url


def print_section(title: str):
    width = 70
    print(f"\n{C.BOLD}{C.BLUE}{'─' * width}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}{'─' * width}{C.RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# CVE lookup
# ─────────────────────────────────────────────────────────────────────────────
def lookup_cves(component_name: str) -> list:
    """Return CVE entries for a component name (case-insensitive key lookup)."""
    key = component_name.lower()
    return CVE_DB.get(key, [])


def print_cves(cves: list, indent: str = "      "):
    for entry in cves:
        sev   = entry["severity"]
        cfn   = SEVERITY_COLOUR.get(sev, cyan)
        cvss  = f"CVSS {entry['cvss']:.1f}" if entry.get("cvss") else ""
        label = cfn(f"[{sev}]") + (f" {dim(cvss)}" if cvss else "")
        print(f"{indent}⚠  {label} {bold(entry['cve'])}  (affects {entry['affects']})")
        print(f"{indent}   {dim(entry['description'])}")


# ─────────────────────────────────────────────────────────────────────────────
# Version fingerprinting — vote-based (replaces brittle intersection)
# ─────────────────────────────────────────────────────────────────────────────
def load_versions_db(xml_path: str) -> dict:
    """Returns: { file_url: [(md5, version_nb), ...], ... }"""
    db = {}
    if not os.path.exists(xml_path):
        return db
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for file_elem in root.findall(".//file"):
            file_url = file_elem.get("url")
            entries  = [(ver.get("md5"), ver.get("nb")) for ver in file_elem.findall("version")]
            db[file_url] = entries
    except Exception as e:
        print(yellow(f"  [!] Could not parse versions.xml: {e}"))
    return db


def fingerprint_version(session, base_url, versions_db, threads, timeout,
                         rl, rotate_ua,
                         min_votes: int = 1) -> list:
    """
    Vote-based version detection.

    For each file in the DB that returns HTTP 200:
      - compute its MD5
      - award a vote to every version whose expected MD5 matches

    Returns the top candidates sorted by vote count (descending), then
    numerically (descending).  Versions with fewer than min_votes are excluded.

    This is far more resilient than pure intersection: a single modified or
    missing file no longer wipes out all results.
    """
    votes: Counter = Counter()
    files_checked = 0

    def check_file(file_url, entries):
        full_url = base_url + file_url
        resp = get(session, full_url, timeout, rl, rotate_ua)
        if resp is None or resp.status_code != 200:
            return {}
        digest = md5_content(resp.content)
        return {nb: 1 for (md5, nb) in entries if md5 == digest}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check_file, fu, entries): fu
                   for fu, entries in versions_db.items()}
        for future in as_completed(futures):
            result = future.result()
            files_checked += 1
            votes.update(result)

    if not votes:
        return []


    def ver_key(item):
        ver, count = item
        parts = re.split(r"[.\-]", re.sub(r"[^0-9.\-]", "", ver))
        numeric = [int(p) if p.isdigit() else 0 for p in parts]
        # primary sort: vote count desc; secondary: version number desc
        return (-count, [-x for x in numeric])

    candidates = [(v, c) for v, c in votes.items() if c >= min_votes]
    candidates.sort(key=ver_key)

    return candidates   # list of (version_string, vote_count)


# ─────────────────────────────────────────────────────────────────────────────
# Interesting URL scan
# ─────────────────────────────────────────────────────────────────────────────
# Extra sensitive paths not in the original droopescan list
EXTRA_SENSITIVE_PATHS = [
    ("configuration.php~",                  "Config backup (tilde) — may expose DB credentials!"),
    ("configuration.php.bak",               "Config backup (.bak) — may expose DB credentials!"),
    ("configuration.php.old",               "Config backup (.old) — may expose DB credentials!"),
    ("configuration.php.save",              "Config backup (.save) — may expose DB credentials!"),
    (".git/HEAD",                           "Exposed .git repository — source code disclosure!"),
    (".git/config",                         "Exposed .git config — may contain remote URLs/tokens"),
    ("administrator/components/com_joomlaupdate/restore.php", "Joomla restore script (should not be accessible)"),
    ("administrator/logs/",                 "Admin logs directory"),
    ("cli/",                                "Joomla CLI directory"),
]

ALL_INTERESTING_URLS = INTERESTING_URLS + EXTRA_SENSITIVE_PATHS


def scan_interesting_urls(session, base_url, timeout, rl, rotate_ua) -> list:
    found = []
    for path, description in ALL_INTERESTING_URLS:
        full_url = base_url + path
        # Use GET not HEAD — some servers / WAFs treat them differently,
        # and interesting URLs should follow redirects to catch HTTPS redirects.
        resp = get(session, full_url, timeout, rl, rotate_ua)
        if resp is not None and resp.status_code in (200, 301, 302, 403):
            found.append({
                "url":         full_url,
                "final_url":   resp.url,          # URL after any redirects
                "status":      resp.status_code,
                "description": description,
            })
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Component scanning
# ─────────────────────────────────────────────────────────────────────────────
def load_components(db_path: str) -> list:
    if not os.path.exists(db_path):
        return []
    with open(db_path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def _parse_component_version(xml_content: str) -> Optional[str]:
    """
    Extract <version> from a Joomla component XML manifest.
    Returns the version string or None if not found.
    """
    try:
        root = ET.fromstring(xml_content)
        ver_elem = root.find(".//version")
        if ver_elem is not None and ver_elem.text:
            return ver_elem.text.strip()
    except Exception:
        pass
    return None


def check_component(session, base_url, component, timeout, rl, rotate_ua,
                    fake_200: bool = False) -> Optional[dict]:
    paths = [
        (f"index.php?option={component}", "active"),
        (f"components/{component}/",      "inactive/protected"),
        (f"administrator/components/{component}/", "admin-side"),
    ]

    for path, status_label in paths:
        full_url = base_url + path
        resp = head(session, full_url, timeout, rl, rotate_ua)
        if resp is None:
            continue
        if resp.status_code == 200:
            result = {
                "name":       component,
                "url":        full_url,
                "status":     status_label,
                "subfiles":   [],
                "explorable": [],
                "cves":       lookup_cves(component),
                "version":    None,
            }

            # Sub-file checks (README, LICENSE, CHANGELOG, MANIFEST)
            for subfile, subfile_type in COMPONENT_SUBFILES:
                for prefix in [f"components/{component}/",
                                f"administrator/components/{component}/"]:
                    sub_url = base_url + prefix + subfile
                    sr = head(session, sub_url, timeout, rl, rotate_ua)
                    if sr is not None and sr.status_code == 200:
                        result["subfiles"].append({"type": subfile_type, "url": sub_url})

            # Index file check — only flag if content-length > 1000 bytes
            # (avoids false positives from blank index.html placeholder files)
            for dir_path in [f"components/{component}/",
                              f"administrator/components/{component}/"]:
                for idx in ("index.htm", "index.html", "INDEX.htm", "INDEX.html"):
                    idx_url = base_url + dir_path + idx
                    ir = get(session, idx_url, timeout, rl, rotate_ua)
                    if ir is not None and ir.status_code == 200 and len(ir.content) > 1000:
                        result["subfiles"].append({"type": "INDEX", "url": idx_url})

            # Directory listing detection
            for dir_path in [f"components/{component}/",
                              f"administrator/components/{component}/"]:
                dir_url = base_url + dir_path
                gr = get(session, dir_url, timeout, rl, rotate_ua)
                if gr is not None and gr.status_code == 200 and is_index_of(gr.text):
                    result["explorable"].append(dir_url)

            # Component XML manifest — try to extract version
            comp_short = component.replace("com_", "", 1)
            for xml_path in [
                f"components/{component}/{comp_short}.xml",
                f"administrator/components/{component}/{comp_short}.xml",
                f"administrator/components/{component}/{component}.xml",
            ]:
                xml_url = base_url + xml_path
                xr = get(session, xml_url, timeout, rl, rotate_ua)
                if xr is not None and xr.status_code == 200:
                    ver = _parse_component_version(xr.text)
                    if ver:
                        result["version"] = ver
                        result["subfiles"].append({"type": "MANIFEST (version: " + ver + ")", "url": xml_url})
                        break

            return result

    return None


def scan_components(session, base_url, components, threads, timeout,
                    rl, rotate_ua, fake_200: bool = False) -> list:
    found = []
    lock  = threading.Lock()
    total = len(components)
    bar   = ProgressBar(total, label="Component scan").start()

    def worker(component):
        result = check_component(session, base_url, component, timeout, rl, rotate_ua, fake_200)
        bar.tick()
        return result

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(worker, c) for c in components]
        for future in as_completed(futures):
            result = future.result()
            if result:
                with lock:
                    found.append(result)

    bar.stop()
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Main scan orchestrator
# ─────────────────────────────────────────────────────────────────────────────
def run_scan(args):
    base_url = normalize_url(args.url)
    session  = make_session(args)
    threads  = args.threads
    timeout  = args.timeout
    rotate   = args.rotate_ua

    # Build rate limiter
    rps = args.rate_limit if args.rate_limit > 0 else float("inf")
    rl  = RateLimiter(rps)

    if args.delay > 0:
        # Wrap rl with a fixed delay on top
        orig_acquire = rl.acquire
        def delayed_acquire():
            orig_acquire()
            time.sleep(args.delay)
        rl.acquire = delayed_acquire

    results = {
        "target":           base_url,
        "version":          [],
        "interesting_urls": [],
        "components":       [],
        "core_cves":        CVE_DB.get("__core__", []),
    }

    # ── Connectivity check + redirect following ────────────────────────────
    print_section("Target Connectivity")
    resp = head(session, base_url, timeout, rl, rotate)
    if resp is None:
        print(red(f"  [✗] Cannot reach {base_url} — check the URL and try again."))
        sys.exit(1)

    # Follow redirects to get the real base URL (handles HTTP→HTTPS, www→non-www)
    if not args.no_redirect_follow:
        base_url = follow_redirect(session, base_url, timeout)
        results["target"] = base_url

    server  = resp.headers.get("Server", "Unknown")
    powered = resp.headers.get("X-Powered-By", "")
    waf_hints = []
    for h in ("X-Sucuri-ID", "X-Firewall", "X-CDN", "CF-RAY", "X-Cache"):
        if h in resp.headers:
            waf_hints.append(f"{h}: {resp.headers[h]}")
    print(green(f"  [✓] Target is UP  →  {base_url}"))
    print(dim(f"      Server: {server}") + (f"  |  X-Powered-By: {powered}" if powered else ""))
    if waf_hints:
        print(yellow(f"  [!] WAF/CDN indicators: {', '.join(waf_hints)}"))
        if not args.rotate_ua:
            print(dim("      Tip: add --rotate-ua to rotate User-Agents and reduce fingerprinting."))

    # ── Fake-200 detection ─────────────────────────────────────────────────
    fake_200 = detect_fake_200(session, base_url, timeout, rl, rotate)

    # ── Phase 1: Quick recon ───────────────────────────────────────────────
    print_section("Phase 1 — Quick Recon")
    quick_checks = [
        ("robots.txt",  "robots.txt"),
        ("error_log",   "PHP error_log"),
        ("sitemap.xml", "sitemap.xml"),
    ]
    for path, label in quick_checks:
        r = head(session, base_url + path, timeout, rl, rotate)
        if r and r.status_code == 200:
            print(f"  {yellow('[+]')} {bold(label)}: {base_url + path}")
        else:
            print(dim(f"  [-] {label}: not found"))

    # ── Phase 2: Version fingerprinting ───────────────────────────────────
    if not args.no_version:
        print_section("Phase 2 — Version Fingerprinting (MD5 vote-based)")
        versions_db = load_versions_db(VERSIONS_XML)
        if not versions_db:
            print(yellow("  [!] versions.xml not found — skipping version detection"))
        else:
            print(dim(f"  Loaded {len(versions_db)} fingerprint files  |  {threads} threads"))
            candidates = fingerprint_version(
                session, base_url, versions_db, threads, timeout, rl, rotate
            )
            if candidates:
                results["version"] = [v for v, _ in candidates]
                top_ver, top_votes = candidates[0]
                print(green(f"  [✓] Most likely version: {bold(top_ver)}  ({top_votes} matching file(s))"))
                if len(candidates) > 1:
                    others = ", ".join(
                        f"{v} ({c})" for v, c in candidates[1:6]
                    )
                    print(dim(f"      Other candidates: {others}"))
                    if len(candidates) > 6:
                        print(dim(f"      … and {len(candidates) - 6} more"))

                # Core CVE advisory based on detected version
                print(f"\n  {bold('Core CVE advisory')} (verify version ranges manually):")
                print_cves(CVE_DB.get("__core__", []), indent="    ")
            else:
                print(yellow("  [?] Could not determine version (files may be modified or absent)"))
    else:
        print_section("Phase 2 — Version Fingerprinting")
        print(dim("  Skipped (--no-version)"))

    # ── Phase 3: Interesting URLs ──────────────────────────────────────────
    print_section("Phase 3 — Interesting URL Detection")
    interesting = scan_interesting_urls(session, base_url, timeout, rl, rotate)
    results["interesting_urls"] = interesting
    if interesting:
        for item in interesting:
            status  = item["status"]
            is_crit = "backup" in item["description"].lower() or "critical" in item["description"].lower()
            is_admin = "admin" in item["url"].lower()
            colour  = red if (status == 200 and (is_admin or is_crit)) else \
                      yellow if status == 403 else cyan
            print(f"  {colour(f'[{status}]')} {item['url']}")
            print(dim(f"       └─ {item['description']}"))
    else:
        print(dim("  No interesting URLs found."))

    # ── Phase 4: Component enumeration ────────────────────────────────────
    if not args.no_components:
        print_section(f"Phase 4 — Component Enumeration ({threads} threads)")
        components = load_components(COMPONENTS_DB)
        if not components:
            print(yellow("  [!] comptotestdb.txt not found — skipping component scan"))
        else:
            print(dim(f"  Scanning {len(components)} known Joomla components..."))
            found_components = scan_components(
                session, base_url, components, threads, timeout, rl, rotate,
                fake_200=fake_200
            )
            results["components"] = found_components

            if found_components:
                for comp in sorted(found_components, key=lambda x: x["name"]):
                    sc = green if comp["status"] == "active" else yellow
                    print(f"\n  {sc('[+]')} {bold(comp['name'])}  ({comp['status']})")
                    print(f"      {comp['url']}")

                    if comp.get("version"):
                        print(cyan(f"      ├─ Version detected: {bold(comp['version'])}"))

                    for sf in comp["subfiles"]:
                        print(yellow(f"      ├─ {sf['type']}: {sf['url']}"))

                    for exp in comp["explorable"]:
                        print(red(f"      └─ EXPLORABLE DIRECTORY: {exp}"))

                    if comp["cves"]:
                        print(f"      {bold('CVEs')}:")
                        print_cves(comp["cves"], indent="        ")
            else:
                print(dim("  No known components found."))
    else:
        print_section("Phase 4 — Component Enumeration")
        print(dim("  Skipped (--no-components)"))

    # ── Phase 5: Brute-force login ─────────────────────────────────────────
    brute_creds = []
    if args.brute:
        print_section("Phase 5 — Brute-Force Login")
        if not args.wordlist:
            print(red("  [✗] --brute requires -w / --wordlist"))
        elif not (args.username or args.userlist):
            print(red("  [✗] --brute requires -usr / --username or -U / --userlist"))
        else:
            brute_creds = run_brute(args, session)
            if not brute_creds:
                print(yellow("\n  [-] No valid credentials found."))
    else:
        print_section("Phase 5 — Brute-Force Login")
        print(dim("  Skipped (add --brute -usr <user> -w <wordlist> to enable)"))

    results["credentials"] = [
        {"username": c.username, "password": c.password}
        for c in brute_creds
    ]

    # ── Phase 5b: Live NVD CVE lookup ─────────────────────────────────────
    live_cves = {}
    if args.live_cve:
        detected_ver = results["version"][0] if results["version"] else ""
        live_cves = live_cve_scan(
            session, base_url,
            results["components"],
            detected_ver,
            timeout,
            api_key=args.nvd_key,
        )
        results["live_cves"] = live_cves
    else:
        print_section("Phase 5b — Live NVD CVE Lookup")
        print(dim("  Skipped (add --live-cve to query NIST NVD in real time)"))

    # ── Summary ───────────────────────────────────────────────────────────
    print_section("Scan Summary")
    ver_str = results["version"][0] if results["version"] else "Unknown"
    print(f"  {bold('Target')}          : {base_url}")
    print(f"  {bold('Version')}         : {green(ver_str) if results['version'] else yellow('Unknown')}")
    print(f"  {bold('Interesting URLs')}: {len(results['interesting_urls'])} found")
    print(f"  {bold('Components')}      : {len(results['components'])} found")

    active     = [c for c in results["components"] if c["status"] == "active"]
    explorable = [c for c in results["components"] if c["explorable"]]
    vuln_comps = [c for c in results["components"] if c.get("cves")]
    if active:
        print(f"  {bold('Active components')}: {green(str(len(active)))}")
    if explorable:
        print(f"  {red(bold('Explorable dirs'))} : {red(str(len(explorable)))} (directory listing!)")
    if vuln_comps:
        print(f"  {red(bold('Components w/ CVEs'))}: {red(str(len(vuln_comps)))}")
    if brute_creds:
        print(f"  {red(bold('Valid credentials'))} : {red(str(len(brute_creds)))} found!")
        for c in brute_creds:
            print(f"    {green('»')} {bold(c.username)}:{bold(c.password)}")
    if live_cves:
        total_live = sum(len(v) for v in live_cves.values())
        print(f"  {bold('Live CVEs (NVD)')}   : {red(str(total_live))} fetched")

    # ── JSON output ───────────────────────────────────────────────────────
    if args.output == "json":
        out_file = args.output_file or "joomla_recon_results.json"
        with open(out_file, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n  {green('[✓]')} JSON results saved to: {bold(out_file)}")
    elif args.output == "stdout-json":
        print("\n" + json.dumps(results, indent=2))

    print(f"\n{C.DIM}  Scan complete.{C.RESET}\n")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        prog="joomla_recon.py",
        description="Unified Joomla Vulnerability Scanner + Brute-force + Live CVE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 joomla_recon.py -u https://target.com
  python3 joomla_recon.py -u https://target.com -t 30 --timeout 10
  python3 joomla_recon.py -u https://target.com --proxy http://127.0.0.1:8080
  python3 joomla_recon.py -u https://target.com --cookie "PHPSESSID=abc; logged_in=yes"
  python3 joomla_recon.py -u https://target.com --header "X-Custom: value" --header "Auth: token"
  python3 joomla_recon.py -u https://target.com --rate-limit 5 --delay 0.2 --rotate-ua
  python3 joomla_recon.py -u https://target.com --output json --output-file results.json
  python3 joomla_recon.py -u https://target.com --no-components --no-version

  # Brute-force (single user)
  python3 joomla_recon.py -u https://target.com --brute -usr admin -w rockyou.txt
  # Brute-force (user list, 3 threads, 0.5s delay, pause 120s on lockout)
  python3 joomla_recon.py -u https://target.com --brute -U users.txt -w passwords.txt \\
      --brute-threads 3 --brute-delay 0.5 --lockout-pause 120 -vv

  # Live NVD CVE lookup (requires internet access)
  python3 joomla_recon.py -u https://target.com --live-cve

  # Full combo: scan + brute + live CVE + JSON output
  python3 joomla_recon.py -u https://target.com --brute -usr admin -w rockyou.txt \\
      --live-cve --output json --output-file report.json
        """
    )

    # ── Core ────────────────────────────────────────────────────────────────
    parser.add_argument("-u", "--url",      required=True,
                        help="Target Joomla URL")
    parser.add_argument("-t", "--threads",  type=int, default=10,
                        help="Concurrent threads for recon phases (default: 10)")
    parser.add_argument("--timeout",        type=int, default=8,
                        help="HTTP timeout in seconds (default: 8)")
    parser.add_argument("--user-agent",
                        default=USER_AGENTS[0],
                        help="Base User-Agent string")
    parser.add_argument("-vv", "--verbose", action="store_true",
                        help="Show failed login attempts during brute-force")

    # ── Proxy / Auth (recon) ────────────────────────────────────────────────
    auth = parser.add_argument_group("Proxy / Session")
    auth.add_argument("--proxy",
                      help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    auth.add_argument("--cookie",
                      help="Cookie string (e.g. 'PHPSESSID=abc; token=xyz')")
    auth.add_argument("--header", action="append", metavar="HEADER",
                      help="Extra HTTP header 'Name: value' (repeatable)")

    # ── WAF evasion / rate limiting ─────────────────────────────────────────
    waf = parser.add_argument_group("WAF Evasion / Rate Limiting")
    waf.add_argument("--rate-limit", type=float, default=0, metavar="RPS",
                     help="Max requests/sec for recon phases (0 = unlimited)")
    waf.add_argument("--delay", type=float, default=0, metavar="SECONDS",
                     help="Fixed delay between recon requests (default: 0)")
    waf.add_argument("--rotate-ua", action="store_true",
                     help="Rotate User-Agent per request from built-in pool")

    # ── Brute-force ─────────────────────────────────────────────────────────
    brute = parser.add_argument_group("Brute-Force Login (Phase 5)")
    brute.add_argument("--brute", action="store_true",
                       help="Enable brute-force login phase")
    brute.add_argument("-w", "--wordlist", default=None,
                       help="Path to password wordlist file")
    brute_creds = brute.add_mutually_exclusive_group()
    brute_creds.add_argument("-usr", "--username", default=None,
                              help="Single username to try")
    brute_creds.add_argument("-U", "--userlist", default=None,
                              help="Path to username list file")
    brute.add_argument("--brute-threads", type=int, default=1,
                       help="Threads for brute-force (default: 1 — stealth)")
    brute.add_argument("--brute-delay", type=float, default=0.0,
                       help="Delay between login attempts in seconds (default: 0)")
    brute.add_argument("--lockout-pause", type=float, default=60.0,
                       help="Seconds to pause when lockout detected (default: 60)")

    # ── Live CVE ────────────────────────────────────────────────────────────
    cve = parser.add_argument_group("Live CVE Lookup (Phase 5b)")
    cve.add_argument("--live-cve", action="store_true",
                     help="Query NIST NVD API for live CVEs (requires internet)")
    cve.add_argument("--nvd-key", default=None,
                     help="NVD API key to bypass rate-limit (50 req/30s vs 5/30s)")

    # ── Output ──────────────────────────────────────────────────────────────
    out = parser.add_argument_group("Output")
    out.add_argument("--output", choices=["text", "json", "stdout-json"],
                     default="text",
                     help="Output format: text (default), json (file), stdout-json")
    out.add_argument("--output-file", default=None,
                     help="File for JSON output (default: joomla_recon_results.json)")

    # ── Skip phases ─────────────────────────────────────────────────────────
    skip = parser.add_argument_group("Skip Recon Phases")
    skip.add_argument("--no-components", action="store_true",
                      help="Skip component enumeration")
    skip.add_argument("--no-version",    action="store_true",
                      help="Skip version fingerprinting")
    skip.add_argument("--no-redirect-follow", action="store_true",
                      help="Do not follow HTTP redirects to determine final base URL")


    parser.add_argument("--version", action="version",
                        version=f"joomla_recon.py {VERSION}")
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    print(BANNER)
    args = parse_args()

    parsed = urlparse(args.url if "://" in args.url else "http://" + args.url)
    if not parsed.netloc:
        print(red("[✗] Invalid URL."))
        sys.exit(1)

    if not os.path.exists(COMPONENTS_DB):
        print(yellow(f"[!] Component database not found at: {COMPONENTS_DB}"))
    if not os.path.exists(VERSIONS_XML):
        print(yellow(f"[!] versions.xml not found at: {VERSIONS_XML}"))

    # Brute-force sanity checks (early, before network calls)
    if args.brute:
        if not args.wordlist:
            print(red("[✗] --brute requires -w / --wordlist"))
            sys.exit(1)
        if not (args.username or args.userlist):
            print(red("[✗] --brute requires -usr / --username or -U / --userlist"))
            sys.exit(1)

    start = time.time()
    run_scan(args)
    elapsed = time.time() - start
    print(dim(f"  Total time: {elapsed:.1f}s\n"))


if __name__ == "__main__":
    main()
