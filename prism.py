#!/usr/bin/env python3
"""
prism.py -- Daily Intelligence Aggregator

Pulls from grouped RSS feeds and threat intel APIs, scores items by
relevance to your stack, filters noise, and writes a self-contained HTML
digest. No external fonts, CDN calls, or third-party JS.

Groups (configured in prism_config.json):
  threat_intel -- security research, advisories, exploits, vendor blogs
  news         -- trusted news sources with exclusion and country filtering
  government   -- official government cyber and national security publications

Usage:
    python prism.py                          # run digest, auto-versioned html
    python prism.py -v                       # verbose: show every accepted item
    python prism.py --output json            # json for automation
    python prism.py --output data-json       # write prism_data.json (GitHub Pages mode)
    python prism.py --min-score 5            # high/critical only
    python prism.py --lookback 48            # look back 48 hours
    python prism.py --no-cache               # ignore dedup cache this run
    python prism.py --no-fetch-cache         # bypass URL fetch cache
    python prism.py --check-feeds            # test all feeds, write feeds_check.json
    python prism.py --check-feeds --group threat_intel
    python prism.py --set-key otx            # store OTX API key in OS keychain
    python prism.py --show-keys              # show which keys are configured

Dependencies:
    pip install feedparser requests keyring
    Linux headless: pip install keyrings.alt

Secrets:
    API keys stored in OS keychain only -- never in files.
    Windows  -- Windows Credential Manager
    macOS    -- macOS Keychain
    Linux    -- GNOME Keyring (secretstorage) or file backend (keyrings.alt)

External files (must sit alongside this script):
    prism_config.json  -- all configuration: groups, feeds, keywords, settings
    template.html      -- chosen template variant (copy one of the three variants)

    # SECURITY: Neither file contains secrets. Safe to commit to Git.

Changes from v012 -> v013:
  - CRITICAL BUG FIX: _parse_feed_entries used safe_get(entry.__dict__, "link")
    to extract article URLs. feedparser exposes .link via __getattr__ (not __dict__),
    so this silently returned "" for 635/720 items -- all cards rendered as plain
    text with no clickable link. Fixed to getattr(entry, "link", "").
  - Fallback URL: when a feed entry has no article URL (some feeds omit it, e.g.
    oss-security digest items), the card now falls back to the feed's publication
    homepage (derived from the feed URL origin) so every card is always clickable.
    Stored as item["url"] = display_url (article or homepage fallback).
    item["article_url"] stores the raw article link (empty if absent).
  - index.html: card-head is wrapped in <a class="card-head-link"> block link
    when item.url is available (always true after this fix). Title is a <span>
    (not a nested <a>) to avoid invalid HTML and browser click-event conflicts.
  - Data patch: existing 2026-03-29.json patched manually with source homepage
    fallback URLs for the 635 items that had empty URL fields.

Changes from v011 -> v012:
  - max_items raised: default cap lifted from 200 to 500 per group. 200 was
    too restrictive across 86+ feeds -- high-volume feeds like NVD (528 entries)
    were silently truncating useful items. Users should use --min-score to filter
    signal rather than relying on a hard item cap.
  - Data directory clarification: data/YYYY-MM-DD.json IS the day cache -- the
    persistent processed record for each run. prism_cache/ remains the raw HTTP
    fetch cache (URL -> bytes). Added --from-day-file flag to re-process a
    specific day file without re-fetching any feeds.
  - Source trust tier: each item now carries a source_tier field (1-4) derived
    from the feed's trust_tier config key. index.html uses this to sort the
    related-sources dropdown on each card.

Changes from v010 -> v011:
  - Template error fix: build_html() now raises SystemExit with a clear actionable
    message instead of FileNotFoundError when template.html is missing. Directs
    user to --output data-json as the correct mode for the Pages architecture.
  - Multi-day data storage: --output data-json now writes data/YYYY-MM-DD.json
    (one file per day) and data/index.json (manifest of available dates + per-day
    stats). index.html loads index.json first, then fetches the selected day file.
    History is kept up to MAX_HISTORY (30) days. Files are written atomically.
  - Trend detection: detect_trends() cross-references today's items against up to
    TREND_WINDOW (7) prior days in data/. Items whose matched keywords appeared in
    2+ consecutive prior days are tagged as trending (item["trending"]=True,
    item["trend_days"]=N). Score boost: +2 per trend day, capped at +6. Trending
    items re-sort after boost so they surface above non-trending items of the
    same base score. Trend signal also mines CVEs for cross-day correlation.
  - build_data_json() renamed to build_json_legacy() intent -- kept as the
    --output json handler. write_day_and_index() is the new data-json writer.
  - Source link fix: src-name <a> tags in cards and sidebar source directory now
    include target="_blank" so source links open in a new tab rather than
    navigating away from the digest. (template.html updated in tandem.)
  - News auto-categorisation: new classify_news_item() function applies
    config-driven news_categories rules (from prism_config.json) to assign
    meaningful categories (incident, vulnerability, threat-actor, policy, ai,
    geopolitical, industry) to news items based on title+summary content.
    Falls back to "news" if no rule matches. Rules are evaluated in order;
    first match wins.
  - News scoring: news_categories rules in config now include keyword weights
    for LOW/MEDIUM/HIGH/CRITICAL scoring. News items previously all scored 0.
  - CAT_COLOURS: added colour mappings for all 7 news sub-categories so they
    render with distinct badge colours in the HTML output.
  - Carried forward from v009: cache-only lookback anchor, age-dropped counter,
    RotatingFileHandler, fetch_cached (bytes|None, datetime|None) return type.

Author: [your name]
Version: 1.0
"""

import argparse
import getpass
import hashlib
import json
import logging
import logging.handlers
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path

# -- Third-party dependency imports -------------------------------------------
try:
    import feedparser
except ImportError:
    raise SystemExit("Missing: feedparser -- run: pip install feedparser")

try:
    import requests
except ImportError:
    raise SystemExit("Missing: requests -- run: pip install requests")

try:
    import keyring
except ImportError:
    raise SystemExit(
        "Missing: keyring -- run: pip install keyring\n"
        "Linux headless: pip install keyrings.alt"
    )

# -- Logging: screen + rotating file -----------------------------------------
# Log file is always prism.log alongside the script -- no version number.
# RotatingFileHandler: 5 MB per file, 3 backups (prism.log.1, .2, .3).
# Replaces the previous mode='w' overwrite -- history is now preserved.
# SECURITY: Path derived from __file__ -- never from user input.
_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
_LOG_FILE   = Path(__file__).parent / "prism.log"

_root = logging.getLogger()
_root.setLevel(logging.INFO)

_console = logging.StreamHandler()
_console.setFormatter(logging.Formatter(_LOG_FORMAT))
_root.addHandler(_console)

_fh = logging.handlers.RotatingFileHandler(
    _LOG_FILE,
    maxBytes=5 * 1024 * 1024,  # 5 MB per file
    backupCount=3,
    encoding="utf-8",
)
_fh.setFormatter(logging.Formatter(_LOG_FORMAT))
_root.addHandler(_fh)

log = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================

SCRIPT_DIR       = Path(__file__).parent
CONFIG_FILE      = SCRIPT_DIR / "prism_config.json"
TEMPLATE_FILE    = SCRIPT_DIR / "template.html"
DEDUP_CACHE_FILE = SCRIPT_DIR / "prism_seen.json"  # anchored to script dir, not cwd

KEYCHAIN_SERVICE = "prism"
API_KEY_NAMES: list[str] = [
    "otx",   # AlienVault OTX -- https://otx.alienvault.com (free account)
]

OTX_PULSE_URL       = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20&modified_since={since}"
RANSOMWARE_LIVE_URL = "https://api.ransomware.live/recentvictims"

# SECURITY: https:// only. Rejects file://, ftp://, data: etc.
ALLOWED_SCHEMES = {"https"}

# SECURITY: Browser-like User-Agent to avoid soft-blocks.
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

# Pre-compiled URL validation pattern
_URL_RE = re.compile(r"^https://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")

# Category colours for HTML output
CAT_COLOURS: dict[str, str] = {
    "advisory":     "#e63946",
    "exploit":      "#ff6b35",
    "research":     "#4361ee",
    "intel":        "#7209b7",
    "vendor":       "#3a86ff",
    "detection":    "#06d6a0",
    "ransomware":   "#f72585",
    "news":         "#adb5bd",
    "government":   "#f4a261",
    "ioc":          "#9d4edd",
    # News sub-categories (auto-classified)
    "incident":     "#e63946",   # red -- same urgency as advisory
    "vulnerability": "#ff6b35",  # orange
    "threat-actor": "#7209b7",   # purple
    "policy":       "#f4a261",   # amber -- same family as government
    "ai":           "#00b4d8",   # cyan
    "geopolitical": "#e9c46a",   # gold
    "industry":     "#adb5bd",   # muted -- low urgency business news
}

# Clickbait pattern cache -- built once from config on first use
_CLICKBAIT_RE: re.Pattern | None = None


# =============================================================================
# INPUT VALIDATION & SANITISATION
# =============================================================================

def validate_url(url: str) -> bool:  # returns True if URL is safe to fetch
    """
    Validate a URL before fetching.
    Requires https://, rejects other schemes, enforces length limit.
    SECURITY: Pre-flight check -- TLS verification in requests() provides
    actual transport security.
    """
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if len(url) > 2048:
        return False
    scheme = url.split("://")[0].lower() if "://" in url else ""
    if scheme not in ALLOWED_SCHEMES:
        return False
    return bool(_URL_RE.match(url))


def sanitise(value: str, max_len: int = 500) -> str:  # returns clean ASCII-safe string
    """
    Sanitise a string from external data before storage or display.
    Strips control characters (log injection prevention) and enforces max length.
    SECURITY: All external feed content passes through here.
    """
    if not isinstance(value, str):
        return ""
    # Strip control characters that are log injection vectors or cause display issues.
    # Allowed: \x09 (tab), \x0a (LF newline) -- legitimate in text content.
    # Stripped: \x0d (CR) -- log injection: overwrites terminal lines;
    #           \x00-\x08 low controls; \x0b \x0c vertical controls;
    #           \x0e-\x1f remaining C0 controls; \x7f (DEL).
    # SECURITY: \x0d was missing from the original range [\x00-\x08\x0b\x0c\x0e-\x1f]
    #           because \x0c-\x0e skipped it. Now listed explicitly.
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0d\x0e-\x1f\x7f]", "", value)
    return cleaned.strip()[:max_len]


def safe_get(data: dict, key: str, default: str = "") -> str:  # returns string or default
    """Null-safe dict access that always returns a string."""
    val = data.get(key)
    if val is None:
        return default
    return str(val).strip() or default


def _escape(text: str) -> str:  # returns HTML-escaped string
    """
    Escape characters that break HTML or enable XSS injection.
    SECURITY: Called on every external string before HTML insertion (OWASP A03).
    """
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


# =============================================================================
# SECRETS -- OS keychain (cross-platform)
# =============================================================================
# Backends:
#   Windows  -- Windows Credential Manager (built-in)
#   macOS    -- macOS Keychain (built-in)
#   Linux    -- GNOME Keyring via secretstorage, or file via keyrings.alt
#
# First-time setup (run once per machine):
#   python prism.py --set-key otx
#
# Manual equivalent:
#   python -c "import keyring; keyring.set_password('prism', 'otx', 'KEY')"
#
# Remove a key:
#   python -c "import keyring; keyring.delete_password('prism', 'otx')"
# =============================================================================

def get_api_key(name: str) -> str:  # returns key string or empty string
    """
    Retrieve an API key from the OS keychain.
    Returns empty string if not set -- callers must check before using.
    SECURITY: Key values are never logged -- only presence/absence.
    """
    if name not in API_KEY_NAMES:
        log.warning(f"Unknown API key name: '{name}' -- skipping")
        return ""
    try:
        value = keyring.get_password(KEYCHAIN_SERVICE, name) or ""
        log.debug(f"API key '{name}': {'found' if value else 'not configured'}")
        return value
    except keyring.errors.KeyringError as e:
        log.warning(f"Keychain error for '{name}': {type(e).__name__} -- skipping")
        return ""


def set_api_key(name: str) -> None:  # returns None -- stores key in keychain
    """
    Prompt for an API key and store it in the OS keychain.
    SECURITY: Uses getpass -- key never echoed to terminal or shell history.
    """
    if name not in API_KEY_NAMES:
        raise SystemExit(f"Unknown key name: '{name}'. Valid: {API_KEY_NAMES}")

    sources = {"otx": "https://otx.alienvault.com -> Settings -> API Integration"}
    print(f"\nStoring API key '{name}' (service: {KEYCHAIN_SERVICE})")
    print(f"Get your key at: {sources.get(name, 'see provider docs')}")
    print("Input is hidden -- will not appear on screen.")

    try:
        value = getpass.getpass("Key: ").strip()
    except KeyboardInterrupt:
        print("\nCancelled.")
        return

    if len(value) < 8:
        raise SystemExit("Key too short (min 8 chars). Aborting.")

    try:
        keyring.set_password(KEYCHAIN_SERVICE, name, value)
        print(f"[OK] Key '{name}' stored in OS keychain ({type(keyring.get_keyring()).__name__})")
    except keyring.errors.KeyringError as e:
        raise SystemExit(
            f"Failed to store key: {e}\n"
            "Linux headless: run 'pip install keyrings.alt' for file backend."
        )


def show_keys() -> None:  # returns None -- prints status to stdout
    """Print configured/not-configured status for all known API keys."""
    print(f"\nAPI key status (service: {KEYCHAIN_SERVICE})")
    print(f"Backend: {type(keyring.get_keyring()).__name__}\n")
    for name in API_KEY_NAMES:
        try:
            value  = keyring.get_password(KEYCHAIN_SERVICE, name) or ""
            status = "[OK] configured" if value else "[FAIL] not set"
        except keyring.errors.KeyringError:
            status = "[FAIL] keychain error"
        print(f"  {name:<20} {status}")
    print()


# =============================================================================
# CONFIG LOADING
# =============================================================================

def load_config() -> dict:  # returns validated config dict
    """
    Load and validate prism_config.json.
    Returns the full config dict with validated groups.
    Raises SystemExit on missing file or invalid structure.
    SECURITY: Path resolved relative to SCRIPT_DIR -- prevents path traversal.
    """
    resolved = CONFIG_FILE.resolve()
    if not resolved.is_relative_to(SCRIPT_DIR.resolve()):
        raise SystemExit(f"Config path outside script directory: {resolved}")

    if not CONFIG_FILE.exists():
        raise FileNotFoundError(
            f"Config not found: {CONFIG_FILE}\n"
            "prism_config.json must sit alongside prism.py"
        )

    try:
        config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(f"Config is not valid JSON: {e}")

    # SECURITY: Validate structure before accessing nested keys.
    if not isinstance(config, dict):
        raise SystemExit("Config root must be a JSON object")
    if "data" not in config or "groups" not in config.get("data", {}):
        raise SystemExit("Config missing data.groups")

    groups = config["data"]["groups"]
    if not isinstance(groups, dict) or not groups:
        raise SystemExit("data.groups must be a non-empty object")

    settings = config.get("settings", {})

    # Validate each group's feeds -- drop invalid URLs silently with a warning
    for group_name, group in groups.items():
        if not isinstance(group, dict):
            continue
        raw_feeds = group.get("feeds", [])
        valid: list[dict] = []
        for i, feed in enumerate(raw_feeds):
            if not isinstance(feed, dict):
                continue
            name = sanitise(safe_get(feed, "name", f"{group_name}_feed_{i}"), 100)
            url  = safe_get(feed, "url", "")
            if not validate_url(url):
                log.warning(f"[{group_name}] feed '{name}' invalid URL -- skipped: {url[:60]}")
                continue
            valid.append({
                "name":        name,
                "url":         url,
                "category":    sanitise(safe_get(feed, "category", group_name), 50),
                "country_tag": sanitise(safe_get(feed, "country_tag", ""), 10).upper(),
                "note":        sanitise(safe_get(feed, "note", ""), 200),
                # trust_tier: 1=primary (gov/CERT/authoritative vendor), 2=established research,
                # 3=general security blog, 4=news/commentary. Default 3.
                # Used in index.html to sort the per-card related-sources dropdown.
                "trust_tier":  max(1, min(4, int(feed.get("trust_tier", 3)))),
            })
        group["feeds"] = valid

    # Validate keyword weights for threat_intel group
    ti = groups.get("threat_intel", {})
    raw_kw = ti.get("keywords", {})
    if isinstance(raw_kw, dict):
        valid_kw: dict[str, int] = {}
        for kw, w in raw_kw.items():
            if not isinstance(kw, str) or not kw:
                continue
            if not isinstance(w, int) or not (1 <= w <= 10):
                log.warning(f"Keyword '{kw}' weight {w!r} invalid -- skipped")
                continue
            valid_kw[sanitise(kw, 100)] = w
        ti["keywords"] = valid_kw

    meta = config.get("meta", {})
    total_feeds = sum(len(g.get("feeds", [])) for g in groups.values())
    log.info(
        f"Config v{safe_get(meta, 'version', '?')} loaded -- "
        f"{len(groups)} groups, {total_feeds} feeds"
    )
    return config


# =============================================================================
# FETCH CACHE
# URL-level cache -- prevents re-fetching the same URL within TTL window.
# Separate from dedup cache (prism_seen.json) which tracks item hashes.
#
# Storage: prism_cache/<url_hash>.json
# Each entry: {"fetched_at": ISO timestamp, "content_b64": base64 bytes}
# =============================================================================

import base64

def _cache_dir(settings: dict) -> Path:  # returns resolved cache directory Path
    """Return the fetch cache directory, creating it if needed."""
    cache_path = SCRIPT_DIR / sanitise(
        settings.get("fetch_cache_dir", "prism_cache"), 80  # default matches config
    )
    # SECURITY: Resolve and confirm it stays within SCRIPT_DIR.
    resolved = cache_path.resolve()
    if not resolved.is_relative_to(SCRIPT_DIR.resolve()):
        raise SystemExit(f"fetch_cache_dir outside script directory: {resolved}")
    resolved.mkdir(exist_ok=True)
    return resolved


def _cache_key(url: str) -> str:  # returns 16-char hex string
    """SHA-256 prefix of URL -- used as the cache filename."""
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def fetch_cached(
    url: str,
    settings: dict,
    bypass: bool = False,
    cache_only: bool = False,
) -> tuple[bytes | None, datetime | None]:  # returns (content, fetched_at) -- fetched_at is None on network fetch or failure
    """
    Fetch a URL, returning cached bytes if the TTL has not expired.

    Cache layout: prism_cache/<url_hash>.json
    Each file stores fetch timestamp and base64-encoded response content.

    bypass=True     -- skip the cache, always hit the network (--no-fetch-cache)
    cache_only=True -- never hit the network; return cached bytes or None.
                       TTL is ignored -- any cached entry is returned regardless
                       of age. Use this to process existing data without making
                       any outbound requests (--cache-only / --cache-only-group).

    Return value: (content, fetched_at)
      content    -- raw response bytes, or None on failure/miss
      fetched_at -- datetime the content was originally fetched (from cache entry),
                    or None when content comes fresh from the network or on failure.
                    Callers use this to anchor the lookback cutoff: in cache-only
                    mode the content may be hours/days old and using now() as the
                    reference clock causes all items to appear stale.

    SECURITY: URL validated before fetch. TLS verified. Content capped at 10 MB.
    """
    # SECURITY: Validate URL before any network or filesystem operation.
    if not validate_url(url):
        log.warning(f"fetch_cached: invalid URL rejected: {url[:80]}")
        return None, None

    ttl     = int(settings.get("fetch_cache_ttl_seconds", 3600))
    timeout = int(settings.get("feed_timeout_seconds", 5))
    cache   = _cache_dir(settings)
    key     = _cache_key(url)
    entry   = cache / f"{key}.json"

    # -- Cache-only mode: return whatever is cached, no network fallback -------
    if cache_only:
        # In verbose mode, log the exact file path being checked so location
        # issues are immediately diagnosable without guessing.
        log.debug(f"Cache-only check: {entry}")
        if entry.exists():
            try:
                data       = json.loads(entry.read_text(encoding="utf-8"))
                fetched_at = datetime.fromisoformat(data["fetched_at"])
                age        = (datetime.now(timezone.utc) - fetched_at).total_seconds()
                log.debug(f"Cache-only HIT ({int(age)}s old): {url[:60]}")
                return base64.b64decode(data["content_b64"]), fetched_at
            except (json.JSONDecodeError, KeyError, ValueError, Exception) as e:
                log.debug(f"Cache-only: corrupt entry ({e}): {url[:60]}")
        else:
            log.debug(f"Cache-only MISS (no file): {entry}")
        return None, None

    # -- Try cache first (unless bypass requested) ----------------------------
    if not bypass and entry.exists():
        try:
            data       = json.loads(entry.read_text(encoding="utf-8"))
            fetched_at = datetime.fromisoformat(data["fetched_at"])
            age        = (datetime.now(timezone.utc) - fetched_at).total_seconds()
            if age < ttl:
                log.debug(f"Cache HIT ({int(age)}s old): {url[:60]}")
                return base64.b64decode(data["content_b64"]), fetched_at
            log.debug(f"Cache STALE ({int(age)}s > {ttl}s): {url[:60]}")
        except (json.JSONDecodeError, KeyError, ValueError, Exception) as e:
            log.debug(f"Cache entry corrupt ({e}) -- re-fetching: {url[:60]}")

    # -- Fetch from network ---------------------------------------------------
    log.debug(f"Cache MISS -- fetching: {url[:60]}")
    try:
        resp = requests.get(
            url,
            headers=REQUEST_HEADERS,
            timeout=timeout,
            allow_redirects=True,
            verify=True,  # SECURITY: Always verify TLS -- never verify=False
        )
        resp.raise_for_status()

        # SECURITY: Cap content size before caching or parsing.
        content    = resp.content[:10 * 1024 * 1024]  # 10 MB hard cap
        fetched_at = datetime.now(timezone.utc)        # record fetch time for cache entry

        # -- Write to cache (atomic: write .tmp then rename) ------------------
        tmp = entry.with_suffix(".tmp")
        try:
            tmp.write_text(
                json.dumps({
                    "fetched_at":  fetched_at.isoformat(),
                    "url":         url,
                    "content_b64": base64.b64encode(content).decode(),
                }),
                encoding="utf-8",
            )
            tmp.replace(entry)
        except OSError as e:
            log.debug(f"Cache write failed ({e}) -- continuing without cache")
            if tmp.exists():
                tmp.unlink(missing_ok=True)

        # Network fetch: return None for fetched_at -- caller uses now() as reference
        return content, None

    except requests.exceptions.Timeout:
        log.warning(f"Timeout ({timeout}s): {url[:70]}")
    except requests.exceptions.SSLError:
        log.warning(f"TLS error: {url[:70]}")
    except requests.exceptions.HTTPError as e:
        # Extract status code cleanly rather than logging the full requests exception
        # which includes the URL a second time and creates duplicate noise in the log.
        code = e.response.status_code if e.response is not None else "?"
        log.warning(f"HTTP {code}: {url[:70]}")
    except Exception as e:
        log.error(f"Fetch failed ({sanitise(str(e)[:80], 80)}): {url[:70]}")

    return None, None


# =============================================================================
# DEDUPLICATION CACHE
# Tracks which *items* (by title+url hash) have already been processed.
# Separate from the fetch cache which tracks which *URLs* were hit.
# =============================================================================

def load_dedup() -> set[str]:  # returns set of previously seen item hashes
    """Load item hashes from prism_seen.json. Returns empty set on error."""
    if DEDUP_CACHE_FILE.exists():
        try:
            data = json.loads(DEDUP_CACHE_FILE.read_text(encoding="utf-8"))
            seen = data.get("seen", [])
            if not isinstance(seen, list):
                raise ValueError("seen is not a list")
            return {s for s in seen if isinstance(s, str) and len(s) == 12}
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            log.warning(f"Dedup cache invalid ({e}) -- starting fresh")
    return set()


def save_dedup(seen: set[str]) -> None:  # returns None -- writes to disk atomically
    """Save item hashes. Caps at 10000 entries. Atomic write."""
    limited = list(seen)[-10000:]
    tmp = DEDUP_CACHE_FILE.with_suffix(".tmp")
    try:
        tmp.write_text(
            json.dumps({"seen": limited, "updated": datetime.now().isoformat()}),
            encoding="utf-8",
        )
        tmp.replace(DEDUP_CACHE_FILE)
    except OSError as e:
        log.error(f"Failed to save dedup cache: {e}")
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def make_hash(title: str, url: str) -> str:  # returns 12-char hex string
    """Short MD5 hash of title+url -- used for deduplication only."""
    raw = f"{title.lower().strip()}{url.lower().strip()}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


# =============================================================================
# RELEVANCE SCORING
# =============================================================================

def score_item(
    title: str,
    summary: str,
    keywords: dict[str, int],
) -> tuple[int, list[str]]:  # returns (score, matched_keyword_list)
    """
    Score an item against the group's keyword weights.
    Higher score = more relevant to the configured stack.
    """
    text    = (title + " " + summary).lower()
    score   = 0
    matched: list[str] = []
    for kw, weight in keywords.items():
        if kw.lower() in text:
            score += weight
            matched.append(kw)
    return score, matched


# =============================================================================
# CLICKBAIT FILTER (news group)
# =============================================================================

def _build_clickbait_re(phrases: list[str]) -> "re.Pattern[str]":  # returns compiled Pattern
    """Compile clickbait phrase list into a single regex. Cached at module level."""
    escaped = [re.escape(p.lower()) for p in phrases if isinstance(p, str) and p]
    return re.compile("|".join(escaped)) if escaped else re.compile(r"(?!)")


def is_clickbait(
    title: str,
    summary: str,
    news_cfg: dict,
) -> tuple[bool, str]:  # returns (filtered_out, reason)
    """
    Apply clickbait heuristics to a news article.
    Returns (True, reason) if the article should be dropped.
    """
    global _CLICKBAIT_RE

    phrases = news_cfg.get("clickbait_phrases", [])
    if _CLICKBAIT_RE is None:
        _CLICKBAIT_RE = _build_clickbait_re(phrases)

    max_title   = int(news_cfg.get("max_title_length",  120))
    min_summary = int(news_cfg.get("min_summary_length",  30))
    title_lower = title.lower()

    if len(title) > max_title:
        return True, f"title too long ({len(title)} > {max_title})"
    if _CLICKBAIT_RE.search(title_lower):
        m = _CLICKBAIT_RE.search(title_lower).group(0)
        return True, f"clickbait phrase: '{m}'"
    if title.rstrip().endswith("?"):
        return True, "rhetorical question title"
    if title.count("!") >= 2:
        return True, "2+ exclamation marks"
    if summary and len(summary.strip()) < min_summary:
        return True, f"summary too short ({len(summary.strip())} < {min_summary})"

    return False, ""


def is_excluded_category(title: str, summary: str, exclusions: list[str]) -> bool:  # returns True if excluded
    """
    Check whether a news article matches an excluded category keyword.
    Operates on title + summary combined, case-insensitive.
    """
    text = (title + " " + summary).lower()
    return any(ex.lower() in text for ex in exclusions if isinstance(ex, str))


def classify_news_item(title: str, summary: str, rules: list[dict]) -> str:  # returns category string
    """
    Auto-classify a news item against the news_categories rules from config.

    Rules are evaluated in order; the first matching rule wins.
    Each rule is: {"category": str, "keywords": [str, ...]}
    Matching is substring, case-insensitive, on title + summary combined.
    Falls back to "news" if no rule matches.

    This allows category assignment to be config-driven without changing the script.
    The category string is used for the card colour badge and category filter.
    """
    if not isinstance(rules, list):
        return "news"
    text = (title + " " + summary).lower()
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        kws = rule.get("keywords", [])
        if not isinstance(kws, list):
            continue
        if any(isinstance(kw, str) and kw.lower() in text for kw in kws):
            return sanitise(rule.get("category", "news"), 50)
    return "news"


# =============================================================================
# FEED FETCHING (per group)
# =============================================================================

def _parse_feed_entries(
    content: bytes,
    feed_meta: dict,
    lookback_hours: int,
    seen: set[str],
    keywords: dict[str, int],
    group_name: str,
    extra_filter=None,           # callable(title, summary) -> (bool, str) | None
    reference_time: datetime | None = None,  # anchor for lookback cutoff
) -> tuple[list[dict], int]:  # returns (accepted_items, filtered_count)
    """
    Parse raw feed bytes and return normalised, filtered items.
    extra_filter is called for optional per-group filtering (e.g. clickbait).

    reference_time -- when provided (cache-only mode), the lookback cutoff is
    calculated as reference_time - lookback_hours rather than now() - lookback_hours.
    This prevents all items appearing stale when replaying a cache entry that was
    populated hours or days before the current run.
    When None (live fetch), now() is used as the reference -- no behaviour change.
    """
    name          = feed_meta["name"]
    url           = feed_meta["url"]
    category      = feed_meta.get("category", group_name)
    country       = feed_meta.get("country_tag", "")
    source_tier   = int(feed_meta.get("trust_tier", 3))  # 1=authoritative .. 4=commentary
    # Derive the publication homepage from the feed URL (origin only: scheme + host).
    # Used as a fallback article URL when feedparser returns no link for an entry,
    # so cards always have something clickable rather than rendering as plain text.
    feed_origin   = "/".join(url.split("/")[:3]) if url.startswith("https://") else ""

    # Anchor the lookback cutoff to the cache entry's fetch time when available.
    # Using now() in cache-only mode causes items to appear stale even though
    # they were fresh when the cache was populated.
    ref      = reference_time if reference_time is not None else datetime.now(timezone.utc)
    cutoff   = ref - timedelta(hours=lookback_hours)

    items:      list[dict] = []
    filtered:   int        = 0
    age_dropped: int       = 0   # entries dropped because pub_date < cutoff

    parsed = feedparser.parse(content)
    if parsed.bozo and not parsed.entries:
        log.warning(f"[{group_name}] Malformed or empty: {name} -- {url[:80]}")
        return items, filtered

    for entry in parsed.entries:
        # -- Parse date -------------------------------------------------------
        pub_date = None
        for attr in ("published_parsed", "updated_parsed"):
            val = getattr(entry, attr, None)
            if val:
                try:
                    pub_date = datetime(*val[:6], tzinfo=timezone.utc)
                    break
                except (TypeError, ValueError):
                    pass

        if pub_date and pub_date < cutoff:
            age_dropped += 1
            continue

        # -- Sanitise fields --------------------------------------------------
        # SECURITY: All external content sanitised before storage or display.
        title   = sanitise(getattr(entry, "title",   "") or "No title", 300)
        # BUG FIX (v013): feedparser exposes .link via __getattr__, NOT __dict__.
        # safe_get(entry.__dict__, "link") silently returned "" for 635/720 items
        # because feedparser's internal attribute resolution is not reflected in
        # __dict__. getattr() triggers feedparser's __getattr__ correctly.
        link    = sanitise(getattr(entry, "link", "") or "", 2048)
        raw_sum = getattr(entry, "summary", "") or ""
        summary = sanitise(re.sub(r"<[^>]+>", " ", raw_sum), 500)

        # SECURITY: Only store links that pass URL validation.
        if link and not validate_url(link):
            log.debug(f"Non-HTTPS link dropped in '{name}': {link[:60]}")
            link = ""

        # Fallback: if the feed entry has no article URL (some feeds omit it),
        # use the feed's homepage origin so the card is always clickable.
        # Store both so the frontend can distinguish article links from homepage links.
        article_url = link
        display_url = link if link else feed_origin

        # -- Dedup ------------------------------------------------------------
        item_hash = make_hash(title, link)
        if item_hash in seen:
            continue
        seen.add(item_hash)

        # -- Optional per-group filter ----------------------------------------
        if extra_filter is not None:
            drop, reason = extra_filter(title, summary)
            if drop:
                filtered += 1
                log.debug(f"[{group_name}] Filtered '{name}': {title[:50]} -- {reason}")
                continue

        # -- Score ------------------------------------------------------------
        item_score, matched = score_item(title, summary, keywords)

        log.debug(f"[{group_name}] +{item_score:>3} {title[:70]}")

        items.append({
            "group":        group_name,
            "source":       name,
            "source_tier":  source_tier,
            "category":     category,
            "country_tag":  country,
            "title":        title,
            "url":          display_url,   # article URL if found, else feed homepage
            "article_url":  article_url,   # empty string if no article URL in feed
            "summary":      summary,
            "date":         pub_date.strftime("%Y-%m-%d %H:%M UTC") if pub_date else "Unknown",
            "score":        item_score,
            "matched":      matched,
            "hash":         item_hash,
            "cves":         [],
            "corroborated": [],
        })

    # Log age-dropped count at DEBUG so the cause of 0-item runs is diagnosable
    # without having to add instrumentation after the fact.
    if age_dropped:
        log.debug(
            f"[{group_name}] '{name}': {age_dropped} entries dropped (older than "
            f"{lookback_hours}h, cutoff {cutoff.strftime('%Y-%m-%d %H:%M UTC')})"
        )

    return items, filtered


def fetch_group(
    group_name: str,
    group_cfg: dict,
    lookback_hours: int,
    seen: set[str],
    settings: dict,
    bypass_fetch_cache: bool = False,
    cache_only: bool = False,
) -> list[dict]:  # returns list of item dicts for this group
    """
    Fetch all feeds in a group and return normalised, filtered items.
    Handles per-group filtering logic (clickbait for news, etc.).
    """
    if not group_cfg.get("enabled", True):
        log.info(f"[{group_name}] Disabled -- skipping")
        return []

    feeds    = group_cfg.get("feeds", [])
    keywords = group_cfg.get("keywords", {})
    if not isinstance(keywords, dict):
        keywords = {}

    # Build per-group extra filter
    extra_filter = None
    news_category_rules: list[dict] = []   # populated below for news group only
    if group_name == "news":
        exclusions = group_cfg.get("exclusion_categories", [])
        news_cfg   = {
            "clickbait_phrases":  group_cfg.get("clickbait_phrases", []),
            "max_title_length":   group_cfg.get("max_title_length",  120),
            "min_summary_length": group_cfg.get("min_summary_length", 30),
        }
        # Load category classification rules from config (empty list = no classification)
        raw_rules = group_cfg.get("news_categories", [])
        news_category_rules = raw_rules if isinstance(raw_rules, list) else []

        def extra_filter(title: str, summary: str) -> tuple[bool, str]:  # returns (drop, reason)
            # Check exclusion categories first (faster)
            if is_excluded_category(title, summary, exclusions):
                return True, "excluded category"
            return is_clickbait(title, summary, news_cfg)

    all_items: list[dict] = []
    total_filtered = 0

    log.info(f"[{group_name}] Fetching {len(feeds)} feeds...")
    for feed in feeds:
        content, fetched_at = fetch_cached(
            feed["url"], settings, bypass=bypass_fetch_cache, cache_only=cache_only
        )
        if content is None:
            continue

        items, filtered = _parse_feed_entries(
            content, feed, lookback_hours, seen, keywords, group_name, extra_filter,
            reference_time=fetched_at,  # None on live fetch -- parser uses now()
        )

        # Auto-classify news items by content rather than by feed source.
        # _parse_feed_entries uses feed_meta["category"] which is blank for news feeds.
        # classify_news_item() applies config-driven rules to title+summary.
        if news_category_rules:
            for item in items:
                item["category"] = classify_news_item(
                    item.get("title", ""), item.get("summary", ""), news_category_rules
                )

        all_items.extend(items)
        total_filtered += filtered
        time.sleep(0.1)  # polite pause -- fetch cache means most are local reads

    log.info(
        f"[{group_name}] {len(all_items)} items accepted"
        + (f", {total_filtered} filtered" if total_filtered else "")
    )
    return all_items


# =============================================================================
# THREAT INTEL EXTRAS: ransomware.live + OTX
# =============================================================================

def fetch_ransomware_live(
    lookback_hours: int,
    seen: set[str],
    keywords: dict[str, int],
    settings: dict,
    bypass_fetch_cache: bool = False,
    cache_only: bool = False,
) -> list[dict]:  # returns list of item dicts
    """Fetch recent ransomware victims from ransomware.live. No key required."""
    content, fetched_at = fetch_cached(
        RANSOMWARE_LIVE_URL, settings, bypass=bypass_fetch_cache, cache_only=cache_only
    )
    if content is None:
        return []

    items: list[dict] = []
    # Anchor cutoff to fetched_at when available (cache-only mode) so victims
    # are not dropped as stale due to the same clock-skew issue as RSS feeds.
    ref    = fetched_at if fetched_at is not None else datetime.now(timezone.utc)
    cutoff = ref - timedelta(hours=lookback_hours)

    try:
        victims = json.loads(content)
    except (ValueError, json.JSONDecodeError) as e:
        log.error(f"ransomware.live invalid JSON: {e}")
        return []

    if not isinstance(victims, list):
        log.error("ransomware.live returned unexpected structure (not a list)")
        return []

    for victim in victims:
        if not isinstance(victim, dict):
            continue

        raw_date = safe_get(victim, "discovered") or safe_get(victim, "published")
        pub_date = None
        if raw_date:
            try:
                pub_date = datetime.strptime(raw_date[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        if pub_date and pub_date < cutoff:
            continue

        group   = sanitise(safe_get(victim, "group_name",  "Unknown group"), 100)
        org     = sanitise(safe_get(victim, "victim_name") or safe_get(victim, "post_title", "Unknown victim"), 200)
        country = sanitise(safe_get(victim, "country"), 100)
        sector  = sanitise(safe_get(victim, "activity"), 100)
        website = sanitise(safe_get(victim, "website"), 200)
        desc    = sanitise(safe_get(victim, "description"), 200)

        raw_url = safe_get(victim, "url")
        if raw_url and validate_url(raw_url):
            url = raw_url
        else:
            safe_grp = re.sub(r"[^a-z0-9\-]", "", group.lower().replace(" ", "-"))
            url = f"https://www.ransomware.live/group/{safe_grp}"

        title = f"[{group}] {org}"
        if country:
            title += f" -- {country}"

        parts = []
        if sector:  parts.append(f"Sector: {sector}")
        if website: parts.append(f"Website: {website}")
        if desc:    parts.append(desc)
        summary = " | ".join(parts) if parts else "Ransomware victim post"

        item_hash = make_hash(title, url)
        if item_hash in seen:
            continue
        seen.add(item_hash)

        item_score, matched = score_item(title, summary, keywords)
        item_score = max(item_score, 3)

        items.append({
            "group":        "threat_intel",
            "source":       f"ransomware.live [{group}]",
            "category":     "ransomware",
            "country_tag":  country,
            "title":        title,
            "url":          url,
            "summary":      summary,
            "date":         pub_date.strftime("%Y-%m-%d %H:%M UTC") if pub_date else raw_date or "Unknown",
            "score":        item_score,
            "matched":      matched,
            "hash":         item_hash,
            "cves":         [],
            "corroborated": [],
        })

    log.info(f"[threat_intel] ransomware.live: {len(items)} victims")
    return items


def fetch_otx(
    api_key: str,
    lookback_hours: int,
    seen: set[str],
    keywords: dict[str, int],
    settings: dict,
) -> list[dict]:  # returns list of item dicts
    """Fetch AlienVault OTX pulses. Skips silently if key not configured."""
    if not api_key or len(api_key) < 8:
        return []

    since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).strftime("%Y-%m-%dT%H:%M:%S")
    url   = OTX_PULSE_URL.format(since=since)
    timeout = int(settings.get("feed_timeout_seconds", 5))

    items: list[dict] = []
    try:
        resp = requests.get(
            url,
            # SECURITY: Key in header only -- never in URL query string.
            headers={"X-OTX-API-KEY": api_key},
            timeout=timeout,
            verify=True,  # SECURITY: Always verify TLS.
        )
        resp.raise_for_status()

        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError) as e:
            log.error(f"OTX invalid JSON: {e}")
            return []

        for pulse in data.get("results", []) if isinstance(data, dict) else []:
            if not isinstance(pulse, dict):
                continue

            title    = sanitise(safe_get(pulse, "name", "No title"), 300)
            pulse_id = safe_get(pulse, "id", "")
            link     = f"https://otx.alienvault.com/pulse/{pulse_id}" if pulse_id else ""
            summary  = sanitise(safe_get(pulse, "description"), 400)
            tags     = ", ".join(
                sanitise(t, 50) for t in pulse.get("tags", []) if isinstance(t, str)
            )

            item_hash = make_hash(title, link)
            if item_hash in seen:
                continue
            seen.add(item_hash)

            item_score, matched = score_item(title, summary + " " + tags, keywords)

            items.append({
                "group":        "threat_intel",
                "source":       "AlienVault OTX",
                "category":     "intel",
                "country_tag":  "",
                "title":        title,
                "url":          link,
                "summary":      summary,
                "date":         safe_get(pulse, "modified", "Unknown")[:16].replace("T", " ") + " UTC",
                "score":        item_score,
                "matched":      matched,
                "hash":         item_hash,
                "cves":         [],
                "corroborated": [],
            })

        log.info(f"[threat_intel] OTX: {len(items)} pulses")

    except requests.exceptions.Timeout:
        log.warning(f"OTX timeout ({settings.get('feed_timeout_seconds', 5)}s)")
    except requests.exceptions.SSLError:
        log.warning("OTX TLS error")
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 401:
            log.error("OTX key rejected (401) -- re-run --set-key otx to update")
        else:
            log.error(f"OTX HTTP error: {e}")
    except Exception as e:
        log.error(f"OTX error: {sanitise(str(e), 150)}")

    return items


# =============================================================================
# CVE CROSS-REFERENCING
# =============================================================================

def cross_reference(items: list[dict]) -> list[dict]:
    """
    Find CVEs appearing in 2+ sources and boost their score by +3.
    Adds a 'corroborated' list per item for display in the HTML output.
    """
    cve_re = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    counts: dict[str, int] = {}

    for item in items:
        text = item.get("title", "") + " " + item.get("summary", "")
        for cve in cve_re.findall(text):
            u = cve.upper()
            counts[u] = counts.get(u, 0) + 1

    corroborated = {cve for cve, n in counts.items() if n >= 2}

    for item in items:
        text  = item.get("title", "") + " " + item.get("summary", "")
        found = list(set(c.upper() for c in cve_re.findall(text)))
        item["cves"] = found
        item.setdefault("corroborated", [])
        for cve in found:
            if cve in corroborated:
                item["score"] += 3
                if cve not in item["corroborated"]:
                    item["corroborated"].append(cve)

    if corroborated:
        log.info(f"Cross-reference: {len(corroborated)} CVEs in 2+ sources: "
                 f"{', '.join(sorted(corroborated)[:10])}")
    return items


# =============================================================================
# FEED CHECKER
# =============================================================================

def _check_one(feed: dict, timeout: int, group_name: str) -> dict:  # returns result dict
    """Test a single feed URL. Called from check_all_feeds via thread pool."""
    url  = feed["url"]
    name = feed["name"]
    result: dict = {
        "group": group_name, "name": name, "url": url,
        "status": "unknown", "http_code": None, "entry_count": 0, "error": None,
    }

    if not validate_url(url):
        result["status"] = "invalid_url"
        result["error"]  = "URL failed validation (must be https://)"
        return result

    try:
        resp = requests.get(url, headers=REQUEST_HEADERS, timeout=timeout,
                            allow_redirects=True, verify=True)
        result["http_code"] = resp.status_code
        if resp.status_code >= 400:
            result["status"] = "http_error"
            result["error"]  = f"HTTP {resp.status_code}"
            return result

        parsed = feedparser.parse(resp.content[:10 * 1024 * 1024])
        n = len(parsed.entries)
        result["entry_count"] = n
        if parsed.bozo and n == 0:
            result["status"] = "parse_error"
            result["error"]  = sanitise(str(parsed.bozo_exception), 120)
        elif n == 0:
            result["status"] = "empty"
            result["error"]  = "Parsed OK but 0 entries"
        else:
            result["status"] = "ok"

    except requests.exceptions.Timeout:
        result["status"] = "timeout"
        result["error"]  = f"No response within {timeout}s"
    except requests.exceptions.SSLError as e:
        result["status"] = "ssl_error"
        result["error"]  = sanitise(str(e), 120)
    except requests.exceptions.ConnectionError as e:
        result["status"] = "connection_error"
        result["error"]  = sanitise(str(e), 120)
    except Exception as e:
        result["status"] = "error"
        result["error"]  = sanitise(str(e), 120)

    return result


def check_all_feeds(config: dict, timeout: int, group_filter: str | None = None) -> None:  # returns None -- writes feeds_check.json
    """
    Test every feed in all groups concurrently (20 workers).
    Writes feeds_check.json. Upload to Claude for URL fixing.
    """
    groups = config["data"]["groups"]
    all_feeds: list[tuple[str, dict]] = []
    for gname, gcfg in groups.items():
        if group_filter and gname != group_filter:
            continue
        for feed in gcfg.get("feeds", []):
            all_feeds.append((gname, feed))

    total = len(all_feeds)
    log.info(f"Checking {total} feeds -- {timeout}s timeout, 20 workers...")

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_check_one, f, timeout, g): (g, f) for g, f in all_feeds}
        done = 0
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            done += 1
            ok = r["status"] == "ok"
            print(f"  [{done:>3}/{total}] {'[OK]  ' if ok else '[FAIL]'} "
                  f"{r['group']:<12} {r['status']:<16} {r['name']:<35} n={r['entry_count']}")

    results.sort(key=lambda r: (r["status"] == "ok", r["group"], r["name"].lower()))
    counts: dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    out = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "total": total, "timeout_s": timeout,
        "group_filter": group_filter or "all",
        "summary": counts, "results": results,
    }
    Path("feeds_check.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(f"\n{'='*60}")
    print(f"FEED CHECK COMPLETE -- {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*60}")
    for status, count in sorted(counts.items()):
        marker = "[OK]  " if status == "ok" else "[FAIL]"
        print(f"  {marker} {status:<20} {count}")
    print(f"\nResults -> feeds_check.json")


# =============================================================================
# HTML OUTPUT
# =============================================================================

def _severity(score: int) -> tuple[str, str]:  # returns (css_class, label)
    if score >= 10: return "sev-critical", "CRITICAL"
    if score >= 5:  return "sev-high",     "HIGH"
    if score >= 2:  return "sev-medium",   "MEDIUM"
    return "sev-low", "LOW"


def build_card(item: dict) -> str:  # returns HTML string for one card
    """
    Build one item card. All external strings HTML-escaped (OWASP A03).

    Data attributes on the article element support JS filtering:
      data-score       -- integer score for severity filtering
      data-cat         -- category string for category filter
      data-group       -- group name for group visibility toggle
      data-country     -- country_tag for country filter
      data-source      -- source name for the source directory
      data-source-url  -- publication homepage URL for source links

    The source homepage URL is derived from the item article URL's origin.
    This gives the source directory a useful link without needing a separate
    lookup table -- e.g. an item from bleepingcomputer.com links to
    https://www.bleepingcomputer.com.
    """
    score        = int(item.get("score", 0))
    cat          = sanitise(item.get("category", "news"), 50)
    col          = CAT_COLOURS.get(cat, "#adb5bd")
    sev_cls, sev = _severity(score)
    cves         = item.get("cves", []) if isinstance(item.get("cves"), list) else []
    corr         = item.get("corroborated", []) if isinstance(item.get("corroborated"), list) else []
    matched      = item.get("matched", []) if isinstance(item.get("matched"), list) else []
    country      = sanitise(item.get("country_tag", ""), 10)
    source       = sanitise(item.get("source", ""), 100)
    article_url  = item.get("url", "")

    # Derive the publication homepage from the article URL origin.
    # Used for the source directory link -- not fetched, just linked.
    # SECURITY: Only extract origin from validated https:// URLs.
    source_url = ""
    if article_url and validate_url(article_url):
        try:
            parts = article_url.split("/")
            # ['https:', '', 'hostname', ...]
            if len(parts) >= 3:
                source_url = "/".join(parts[:3])
        except Exception:
            source_url = ""

    # Severity threshold encoded as data-sev for JS score-badge click handler
    sev_threshold = {"sev-critical": "10", "sev-high": "5", "sev-medium": "2"}.get(sev_cls, "")

    # SECURITY: All external strings escaped before HTML insertion.
    cve_tags = "".join(
        f'<span class="{"cve-tag cve-c" if c in corr else "cve-tag"}">{_escape(c)}'
        f'{"[c]" if c in corr else ""}</span>'
        for c in cves[:5]
    )
    kw_tags = "".join(
        f'<span class="kw-tag">{_escape(k)}</span>'
        for k in matched[:6] if isinstance(k, str)
    )
    corr_banner = (
        f'<div class="corr-banner">++ Corroborated: {_escape(", ".join(corr))}</div>'
        if corr else ""
    )
    country_badge = (
        f'<span class="country-tag" data-country="{_escape(country)}">{_escape(country)}</span>'
        if country else ""
    )

    # Source name: link to publication homepage when available, plain text otherwise.
    # A <span> is always rendered so the source directory JS can read it either way.
    if source_url:
        src_el = (
            f'<a class="src-name" href="{source_url}" '
            f'target="_blank" rel="noopener noreferrer" title="Visit {_escape(source)}">'
            f'{_escape(source)}</a>'
        )
    else:
        src_el = f'<span class="src-name">{_escape(source)}</span>'

    # Card title: only wrap in <a> if we have a valid article URL.
    # An empty href="" is a self-link (current page) which is misleading and broken.
    # SECURITY: article_url is validated above; if empty we render plain text.
    if article_url and validate_url(article_url):
        title_el = (
            f'<a href="{article_url}" target="_blank" rel="noopener noreferrer">'
            f'{_escape(item.get("title",""))}</a>'
        )
    else:
        # No URL available -- render title as plain text, no broken link
        title_el = f'<span>{_escape(item.get("title","No title"))}</span>'

    return (
        f'<article class="card" data-score="{score}" data-cat="{_escape(cat)}" '
        f'data-group="{_escape(item.get("group",""))}" data-country="{_escape(country)}" '
        f'data-source="{_escape(source)}" data-source-url="{_escape(source_url)}">'
        f'<div class="card-head" style="border-left:3px solid {col}">'
        f'<div class="card-meta">'
        f'<span class="cat-badge" data-cat="{_escape(cat)}" '
        f'style="background:{col}22;color:{col};border:1px solid {col}44">'
        f'{_escape(cat.upper())}</span>'
        f'{country_badge}'
        f'{src_el}'
        f'<span class="item-date">{_escape(item.get("date",""))}</span>'
        f'<span class="score-badge {sev_cls}" data-sev="{sev_threshold}">{score} {sev}</span>'
        f'</div>'
        f'<h3 class="card-title">{title_el}</h3>'
        f'</div>'
        f'<div class="card-body">{corr_banner}'
        f'<p class="card-summary">{_escape(item.get("summary","")[:400])}</p>'
        f'<div class="tag-row">{cve_tags}{kw_tags}</div>'
        f'</div>'
        f'</article>\n'
    )


def build_html(
    items_by_group: dict[str, list[dict]],
    generated_at: str,
    config: dict,
) -> str:  # returns full HTML string
    """
    Load template.html and replace {{PLACEHOLDER}} tokens.
    One {{GROUP_*}} token per group, plus global summary stats.
    SECURITY: All token values are numeric or pre-escaped HTML.

    NOTE: --output html is the legacy bespoke-HTML mode and requires template.html
    alongside the script. The recommended output mode is --output data-json, which
    writes data/YYYY-MM-DD.json and data/index.json for use with index.html.
    """
    # SECURITY: Resolve and confirm template stays within SCRIPT_DIR.
    if not TEMPLATE_FILE.exists():
        raise SystemExit(
            f"template.html not found: {TEMPLATE_FILE}\n"
            "The --output html mode requires template.html alongside prism.py.\n"
            "If you have moved to the GitHub Pages architecture, use:\n"
            "  python prism.py --output data-json\n"
            "which writes data/YYYY-MM-DD.json and data/index.json for index.html."
        )
    resolved = TEMPLATE_FILE.resolve()
    if not resolved.is_relative_to(SCRIPT_DIR.resolve()):
        raise SystemExit(f"Template outside script directory: {resolved}")

    tmpl = TEMPLATE_FILE.read_text(encoding="utf-8")

    all_items  = [i for items in items_by_group.values() for i in items]
    total      = len(all_items)
    critical   = sum(1 for i in all_items if i.get("score", 0) >= 10)
    high       = sum(1 for i in all_items if 5 <= i.get("score", 0) < 10)
    unique_cve = len(set(c for i in all_items for c in i.get("cves", []) if isinstance(c, str)))
    ransom     = sum(1 for i in all_items if i.get("category") == "ransomware")
    feed_total = sum(
        len(g.get("feeds", [])) for g in config["data"]["groups"].values()
    )

    replacements = {
        "{{DATE}}":          _escape(generated_at[:10]),
        "{{GENERATED_AT}}":  _escape(generated_at),
        "{{FEED_COUNT}}":    str(feed_total),
        "{{TOTAL}}":         str(total),
        "{{CRITICAL}}":      str(critical),
        "{{HIGH}}":          str(high),
        "{{UNIQUE_CVES}}":   str(unique_cve),
        "{{RANSOMWARE}}":    str(ransom),
    }

    # One token per group: {{CARDS_THREAT_INTEL}}, {{CARDS_NEWS}}, {{CARDS_GOVERNMENT}}
    for group_name, items in items_by_group.items():
        token  = "{{CARDS_" + group_name.upper() + "}}"
        html   = "".join(build_card(i) for i in items)
        count_token = "{{COUNT_" + group_name.upper() + "}}"
        replacements[token]       = html
        replacements[count_token] = str(len(items))

    for token, value in replacements.items():
        tmpl = tmpl.replace(token, value)

    return tmpl


def build_json(items_by_group: dict, generated_at: str) -> str:  # returns JSON string
    """Build JSON summary for automation or Obsidian piping."""
    all_items = [i for items in items_by_group.values() for i in items]
    return json.dumps({
        "generated": generated_at,
        "total":     len(all_items),
        "by_group":  {g: len(v) for g, v in items_by_group.items()},
        "items":     all_items,
    }, indent=2)


def build_data_json(items_by_group: dict, generated_at: str, config: dict) -> str:  # returns JSON string
    """Build JSON summary for automation or Obsidian piping (legacy --output json)."""
    all_items = [i for items in items_by_group.values() for i in items]
    return json.dumps({
        "generated": generated_at,
        "total":     len(all_items),
        "by_group":  {g: len(v) for g, v in items_by_group.items()},
        "items":     all_items,
    }, indent=2)


# =============================================================================
# MULTI-DAY DATA STORAGE + TREND DETECTION
#
# FILE LAYOUT (written to SCRIPT_DIR/data/):
#   data/
#     YYYY-MM-DD.json  -- one file per day; items for that UTC date
#     index.json       -- manifest of available dates + per-day summary stats
#
# index.html fetches data/index.json first to learn what dates exist,
# then fetches data/YYYY-MM-DD.json for the selected date. Switching dates
# is a single fetch -- no page reload required.
#
# TREND DETECTION:
# On each run, items are compared against the previous N days' data files.
# An item's keywords (item["matched"]) are cross-referenced against all items
# from previous days. If those keywords collectively appeared in 2+ consecutive
# prior days, the item is tagged as trending.
# "trend_days" field: int >= 0. 0 = new today; N = seen for N prior days.
# Score boost: +2 per trend day (capped at +6) so trending items surface higher.
# This is topic-level trending, not URL dedup: a new article on the same topic
# as yesterday's articles will inherit the trend signal.
# =============================================================================

DATA_DIR_NAME = "data"
INDEX_FILE    = "index.json"
MAX_HISTORY   = 30   # maximum number of daily files kept in index.json
TREND_WINDOW  = 7    # how many prior days to look back for trend signals
TREND_PER_DAY = 2    # score bonus per trend day
TREND_CAP     = 6    # maximum score bonus from trending


def _data_dir(script_dir: Path) -> Path:  # returns resolved data directory Path
    """Return the data/ directory alongside the script, creating it if needed."""
    d = script_dir / DATA_DIR_NAME
    d.mkdir(exist_ok=True)
    return d


def _load_day_file(data_dir: Path, date_str: str) -> list[dict]:  # returns list of item dicts
    """
    Load items from data/YYYY-MM-DD.json.
    Returns empty list if file does not exist or is malformed.
    SECURITY: date_str is validated before use in a filename.
    """
    import re as _re
    if not _re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
        log.warning(f"_load_day_file: invalid date string rejected: {date_str!r}")
        return []
    path = data_dir / f"{date_str}.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return []
        all_items: list[dict] = []
        for gdata in data.get("groups", {}).values():
            items = gdata.get("items", [])
            if isinstance(items, list):
                all_items.extend(i for i in items if isinstance(i, dict))
        return all_items
    except (json.JSONDecodeError, OSError) as e:
        log.warning(f"_load_day_file: could not read {path.name}: {e}")
        return []


def detect_trends(
    items_by_group: dict[str, list[dict]],
    data_dir: Path,
    today_str: str,
) -> dict[str, list[dict]]:  # returns items_by_group with trend_days and score boosts applied
    """
    Cross-reference today's items against the previous TREND_WINDOW days.

    For each item today:
      - Collect its matched keywords (item["matched"]).
      - For each prior day, check whether any prior item shares at least one
        keyword with this item.
      - Count how many consecutive prior days had such a match.
      - Set item["trend_days"] to that count (0 = new today).
      - Boost item["score"] by TREND_PER_DAY per trend day, capped at TREND_CAP.
      - Set item["trending"] = True if trend_days >= 2.

    This is keyword-topology matching, not URL dedup. A new article covering
    the same topic (e.g. "salt typhoon", "CVE-2025-1234") as yesterday's
    articles will correctly inherit the trend signal.
    """
    # Build ordered list of prior dates to check (most recent first)
    prior_dates: list[str] = []
    for delta in range(1, TREND_WINDOW + 1):
        from datetime import datetime as _dt, timezone as _tz, timedelta as _td
        d = _dt.now(_tz.utc) - _td(days=delta)
        prior_dates.append(d.strftime("%Y-%m-%d"))

    # Load keyword sets from each prior day: {date_str: set_of_lowercase_keywords}
    prior_kw_sets: dict[str, set[str]] = {}
    for date_str in prior_dates:
        if date_str == today_str:
            continue
        day_items = _load_day_file(data_dir, date_str)
        if not day_items:
            break  # stop at first gap -- consecutive days only
        kws: set[str] = set()
        for item in day_items:
            for kw in item.get("matched", []):
                if isinstance(kw, str):
                    kws.add(kw.lower())
            # Also mine CVEs from prior days as trend signals
            for cve in item.get("cves", []):
                if isinstance(cve, str):
                    kws.add(cve.upper())
        prior_kw_sets[date_str] = kws

    if not prior_kw_sets:
        # No prior data -- tag everything as new and return
        for items in items_by_group.values():
            for item in items:
                item["trend_days"] = 0
                item["trending"]   = False
        return items_by_group

    log.info(f"Trend detection: comparing against {len(prior_kw_sets)} prior days")

    for items in items_by_group.values():
        for item in items:
            item_kws: set[str] = set()
            for kw in item.get("matched", []):
                if isinstance(kw, str):
                    item_kws.add(kw.lower())
            for cve in item.get("cves", []):
                if isinstance(cve, str):
                    item_kws.add(cve.upper())

            if not item_kws:
                item["trend_days"] = 0
                item["trending"]   = False
                continue

            # Count consecutive days (working backwards) where a keyword matched
            trend_days = 0
            for date_str in prior_dates:
                if date_str not in prior_kw_sets:
                    break  # gap in history -- stop counting
                if item_kws & prior_kw_sets[date_str]:
                    trend_days += 1
                else:
                    break  # must be consecutive

            item["trend_days"] = trend_days
            item["trending"]   = trend_days >= 2

            if trend_days > 0:
                boost = min(trend_days * TREND_PER_DAY, TREND_CAP)
                item["score"] = item.get("score", 0) + boost
                if trend_days >= 2:
                    log.debug(
                        f"Trending ({trend_days}d +{boost}pts): {item.get('title','')[:60]}"
                    )

    return items_by_group


def write_day_and_index(
    items_by_group: dict[str, list[dict]],
    generated_at: str,
    config: dict,
    script_dir: Path,
) -> tuple[Path, Path]:  # returns (day_file_path, index_file_path)
    """
    Write data/YYYY-MM-DD.json and update data/index.json.

    Day file schema (stable -- index.html depends on this):
    {
      "generated":  "YYYY-MM-DD HH:MM",
      "date":       "YYYY-MM-DD",
      "feed_count": int,
      "groups": {
        "<group>": { "items": [ <item>, ... ] }
      },
      "stats": { total, critical, high, unique_cves, ransomware, trending }
    }

    Index file schema:
    {
      "updated": "YYYY-MM-DD HH:MM",
      "dates": [
        { "date": "YYYY-MM-DD", "generated": "YYYY-MM-DD HH:MM",
          "stats": { total, critical, high, unique_cves, ransomware, trending } },
        ...
      ]   -- newest first, capped at MAX_HISTORY entries
    }

    SECURITY: date string is derived from UTC now() -- not user input.
    Atomic write (tmp -> rename) for both files.
    """
    data_dir   = _data_dir(script_dir)
    today_str  = generated_at[:10]   # "YYYY-MM-DD"

    all_items  = [i for items in items_by_group.values() for i in items]
    critical   = sum(1 for i in all_items if i.get("score", 0) >= 10)
    high       = sum(1 for i in all_items if 5 <= i.get("score", 0) < 10)
    unique_cve = len(set(c for i in all_items for c in i.get("cves", []) if isinstance(c, str)))
    ransom     = sum(1 for i in all_items if i.get("category") == "ransomware")
    trending   = sum(1 for i in all_items if i.get("trending"))
    feed_total = sum(len(g.get("feeds", [])) for g in config["data"]["groups"].values())

    stats = {
        "total":       len(all_items),
        "critical":    critical,
        "high":        high,
        "unique_cves": unique_cve,
        "ransomware":  ransom,
        "trending":    trending,
    }

    # -- Write day file -------------------------------------------------------
    day_payload = {
        "generated":  generated_at,
        "date":       today_str,
        "feed_count": feed_total,
        "groups":     {gname: {"items": items} for gname, items in items_by_group.items()},
        "stats":      stats,
    }
    day_path = data_dir / f"{today_str}.json"
    _atomic_write_json(day_path, day_payload)

    # -- Update index file ----------------------------------------------------
    index_path = data_dir / INDEX_FILE
    index_data: dict = {"updated": generated_at, "dates": []}

    if index_path.exists():
        try:
            loaded = json.loads(index_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("dates"), list):
                index_data["dates"] = [
                    d for d in loaded["dates"]
                    if isinstance(d, dict) and d.get("date") != today_str
                ]
        except (json.JSONDecodeError, OSError) as e:
            log.warning(f"index.json unreadable ({e}) -- rebuilding")

    # Prepend today's entry
    index_data["dates"].insert(0, {
        "date":      today_str,
        "generated": generated_at,
        "stats":     stats,
    })
    # Cap history
    index_data["dates"] = index_data["dates"][:MAX_HISTORY]

    _atomic_write_json(index_path, index_data)

    log.info(
        f"Data written: {day_path.name} "
        f"({len(all_items)} items, {trending} trending) | "
        f"index.json ({len(index_data['dates'])} days)"
    )
    return day_path, index_path


def _atomic_write_json(path: Path, data: dict) -> None:  # returns None -- writes atomically
    """Write JSON atomically: write to .tmp then rename. Prevents partial files on crash."""
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(path)
    except OSError as e:
        log.error(f"Failed to write {path.name}: {e}")
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


# =============================================================================
# VERSIONED FILENAME
# =============================================================================

def next_version(stem: str, ext: str) -> Path:  # returns Path to next unused file
    """Return next unused versioned filename: stem.001.ext, stem.002.ext, ..."""
    if not re.match(r"^[a-zA-Z0-9_\-]+$", stem):
        raise ValueError(f"Invalid stem: {stem!r}")
    if not re.match(r"^\.[a-zA-Z0-9]+$", ext):
        raise ValueError(f"Invalid ext: {ext!r}")
    v = 1
    while True:
        p = Path(f"{stem}.{v:03d}{ext}")
        if not p.exists():
            return p
        v += 1


# =============================================================================
# ARGUMENT PARSING
# =============================================================================

def parse_args():  # returns argparse.Namespace
    p = argparse.ArgumentParser(
        description="Prism -- daily intelligence aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python prism.py                          # run full digest
  python prism.py -v                       # verbose item-level logging
  python prism.py --output json            # json output
  python prism.py --output data-json       # prism_data.json for GitHub Pages
  python prism.py --no-fetch-cache         # bypass URL cache, always re-fetch
  python prism.py --check-feeds            # test all feed URLs
  python prism.py --check-feeds --group government
  python prism.py --set-key otx            # store OTX key in OS keychain
  python prism.py --show-keys              # show key configuration status
        """
    )
    p.add_argument("-v", "--verbose",         action="store_true",
                   help="Show every accepted item as it is fetched")
    p.add_argument("--output",                choices=["html", "json", "text", "data-json"], default="html")
    p.add_argument("--file",                  type=str, default="",
                   help="Output filename -- omit for auto-versioned (prism.001.html)")
    p.add_argument("--lookback",              type=int, default=0,
                   help="Hours to look back (0 = use config value)")
    p.add_argument("--min-score",             type=int, default=-1,
                   help="Min relevance score (-1 = use config value)")
    p.add_argument("--max-items",             type=int, default=-1,
                   help="Max items per group (-1 = use config value)")
    p.add_argument("--no-cache",              action="store_true",
                   help="Ignore dedup cache this run")
    p.add_argument("--no-fetch-cache",        action="store_true",
                   help="Bypass URL fetch cache -- always re-fetch from network")
    p.add_argument("--cache-only",            action="store_true",
                   help="Never hit the network -- serve all groups from local cache only. "
                        "URLs with no cache entry are silently skipped. "
                        "Safe to use when testing or avoiding blocks.")
    p.add_argument("--cache-only-group",      type=str, default="",
                   help="Cache-only for one named group only (e.g. threat_intel). "
                        "Other groups fetch normally. Combine with --cache-only to "
                        "isolate which group gets network access.")
    p.add_argument("--check-feeds",           action="store_true",
                   help="Test all feed URLs and write feeds_check.json")
    p.add_argument("--group",                 type=str, default="",
                   help="Limit --check-feeds to one group name")
    p.add_argument("--timeout",               type=int, default=0,
                   help="HTTP timeout in seconds (0 = use config value)")
    p.add_argument("--set-key",               type=str, metavar="NAME",
                   help=f"Store API key in OS keychain. Names: {API_KEY_NAMES}")
    p.add_argument("--show-keys",             action="store_true",
                   help="Show which API keys are configured (values never shown)")
    return p.parse_args()


# =============================================================================
# MAIN
# =============================================================================

def main():  # returns None
    args = parse_args()

    # -- Run header -----------------------------------------------------------
    # Logged to both screen and file so the log file is self-contained.
    run_start = datetime.now(timezone.utc)
    sep = "=" * 68
    log.info(sep)
    log.info(f"PRISM -- run started {run_start.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    log.info(f"Log file: {_LOG_FILE}")
    log.info(sep)

    # -- Logging level --------------------------------------------------------
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        log.debug("Verbose mode enabled")

    # -- Key management (exit after) ------------------------------------------
    if args.set_key:
        set_api_key(args.set_key)
        sys.exit(0)
    if args.show_keys:
        show_keys()
        sys.exit(0)

    # -- Load config ----------------------------------------------------------
    config   = load_config()
    settings = config.get("settings", {})
    groups   = config["data"]["groups"]

    # -- Verbose: show all key paths so location issues are immediately obvious -
    if args.verbose:
        cache_dir = SCRIPT_DIR / sanitise(settings.get("fetch_cache_dir", "prism_cache"), 80)
        log.debug(f"Script dir   : {SCRIPT_DIR.resolve()}")
        log.debug(f"Config       : {CONFIG_FILE.resolve()}")
        log.debug(f"Template     : {TEMPLATE_FILE.resolve()}")
        log.debug(f"Dedup cache  : {DEDUP_CACHE_FILE.resolve()}")
        log.debug(f"Fetch cache  : {cache_dir.resolve()}")
        log.debug(f"Log file     : {_LOG_FILE.resolve()}")
        log.debug(f"Fetch cache exists: {cache_dir.exists()}")
        if cache_dir.exists():
            n = sum(1 for f in cache_dir.glob("*.json"))
            log.debug(f"Fetch cache entries: {n}")

    # -- Apply CLI overrides to settings (0/-1 = use config default) ----------
    lookback  = args.lookback  if args.lookback  > 0  else int(settings.get("lookback_hours", 24))
    min_score = args.min_score if args.min_score >= 0  else int(settings.get("min_score", 0))
    max_items = args.max_items if args.max_items >= 0  else int(settings.get("max_items", 200))
    if args.timeout > 0:
        settings["feed_timeout_seconds"] = args.timeout

    # SECURITY: Validate all numeric args within sensible bounds.
    if not (0 <= lookback  <= 8760):  raise SystemExit("--lookback out of range (0-8760)")
    if not (0 <= min_score <= 100):   raise SystemExit("--min-score out of range (0-100)")
    if not (0 <= max_items <= 10000): raise SystemExit("--max-items out of range (0-10000)")

    # -- Feed check mode ------------------------------------------------------
    if args.check_feeds:
        timeout = int(settings.get("feed_timeout_seconds", 5))
        check_all_feeds(config, timeout, group_filter=args.group or None)
        sys.exit(0)

    # -- API keys -------------------------------------------------------------
    otx_key = get_api_key("otx")
    log.info(f"OTX key: {'configured' if otx_key else 'not set -- skipping'}")

    # -- Dedup cache ----------------------------------------------------------
    seen: set[str] = set() if args.no_cache else load_dedup()
    log.info(f"Dedup cache: {len(seen)} previously seen items")

    # -- Attach a warning collector to capture feed failures for the summary --
    # This intercepts WARNING and ERROR records emitted during fetching so we
    # can print a clean failure summary at the end instead of having errors
    # scattered through the log with no aggregate view.
    class _WarningCollector(logging.Handler):
        def __init__(self):
            super().__init__(logging.WARNING)
            self.records: list[str] = []
        def emit(self, record):
            self.records.append(self.format(record))

    _wc = _WarningCollector()
    _wc.setFormatter(logging.Formatter("%(message)s"))
    logging.getLogger().addHandler(_wc)

    # -- Fetch all groups -----------------------------------------------------
    # cache_only logic:
    #   --cache-only             = all groups served from cache, no network
    #   --cache-only-group NAME  = that group from cache, others fetch normally
    #   Both can be combined: --cache-only --cache-only-group news would have
    #   no effect since --cache-only already covers everything.
    items_by_group: dict[str, list[dict]] = {}
    ti_keywords = groups.get("threat_intel", {}).get("keywords", {})

    cache_only_group = args.cache_only_group.strip().lower()

    for gname, gcfg in groups.items():
        use_cache_only = args.cache_only or (cache_only_group == gname)

        if use_cache_only:
            log.info(f"[{gname}] Cache-only mode -- no network requests")

        items = fetch_group(
            gname, gcfg, lookback, seen, settings,
            bypass_fetch_cache=args.no_fetch_cache,
            cache_only=use_cache_only,
        )

        # Threat intel group gets ransomware.live and OTX appended
        if gname == "threat_intel":
            items += fetch_ransomware_live(
                lookback, seen, ti_keywords, settings,
                bypass_fetch_cache=args.no_fetch_cache,
                cache_only=use_cache_only,
            )
            if otx_key and not use_cache_only:
                # OTX has no local cache -- skip entirely in cache-only mode
                items += fetch_otx(otx_key, lookback, seen, ti_keywords, settings)

        items_by_group[gname] = items

    # -- CVE cross-reference (threat intel only) ------------------------------
    all_ti = items_by_group.get("threat_intel", [])
    if all_ti:
        items_by_group["threat_intel"] = cross_reference(all_ti)

    # -- Filter and sort each group -------------------------------------------
    for gname in items_by_group:
        items = items_by_group[gname]
        if min_score > 0:
            before = len(items)
            items  = [i for i in items if i.get("score", 0) >= min_score]
            if before != len(items):
                log.info(f"[{gname}] Score filter: {before} -> {len(items)}")
        items.sort(key=lambda x: x.get("score", 0), reverse=True)
        if max_items > 0:
            items = items[:max_items]
        items_by_group[gname] = items

    # -- Save dedup -----------------------------------------------------------
    if not args.no_cache:
        save_dedup(seen)

    # -- Validate --file arg --------------------------------------------------
    if args.file:
        out_path = Path(args.file)
        if out_path.is_absolute() or ".." in out_path.parts:
            raise SystemExit(f"--file must be a local filename, not a path: {args.file}")

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    # -- Write output ---------------------------------------------------------
    if args.output == "html":
        outfile = Path(args.file) if args.file else next_version("prism", ".html")
        outfile.write_text(build_html(items_by_group, generated_at, config), encoding="utf-8")
        log.info(f"Report written: {outfile}")

    elif args.output == "json":
        outfile = Path(args.file) if args.file else next_version("prism", ".json")
        outfile.write_text(build_json(items_by_group, generated_at), encoding="utf-8")
        log.info(f"JSON written: {outfile}")

    elif args.output == "data-json":
        # GitHub Pages multi-day architecture:
        #   1. Run trend detection against previous TREND_WINDOW days in data/
        #   2. Write data/YYYY-MM-DD.json with trend-boosted scores
        #   3. Update data/index.json manifest
        # index.html fetches data/index.json first, then the selected day file.
        data_dir_path = _data_dir(SCRIPT_DIR)
        today_str     = generated_at[:10]

        # Trend detection: compare today's items against prior days in data/
        # Must run BEFORE score-dependent sort is finalised (sort already done
        # above, but trend boost may re-rank -- re-sort after detection).
        items_by_group = detect_trends(items_by_group, data_dir_path, today_str)

        # Re-sort after trend score boosts are applied
        for gname in items_by_group:
            items_by_group[gname].sort(key=lambda x: x.get("score", 0), reverse=True)

        write_day_and_index(items_by_group, generated_at, config, SCRIPT_DIR)

    else:  # text
        all_items = [i for items in items_by_group.values() for i in items]
        print(f"\n=== PRISM DIGEST -- {generated_at} UTC ===")
        current_group = None
        for item in sorted(all_items, key=lambda x: (x.get("group",""), -x.get("score",0))):
            if item.get("group") != current_group:
                current_group = item.get("group")
                print(f"\n-- {current_group.upper()} --")
            print(f"  [{item.get('score',0):>3}] {item.get('source',''):<35} {item.get('title','')[:65]}")
        print()

    # -- Run summary ----------------------------------------------------------
    elapsed = (datetime.now(timezone.utc) - run_start).total_seconds()
    total   = sum(len(v) for v in items_by_group.values())

    log.info(sep)
    log.info(f"PRISM -- run complete in {elapsed:.1f}s")
    for gname, items in items_by_group.items():
        log.info(f"  {gname:<20} {len(items):>4} items")
    log.info(f"  {'TOTAL':<20} {total:>4} items")

    # Trending summary (data-json mode only -- other modes don't run trend detection)
    all_items_flat = [i for items in items_by_group.values() for i in items]
    trending_count = sum(1 for i in all_items_flat if i.get("trending"))
    if trending_count:
        log.info(f"  {'TRENDING':<20} {trending_count:>4} items (active 2+ days)")

    # Print warning summary only if there were failures
    failures = [r for r in _wc.records if "HTTP" in r or "Timeout" in r
                or "TLS" in r or "Malformed" in r or "Fetch failed" in r]
    if failures:
        log.info(f"  {len(failures)} feed warnings this run:")
        for msg in failures:
            log.info(f"    [WARN] {msg[:100]}")
    else:
        log.info("  No feed errors")

    log.info(sep)


if __name__ == "__main__":
    main()
