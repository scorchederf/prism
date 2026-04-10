# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Prism is a local-first cybersecurity intelligence aggregator. It pulls from ~127 RSS feeds and threat intel APIs, scores items by keyword relevance, detects multi-day trending topics, and publishes a filterable daily digest as a static GitHub Pages site.

The HTML shell (`index.html`) is committed once. Only `data/YYYY-MM-DD.json` and `data/index.json` change on each run.

## Dependencies

```bash
pip install feedparser requests keyring
# Linux headless (no desktop keyring):
pip install keyrings.alt
```

## Common Commands

```bash
# Standard daily run (recommended)
python prism.py --output data-json

# Verbose output -- shows every feed fetch, score, and age-drop
python prism.py --output data-json -v

# Bypass all caches, widen lookback window
python prism.py --output data-json --no-fetch-cache --no-cache --lookback 48

# High-signal only (CRITICAL and HIGH)
python prism.py --output data-json --min-score 5

# Verify all feed URLs (writes feeds_check.json)
python prism.py --check-feeds
python prism.py --check-feeds --group government

# Manage API keys (stored in OS keychain, never in files)
python prism.py --set-key otx
python prism.py --show-keys

# View locally (index.html requires a server due to fetch())
python -m http.server 8000
```

## Running Tests

```bash
pip install pytest
pytest test_prism.py -v

# Run a single test class
pytest test_prism.py::TestValidateUrl -v
```

The test suite auto-discovers the highest-versioned `prism.NNN.py` alongside it, falling back to `prism.py`. Security invariant tests (URL validation, HTML escaping, path anchoring) are blockers -- any failure must be fixed before committing.

## Architecture

**Single-script design:** All logic lives in `prism.py`. Configuration is data-only in `prism_config.json`. There is no build step.

**Pipeline flow:**
1. `load_config()` -- reads and validates `prism_config.json`, drops invalid feed URLs and out-of-range keyword weights
2. `fetch_cached()` -- fetches feed bytes with a local file cache (`prism_cache/`), `https://` only
3. `_parse_feed_entries()` -- extracts items via feedparser, using `getattr(entry, "link", "")` (not `__dict__`)
4. Scoring -- items matched against group keyword tables; news items run through `classify_news_item()` rules
5. `detect_trends()` -- cross-references today's items against up to 7 prior day files in `data/`; trending items get a +2/day score boost (capped at +6)
6. `write_day_and_index()` -- writes `data/YYYY-MM-DD.json` atomically; updates `data/index.json` manifest; keeps up to 30 days of history
7. `build_card()` -- renders HTML cards; all external strings pass through `_escape()` before insertion

**Key constants (prism.py):**
- `SCRIPT_DIR` -- all file paths are anchored here, never derived from cwd or user input
- `DEDUP_CACHE_FILE` -- `prism_seen.json`, dedup hash store excluded from git
- `MAX_HISTORY = 30` -- days of data files kept
- `TREND_WINDOW = 7` -- prior days examined for trend detection

**Configuration structure (`prism_config.json`):**
- `settings` -- TTL, timeouts, lookback window, item caps
- `data.groups` -- `threat_intel`, `news`, `government`; each has `feeds[]`, `keywords{}`, `enabled`
- `news_categories` -- auto-classification rules applied in order; first match wins
- Feed fields: `name`, `url`, `category`, `country_tag`, `trust_tier` (1=authoritative → 4=commentary), `note`
- Keyword weights: integers 1–10 only; anything outside that range is dropped at load time

**Frontend (`index.html`):**  
Single self-contained file, no build step. CDN dependencies: Bootstrap 5.3 (utility resets only), Font Awesome 6, JetBrains Mono. Operator aesthetic — midnight navy palette (`--bg: #080b10`, `--surface: #0d1117`), monospace throughout, severity-coloured left accent bars on cards.

Layout: fixed top-nav (44px) → horizontally-scrollable filter bar → scrollable feed with inline group headers. On mobile (≤640px) the filter bar is hidden; a ⊞ button opens a bottom sheet (`#filter-sheet`) with all three filter groups (severity, group, country).

Filter source-of-truth: three hidden `<select>` elements (`#f-sev`, `#f-cat`, `#f-country`) drive the existing `applyFilters()` engine via `data-*` attributes on `.intel-card` elements. The chip UI is a visual layer only — bridge functions (`setSev`, `setCountry`, `jumpGroupSheet`) write to the hidden selects and call `applyFilters()`. **Do not remove or rename `#f-sev`, `#f-cat`, `#f-country`, `#stat-banner`, `#topbar`, `#logo-date`, `#date-history-note`, or any `nc-*`/`pill-*` span IDs** — the 800-line JS block references them directly and must not be modified.

## Automated Fetch

GitHub Actions (`.github/workflows/prism.yml`) runs hourly, pushes updated `data/` files back to the repo. The OTX API key must be stored as a GitHub Secret named `OTX_API_KEY`.

## Security Invariants

These must never regress (enforced by `test_security_checklist_meta`):
- All URLs validated as `https://` only before any network request (`validate_url()`)
- All external content HTML-escaped before rendering (`_escape()`)
- All external strings sanitised for control characters (`sanitise()`)
- All file paths anchored to `SCRIPT_DIR`, never derived from user input
- `requests.get()` called with `verify=True` (TLS cert validation)
- API keys stored in OS keychain only -- never in files or env vars committed to git

## Files Excluded from Git

`prism_cache/`, `prism.log`, `prism_seen.json` -- these are runtime-only artefacts.
