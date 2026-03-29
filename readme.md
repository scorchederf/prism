# Prism -- Daily Intelligence Digest

A local-first cybersecurity intelligence aggregator. Pulls from 127 RSS feeds across
threat intelligence, news, and government sources, scores items by relevance, detects
trending topics across multiple days, and publishes a filterable daily digest as a
static GitHub Pages site.

---

## How It Works

```
[Your machine -- runs daily via Task Scheduler / cron]
  prism_012.py --output data-json
        |
        v
  data/2026-03-29.json   <-- processed items with scores, trend detection
  data/index.json        <-- manifest of all available dates
        |
        v (git push)
  GitHub repository
        |
        v (GitHub Pages)
  index.html loads data/index.json, fetches selected day file, renders cards
```

The HTML shell is committed once. Only the data files change on each run.

---

## Repository Layout

```
prism_012.py          Aggregator script -- runs locally only
prism_config.json     All configuration: feeds, keywords, scoring rules
index.html            Static GitHub Pages shell -- committed once
data/
  index.json          Manifest of available dates with per-day stats
  YYYY-MM-DD.json     One processed data file per day (up to 30 kept)
prism_cache/          Raw HTTP fetch cache -- excluded from git (.gitignore)
prism.log             Rotating log file -- excluded from git
prism_seen.json       Dedup hash cache -- excluded from git
test_prism.py         Test suite
README.md             This file
.gitignore            Excludes logs, caches, secrets
```

---

## Quick Start

### 1. Install Dependencies

```bash
pip install feedparser requests keyring
# Linux without a desktop keyring:
pip install keyrings.alt
```

### 2. Run a Full Fetch

```bash
python prism_012.py --output data-json -v
```

This fetches all 127 feeds, scores items, runs trend detection against any existing
day files in `data/`, writes `data/YYYY-MM-DD.json` and `data/index.json`.

### 3. View Locally

`index.html` uses `fetch()` which requires a web server. Open a terminal in the
project folder and run:

```bash
python -m http.server 8000
```

Then open `http://localhost:8000` in your browser.

### 4. Push to GitHub Pages

```bash
git add data/index.json data/2026-03-29.json
git commit -m "data: 2026-03-29 daily update"
git push
```

Your digest is live at `https://YOUR_USERNAME.github.io/prism/`.

---

## Command Reference

```bash
# Standard daily run (recommended)
python prism_012.py --output data-json

# Full refresh: bypass all caches, widen the lookback window
python prism_012.py --output data-json --no-fetch-cache --no-cache --lookback 48

# Verbose -- shows every feed fetch, item score, age-dropped counts
python prism_012.py --output data-json -v

# High signal only -- surface CRITICAL and HIGH items
python prism_012.py --output data-json --min-score 5

# Test all feed URLs -- writes feeds_check.json
python prism_012.py --check-feeds

# Test feeds for a single group
python prism_012.py --check-feeds --group government

# Store API key in OS keychain (AlienVault OTX)
python prism_012.py --set-key otx

# Show which API keys are configured
python prism_012.py --show-keys

# Legacy HTML output (requires template.html alongside script)
python prism_012.py --output html
```

---

## Configuration (`prism_config.json`)

### Settings

```json
"settings": {
  "fetch_cache_ttl_seconds": 3600,   // how long raw feed bytes are cached locally
  "fetch_cache_dir": "prism_cache",  // raw HTTP cache directory (excluded from git)
  "feed_timeout_seconds": 5,         // per-feed HTTP timeout
  "lookback_hours": 24,              // how far back to accept article pub dates
  "max_items": 500,                  // max items per group after scoring
  "min_score": 0                     // minimum score for an item to be included
}
```

### Feed Structure

Each feed entry supports:

```json
{
  "name": "Display name",
  "url": "https://example.com/rss",
  "category": "advisory",       // card badge: advisory, research, exploit, intel, vendor,
                                //   detection, ransomware, government, news, incident,
                                //   vulnerability, threat-actor, policy, ai, geopolitical, industry
  "country_tag": "AU",          // shown as a badge; filters in the UI
  "trust_tier": 2,              // 1=authoritative, 2=established, 3=blog, 4=commentary
  "note": "Optional note"       // internal documentation only
}
```

### Scoring

Items are scored by matching their title + summary against the keyword weight table
in `prism_config.json`. Score bands:

| Score | Severity | Meaning |
|-------|----------|---------|
| 10+   | CRITICAL | Active incident, zero-day, national-level event |
| 5-9   | HIGH     | Significant breach, named threat actor, CVE |
| 2-4   | MEDIUM   | Policy, regulation, vendor advisory |
| 0-1   | LOW      | General interest, informational |

### Trend Detection

On each run, items are compared against up to 7 prior day files in `data/`.
If an item's matched keywords appear in items from 2+ consecutive prior days,
it is tagged as trending. Score boost: +2 per day, capped at +6. Trending items
get an amber badge and a banner inside the card.

### News Auto-Classification

News items are classified by `news_categories` rules in the config. Rules are
evaluated in order; first match wins. Falls back to `"news"` if no rule matches.
Each rule has a `category` and a list of `keywords` matched against title + summary.

---

## API Keys

API keys are stored in the OS keychain only -- never in files or environment variables
that could be committed to git.

```bash
# Store key (input is hidden)
python prism_012.py --set-key otx

# Verify it is stored
python prism_012.py --show-keys
```

Supported keys:
- `otx` -- AlienVault OTX (free account at otx.alienvault.com)

---

## Scheduling

### Windows Task Scheduler

Create a basic task that runs daily:

**Program:** `python`
**Arguments:** `C:\path\to\prism_012.py --output data-json`
**Start in:** `C:\path\to\prism\`

After the Python task, create a second task (or a `.bat` file) to push:

```bat
@echo off
cd /d C:\path\to\prism
git add data\index.json data\*.json
git commit -m "data: %DATE% daily update"
git push
```

### Linux / macOS (cron)

```cron
# Run at 7am daily, push results to GitHub
0 7 * * * cd /path/to/prism && python prism_012.py --output data-json >> prism_cron.log 2>&1
5 7 * * * cd /path/to/prism && git add data/ && git commit -m "data: $(date +\%Y-\%m-\%d)" && git push
```

---

## GitHub Pages Setup

1. Push the repository to GitHub (set to **Public** if you want the page public)
2. Go to **Settings > Pages**
3. Set **Source** to `Deploy from a branch`
4. Set **Branch** to `main`, folder `/` (root)
5. Save -- the digest is live at `https://YOUR_USERNAME.github.io/REPO_NAME/`

The `index.html` file fetches `data/index.json` at load time. Once the scheduled
task pushes a new day file, the next page load reflects it.

---

## GitHub Actions (Optional -- Cloud Fetch)

> **Security note:** Running the fetcher in GitHub Actions means API keys must be
> stored as GitHub Secrets, not in the repo. Feed content is public but your OTX key
> must never appear in code or logs.

### Workflow File (`.github/workflows/prism.yml`)

```yaml
name: Prism Daily Fetch

on:
  schedule:
    - cron: '0 21 * * *'    # 21:00 UTC = 07:00 AEST next day
  workflow_dispatch:          # allow manual trigger

jobs:
  fetch:
    runs-on: ubuntu-latest
    permissions:
      contents: write          # needed to push data files back to the repo

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install feedparser requests keyring keyrings.alt

      - name: Write OTX key to keyring
        env:
          OTX_KEY: ${{ secrets.OTX_API_KEY }}
        run: |
          python - <<'EOF'
          import keyring, os
          key = os.environ.get('OTX_KEY', '')
          if key:
              keyring.set_password('prism', 'otx', key)
              print('OTX key stored')
          else:
              print('OTX key not configured -- skipping')
          EOF

      - name: Run Prism
        run: python prism_012.py --output data-json

      - name: Commit and push data files
        run: |
          git config user.name  "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add data/
          git diff --staged --quiet || git commit -m "data: $(date -u +%Y-%m-%d) automated fetch"
          git push
```

### Storing API Keys in GitHub Secrets

1. Go to your repository on GitHub
2. **Settings > Secrets and variables > Actions**
3. Click **New repository secret**
4. Name: `OTX_API_KEY`
5. Value: your AlienVault OTX key (get it from otx.alienvault.com > Settings > API Integration)
6. Click **Add secret**

The key is injected as an environment variable during the workflow run and is never
written to any file in the repository.

---

## Feed Check

Run this after adding or changing feeds to verify all URLs are reachable:

```bash
python prism_012.py --check-feeds
```

Output is written to `feeds_check.json`. Upload it to Claude for analysis and
URL fix suggestions.

---

## Security Notes

- All feed URLs are validated as `https://` before any network request
- All external content is HTML-escaped before rendering (OWASP A03)
- API keys are stored in the OS keychain only -- never in files or environment variables
- `data/` files are public on GitHub Pages -- do not include internal hostnames,
  credentials, or PII in feed configuration
- `prism_cache/`, `prism.log`, and `prism_seen.json` are excluded from git by `.gitignore`
- The HTML shell has no external dependencies (no CDN, fonts, analytics, or tracking)
