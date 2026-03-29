#!/usr/bin/env python3
"""
test_prism.py -- Regression and security test suite for prism.py

Run:
    pip install pytest
    pytest test_prism.py -v

Run before and after every significant change. The security invariant
tests must always pass -- any failure there is a blocker, not a warning.

Test categories:
    Security invariants  -- validate_url, sanitise, _escape, path checks
    Cache behaviour      -- cache-only, bypass, TTL, atomic write
    Filter logic         -- clickbait, exclusions, URL suppression
    Config validation    -- bad URLs, bad weights, missing structure
    Card rendering       -- no broken anchors, all data attributes present
"""

import base64
import json
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: import prism from whatever versioned file is alongside this
# test file, or fall back to prism.py. The module is registered in
# sys.modules as "prism" so that patch("prism.X") works correctly.
# ---------------------------------------------------------------------------
_here = Path(__file__).parent

# Pick highest versioned prism.NNN.py, then fall back to prism.py
_prism_candidates = sorted(_here.glob("prism.*.py"), reverse=True) + [_here / "prism.py"]
_prism_path = next((p for p in _prism_candidates if p.exists()), None)

if _prism_path is None:
    raise RuntimeError("No prism.py found alongside test_prism.py")

# Add the script directory to sys.path so relative imports work
sys.path.insert(0, str(_prism_path.parent))

# Dynamic import -- load from file, register as "prism" in sys.modules
import importlib.util
_spec = importlib.util.spec_from_file_location("prism", _prism_path)
_mod  = importlib.util.module_from_spec(_spec)
sys.modules["prism"] = _mod          # register BEFORE exec so patch() finds it
_spec.loader.exec_module(_mod)

print(f"\nTesting: {_prism_path.name}")

# Pull symbols we need
validate_url        = _mod.validate_url
sanitise            = _mod.sanitise
_escape             = _mod._escape
safe_get            = _mod.safe_get
make_hash           = _mod.make_hash
is_clickbait        = _mod.is_clickbait
build_card          = _mod.build_card
_build_clickbait_re = _mod._build_clickbait_re
load_config         = _mod.load_config
fetch_cached        = _mod.fetch_cached
SCRIPT_DIR          = _mod.SCRIPT_DIR
DEDUP_CACHE_FILE    = _mod.DEDUP_CACHE_FILE


# =============================================================================
# SECURITY INVARIANTS
# These must never regress. Any failure is a blocker.
# =============================================================================

class TestValidateUrl:
    """validate_url() -- https:// only, rejects everything else."""

    def test_valid_https(self):
        assert validate_url("https://www.example.com/feed") is True

    def test_valid_https_with_path(self):
        assert validate_url("https://blog.example.com/rss/feed.xml?v=2") is True

    def test_rejects_http(self):
        # http:// must be rejected -- no cleartext fetches
        assert validate_url("http://www.example.com/feed") is False

    def test_rejects_file_scheme(self):
        # file:// would allow reading local filesystem
        assert validate_url("file:///etc/passwd") is False

    def test_rejects_ftp(self):
        assert validate_url("ftp://ftp.example.com/file") is False

    def test_rejects_data_uri(self):
        assert validate_url("data:text/html,<script>alert(1)</script>") is False

    def test_rejects_empty_string(self):
        assert validate_url("") is False

    def test_rejects_none(self):
        assert validate_url(None) is False

    def test_rejects_overlong_url(self):
        # URLs over 2048 chars should be rejected
        assert validate_url("https://x.com/" + "a" * 2100) is False

    def test_rejects_no_scheme(self):
        assert validate_url("www.example.com/feed") is False

    def test_rejects_javascript_scheme(self):
        assert validate_url("javascript:alert(1)") is False

    def test_rejects_bare_path(self):
        assert validate_url("/etc/passwd") is False


class TestSanitise:
    """sanitise() -- strips control chars, enforces max length."""

    def test_strips_null_byte(self):
        # Null bytes in log messages cause issues and can be injection vectors
        assert "\x00" not in sanitise("hello\x00world")

    def test_strips_carriage_return(self):
        # CR can be used for log injection to overwrite log lines
        assert "\r" not in sanitise("line1\rline2")

    def test_strips_escape_sequence(self):
        # Terminal escape sequences could manipulate terminal output
        assert "\x1b" not in sanitise("\x1b[31mred\x1b[0m")

    def test_strips_backspace(self):
        assert "\x08" not in sanitise("test\x08\x08")

    def test_preserves_normal_text(self):
        assert sanitise("hello world") == "hello world"

    def test_preserves_tab_and_newline(self):
        # Tab (0x09) and newline (0x0a) are allowed
        result = sanitise("line1\nline2\ttabbed")
        assert "line1" in result
        assert "line2" in result

    def test_enforces_max_length(self):
        long_str = "a" * 1000
        assert len(sanitise(long_str, max_len=100)) <= 100

    def test_default_max_length(self):
        long_str = "a" * 1000
        assert len(sanitise(long_str)) <= 500

    def test_handles_non_string(self):
        assert sanitise(None) == ""
        assert sanitise(42) == ""
        assert sanitise([]) == ""


class TestEscapeHtml:
    """_escape() -- HTML injection prevention (OWASP A03)."""

    def test_escapes_ampersand(self):
        assert _escape("a & b") == "a &amp; b"

    def test_escapes_less_than(self):
        assert _escape("<script>") == "&lt;script&gt;"

    def test_escapes_greater_than(self):
        assert _escape("a > b") == "a &gt; b"

    def test_escapes_double_quote(self):
        assert _escape('say "hello"') == "say &quot;hello&quot;"

    def test_escapes_single_quote(self):
        assert _escape("it's here") == "it&#39;s here"

    def test_xss_payload_escaped(self):
        payload = '<img src=x onerror=alert(1)>'
        result  = _escape(payload)
        assert "<" not in result
        assert ">" not in result
        assert "onerror" in result  # text preserved, tags broken

    def test_script_injection_escaped(self):
        payload = '"><script>alert(document.cookie)</script>'
        result  = _escape(payload)
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_clean_text_unchanged(self):
        text = "CVE-2026-12345 critical vulnerability"
        assert _escape(text) == text


class TestSafeGet:
    """safe_get() -- null-safe dict access."""

    def test_returns_value(self):
        assert safe_get({"key": "val"}, "key") == "val"

    def test_returns_default_on_missing(self):
        assert safe_get({}, "key", "default") == "default"

    def test_returns_default_on_none_value(self):
        assert safe_get({"key": None}, "key", "fallback") == "fallback"

    def test_returns_empty_string_default(self):
        assert safe_get({}, "key") == ""

    def test_strips_whitespace(self):
        assert safe_get({"key": "  hello  "}, "key") == "hello"

    def test_converts_int_to_string(self):
        result = safe_get({"key": 42}, "key")
        assert result == "42"


class TestPathAnchoring:
    """All file paths must resolve within SCRIPT_DIR."""

    def test_script_dir_is_absolute(self):
        assert SCRIPT_DIR.is_absolute()

    def test_dedup_cache_within_script_dir(self):
        # DEDUP_CACHE_FILE must be absolute and sit directly inside SCRIPT_DIR.
        # Compare resolved paths to avoid symlink or case differences.
        assert DEDUP_CACHE_FILE.is_absolute(), \
            f"DEDUP_CACHE_FILE is not absolute: {DEDUP_CACHE_FILE}"
        assert DEDUP_CACHE_FILE.resolve().parent == SCRIPT_DIR.resolve(), \
            (f"DEDUP_CACHE_FILE ({DEDUP_CACHE_FILE}) is not inside "
             f"SCRIPT_DIR ({SCRIPT_DIR}). Was it defined as a bare "
             f"Path('prism_seen.json') instead of SCRIPT_DIR / 'prism_seen.json'?")

    def test_config_file_within_script_dir(self):
        assert _mod.CONFIG_FILE.resolve().parent == SCRIPT_DIR.resolve()

    def test_template_file_within_script_dir(self):
        assert _mod.TEMPLATE_FILE.resolve().parent == SCRIPT_DIR.resolve()


# =============================================================================
# CACHE BEHAVIOUR
# =============================================================================

class TestFetchCache:
    """fetch_cached() -- cache-only, bypass, TTL, no network in cache-only.

    Strategy: patch prism.SCRIPT_DIR to tmp_path so that
    SCRIPT_DIR / "prism_cache" resolves inside the temp directory.
    Settings always use the relative name "prism_cache" -- never an
    absolute path -- matching how the real config works.
    """

    def _settings(self, ttl: int = 3600) -> dict:
        # fetch_cache_dir is a name relative to SCRIPT_DIR, not an absolute path.
        return {
            "fetch_cache_dir":         "prism_cache",
            "fetch_cache_ttl_seconds": ttl,
            "feed_timeout_seconds":    5,
        }

    def _write_cache_entry(self, cache_dir: Path, url: str, content: bytes, age_seconds: int = 0):
        """Write a synthetic cache entry with a given age."""
        key   = _mod._cache_key(url)
        entry = cache_dir / f"{key}.json"
        ts    = (datetime.now(timezone.utc) - timedelta(seconds=age_seconds)).isoformat()
        entry.write_text(json.dumps({
            "fetched_at":  ts,
            "url":         url,
            "content_b64": base64.b64encode(content).decode(),
        }), encoding="utf-8")
        return entry

    def test_cache_only_returns_cached_content(self, tmp_path):
        url     = "https://example.com/feed.xml"
        content = b"<rss>cached content</rss>"
        cache   = tmp_path / "prism_cache"
        cache.mkdir()
        self._write_cache_entry(cache, url, content, age_seconds=7200)  # older than TTL

        with patch("prism.SCRIPT_DIR", tmp_path):
            result = fetch_cached(url, self._settings(), cache_only=True)

        assert result == content, "cache-only must return content regardless of TTL age"

    def test_cache_only_returns_none_on_miss(self, tmp_path):
        url   = "https://example.com/no-cache-here.xml"
        cache = tmp_path / "prism_cache"
        cache.mkdir()

        with patch("prism.SCRIPT_DIR", tmp_path):
            result = fetch_cached(url, self._settings(), cache_only=True)

        assert result is None, "cache-only with no cache entry must return None silently"

    def test_cache_only_never_calls_requests(self, tmp_path):
        """The most important cache-only test: absolutely zero network calls."""
        url   = "https://example.com/feed.xml"
        cache = tmp_path / "prism_cache"
        cache.mkdir()

        with patch("prism.SCRIPT_DIR", tmp_path):
            with patch("prism.requests.get") as mock_get:
                fetch_cached(url, self._settings(), cache_only=True)
                mock_get.assert_not_called()

    def test_fresh_cache_serves_without_network(self, tmp_path):
        url     = "https://example.com/feed.xml"
        content = b"fresh cached data"
        cache   = tmp_path / "prism_cache"
        cache.mkdir()
        self._write_cache_entry(cache, url, content, age_seconds=60)  # well within TTL

        with patch("prism.SCRIPT_DIR", tmp_path):
            with patch("prism.requests.get") as mock_get:
                result = fetch_cached(url, self._settings(ttl=3600))
                mock_get.assert_not_called()

        assert result == content

    def test_stale_cache_triggers_network_fetch(self, tmp_path):
        url     = "https://example.com/feed.xml"
        content = b"fresh from network"
        cache   = tmp_path / "prism_cache"
        cache.mkdir()
        self._write_cache_entry(cache, url, b"old stale data", age_seconds=7200)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content     = content
        mock_resp.raise_for_status = MagicMock()

        with patch("prism.SCRIPT_DIR", tmp_path):
            with patch("prism.requests.get", return_value=mock_resp):
                result = fetch_cached(url, self._settings(ttl=3600))

        assert result == content

    def test_bypass_always_fetches(self, tmp_path):
        url     = "https://example.com/feed.xml"
        content = b"network response"
        cache   = tmp_path / "prism_cache"
        cache.mkdir()
        # Cache has a fresh entry -- bypass must ignore it entirely
        self._write_cache_entry(cache, url, b"cached data", age_seconds=10)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content     = content
        mock_resp.raise_for_status = MagicMock()

        with patch("prism.SCRIPT_DIR", tmp_path):
            with patch("prism.requests.get", return_value=mock_resp) as mock_get:
                result = fetch_cached(url, self._settings(), bypass=True)
                mock_get.assert_called_once()

        assert result == content

    def test_invalid_url_rejected_before_cache_or_network(self, tmp_path):
        with patch("prism.requests.get") as mock_get:
            result = fetch_cached("http://insecure.com/feed", self._settings())
            mock_get.assert_not_called()
        assert result is None

    def test_file_scheme_rejected(self, tmp_path):
        with patch("prism.requests.get") as mock_get:
            result = fetch_cached("file:///etc/passwd", self._settings())
            mock_get.assert_not_called()
        assert result is None


# =============================================================================
# FILTER LOGIC
# =============================================================================

class TestClickbaitFilter:
    """is_clickbait() -- phrase list, title length, punctuation heuristics."""

    def _cfg(self, phrases=None, max_title=120, min_summary=30):
        return {
            "clickbait_phrases":  phrases or ["you won't believe", "shocking", "viral"],
            "max_title_length":   max_title,
            "min_summary_length": min_summary,
        }

    def test_clean_article_passes(self):
        cfg = self._cfg()
        # Reset the module-level compiled pattern
        _mod._CLICKBAIT_RE = None
        bad, _ = is_clickbait(
            "Government releases new cybersecurity framework",
            "The framework covers incident response and vulnerability management.",
            cfg,
        )
        assert bad is False

    def test_clickbait_phrase_blocked(self):
        cfg = self._cfg()
        _mod._CLICKBAIT_RE = None
        bad, reason = is_clickbait("You won't believe what hackers did next", "summary text here okay", cfg)
        assert bad is True
        assert "clickbait phrase" in reason

    def test_long_title_blocked(self):
        cfg = self._cfg(max_title=60)
        _mod._CLICKBAIT_RE = None
        long_title = "a" * 61
        bad, reason = is_clickbait(long_title, "reasonable summary text here", cfg)
        assert bad is True
        assert "too long" in reason

    def test_rhetorical_question_blocked(self):
        cfg = self._cfg()
        _mod._CLICKBAIT_RE = None
        bad, reason = is_clickbait("Is this the end of cybersecurity?", "normal summary text here okay", cfg)
        assert bad is True
        assert "rhetorical" in reason

    def test_double_exclamation_blocked(self):
        cfg = self._cfg()
        _mod._CLICKBAIT_RE = None
        bad, reason = is_clickbait("Hackers strike again!! Must read", "reasonable summary text", cfg)
        assert bad is True
        assert "exclamation" in reason

    def test_short_summary_blocked(self):
        cfg = self._cfg(min_summary=30)
        _mod._CLICKBAIT_RE = None
        bad, reason = is_clickbait("Normal title here that is fine", "Too short.", cfg)
        assert bad is True
        assert "too short" in reason


class TestCardRendering:
    """build_card() -- security and correctness of generated HTML."""

    def _item(self, **kwargs):
        base = {
            "group":        "threat_intel",
            "source":       "Test Source",
            "category":     "advisory",
            "country_tag":  "AU",
            "title":        "Test Article Title",
            "url":          "https://example.com/article",
            "summary":      "This is a test summary.",
            "date":         "2026-03-28 09:00 UTC",
            "score":        5,
            "matched":      ["windows", "crowdstrike"],
            "hash":         "abc123",
            "cves":         ["CVE-2026-1234"],
            "corroborated": [],
        }
        base.update(kwargs)
        return base

    def test_valid_url_renders_anchor(self):
        html = build_card(self._item())
        assert 'href="https://example.com/article"' in html
        assert "<a " in html

    def test_empty_url_renders_no_anchor(self):
        html = build_card(self._item(url=""))
        # Should not have an empty href
        assert 'href=""' not in html
        # Title should still be present as plain text
        assert "Test Article Title" in html

    def test_http_url_renders_no_anchor(self):
        # http:// fails validate_url so should not become an href
        html = build_card(self._item(url="http://insecure.com/article"))
        assert 'href="http://' not in html

    def test_title_is_html_escaped(self):
        html = build_card(self._item(title='<script>alert("xss")</script>'))
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_summary_is_html_escaped(self):
        html = build_card(self._item(summary='<img src=x onerror=alert(1)>'))
        assert "<img" not in html
        assert "&lt;img" in html

    def test_source_is_html_escaped(self):
        html = build_card(self._item(source='"><script>bad</script>'))
        assert "<script>" not in html

    def test_data_attributes_present(self):
        html = build_card(self._item())
        assert 'data-score="5"' in html
        assert 'data-cat="advisory"' in html
        assert 'data-group="threat_intel"' in html
        assert 'data-country="AU"' in html
        assert 'data-source="Test Source"' in html

    def test_source_url_derived_from_article(self):
        html = build_card(self._item(url="https://example.com/feed/article-1"))
        assert 'data-source-url="https://example.com"' in html

    def test_no_target_blank_on_source_link(self):
        html = build_card(self._item())
        # Source name link (src-name class) must not open in new tab
        src_link_start = html.find('class="src-name"')
        if src_link_start != -1:
            src_link_end = html.find("</a>", src_link_start)
            src_link_html = html[src_link_start:src_link_end]
            assert "target" not in src_link_html

    def test_article_link_opens_new_tab(self):
        html = build_card(self._item())
        assert 'target="_blank"' in html

    def test_cve_tag_rendered_and_escaped(self):
        html = build_card(self._item(cves=["CVE-2026-1234"]))
        assert "CVE-2026-1234" in html
        assert "cve-tag" in html

    def test_rel_noopener_on_all_links(self):
        html = build_card(self._item())
        # Count anchors and noopener attributes -- should match
        import re
        anchors   = len(re.findall(r'<a ', html))
        noopeners = len(re.findall(r'noopener', html))
        assert noopeners >= anchors, "Every anchor must have rel=noopener"


# =============================================================================
# CONFIG VALIDATION
# =============================================================================

class TestConfigValidation:
    """load_config() validates structure and drops invalid entries."""

    def _write_config(self, tmp_path: Path, data: dict) -> Path:
        cfg_path = tmp_path / "prism_config.json"
        cfg_path.write_text(json.dumps(data), encoding="utf-8")
        return cfg_path

    def test_invalid_url_scheme_dropped(self, tmp_path):
        cfg = {
            "meta": {}, "settings": {},
            "data": {"groups": {"threat_intel": {
                "enabled": True,
                "keywords": {"windows": 5},
                "feeds": [
                    {"name": "Good",  "url": "https://ok.com/feed", "category": "advisory"},
                    {"name": "Bad",   "url": "http://bad.com/feed", "category": "advisory"},
                    {"name": "Worse", "url": "file:///etc/passwd",  "category": "advisory"},
                ],
            }}}
        }
        self._write_config(tmp_path, cfg)

        with patch.object(_mod, "CONFIG_FILE", tmp_path / "prism_config.json"):
            with patch.object(_mod, "SCRIPT_DIR", tmp_path):
                config = _mod.load_config()

        feeds = config["data"]["groups"]["threat_intel"]["feeds"]
        urls  = [f["url"] for f in feeds]
        assert "https://ok.com/feed" in urls,    "valid https URL should be kept"
        assert "http://bad.com/feed" not in urls, "http URL should be dropped"
        assert "file:///etc/passwd"  not in urls, "file:// URL should be dropped"

    def test_invalid_keyword_weight_dropped(self, tmp_path):
        cfg = {
            "meta": {}, "settings": {},
            "data": {"groups": {"threat_intel": {
                "enabled": True,
                "keywords": {
                    "valid":       5,
                    "too_high":   11,    # invalid: > 10
                    "too_low":     0,    # invalid: < 1
                    "wrong_type": "x",   # invalid: not int
                },
                "feeds": [],
            }}}
        }
        self._write_config(tmp_path, cfg)

        with patch.object(_mod, "CONFIG_FILE", tmp_path / "prism_config.json"):
            with patch.object(_mod, "SCRIPT_DIR", tmp_path):
                config = _mod.load_config()

        kw = config["data"]["groups"]["threat_intel"]["keywords"]
        assert "valid"      in kw,     "valid keyword should be kept"
        assert "too_high"   not in kw, "weight 11 should be dropped"
        assert "too_low"    not in kw, "weight 0 should be dropped"
        assert "wrong_type" not in kw, "string weight should be dropped"


# =============================================================================
# HASH / DEDUP
# =============================================================================

class TestDedup:
    def test_same_title_url_same_hash(self):
        h1 = make_hash("CVE-2026-1234 exploit released", "https://example.com/article")
        h2 = make_hash("CVE-2026-1234 exploit released", "https://example.com/article")
        assert h1 == h2

    def test_different_url_different_hash(self):
        h1 = make_hash("Same title", "https://source1.com/article")
        h2 = make_hash("Same title", "https://source2.com/article")
        assert h1 != h2

    def test_hash_is_12_chars(self):
        h = make_hash("title", "https://example.com")
        assert len(h) == 12

    def test_hash_is_hex(self):
        h = make_hash("title", "https://example.com")
        int(h, 16)  # raises ValueError if not hex


# =============================================================================
# SECURITY REVERIFICATION SUMMARY
# Printed at the end of the test run as a checklist.
# Run this every 5 script iterations to catch regressions.
# =============================================================================

def test_security_checklist_meta():
    """
    Meta-test: verifies that the source code still contains the expected
    number of SECURITY comments. A drop indicates a comment was removed
    without justification -- potentially hiding a security decision.
    """
    src = _prism_path.read_text(encoding="utf-8")

    security_comments = src.count("# SECURITY:")
    verify_true_calls = src.count("verify=True")
    escape_calls      = src.count("_escape(")
    validate_calls    = src.count("validate_url(")
    sanitise_calls    = src.count("sanitise(")

    print(f"\n-- Security checklist ({_prism_path.name}) --")
    print(f"  # SECURITY: comments : {security_comments}")
    print(f"  verify=True calls     : {verify_true_calls}")
    print(f"  _escape() calls       : {escape_calls}")
    print(f"  validate_url() calls  : {validate_calls}")
    print(f"  sanitise() calls      : {sanitise_calls}")
    print(f"  Non-ASCII chars       : {sum(1 for c in src if ord(c) > 127)}")

    # Hard floors -- these must never go below baseline
    assert security_comments >= 10,  "Too few # SECURITY: comments -- review recent changes"
    assert verify_true_calls  >= 3,  "verify=True missing on some requests.get() calls"
    assert escape_calls       >= 10, "_escape() not applied to all HTML insertion points"
    assert validate_calls     >= 5,  "validate_url() not applied at all fetch points"
    assert sanitise_calls     >= 10, "sanitise() not applied to all external string inputs"
    assert sum(1 for c in src if ord(c) > 127) == 0, "Non-ASCII characters found in script"
