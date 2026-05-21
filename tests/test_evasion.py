"""Evasion subsystem: PayloadMutator, RateController, WAFInfo."""
from __future__ import annotations

from urllib.parse import unquote

from autopnex.evasion.payload_mutator import (
    PayloadMutator,
    _double_url_encode,
    _case_alternation,
    _comment_insertion,
    MUTATION_STRATEGIES,
)
from autopnex.evasion.rate_controller import RateController, BROWSER_USER_AGENTS
from autopnex.evasion.waf_detector import WAFInfo


# ══════════════════════════════════════════════════════════════════════════
# PayloadMutator
# ══════════════════════════════════════════════════════════════════════════


def test_mutate_produces_variants():
    mutator = PayloadMutator()
    variants = mutator.mutate("' OR 1=1--", "sqli", "generic")
    assert len(variants) > 0
    assert all("strategy" in v and "payload" in v for v in variants)


def test_mutate_does_not_return_original():
    mutator = PayloadMutator()
    payload = "<script>alert(1)</script>"
    variants = mutator.mutate(payload, "xss", "cloudflare")
    for v in variants:
        assert v["payload"] != payload


def test_mutate_caps_at_max_variants():
    mutator = PayloadMutator()
    variants = mutator.mutate("' OR 1=1--", "sqli", "modsecurity")
    assert len(variants) <= 5


def test_all_strategies_produce_valid_output():
    payload = "SELECT * FROM users WHERE id='1'"
    for name, fn in MUTATION_STRATEGIES.items():
        result = fn(payload)
        assert isinstance(result, str), f"strategy {name} returned non-string"
        assert len(result) > 0, f"strategy {name} returned empty string"


# ── Specific strategy correctness ────────────────────────────────────────


def test_double_url_encode_correctness():
    result = _double_url_encode("'")
    decoded_once = unquote(result)
    decoded_twice = unquote(decoded_once)
    assert decoded_twice == "'"
    assert result != "'"
    assert "%" in result


def test_case_alternation_produces_mixed_case():
    result = _case_alternation("select")
    assert result != "select"
    assert result != "SELECT"
    has_upper = any(c.isupper() for c in result)
    has_lower = any(c.islower() for c in result)
    assert has_upper and has_lower


def test_comment_insertion_adds_inline_comments():
    result = _comment_insertion("SELECT")
    assert "/**/" in result
    assert result.replace("/**/", "") == "SELECT"


def test_mutate_batch():
    mutator = PayloadMutator()
    results = mutator.mutate_batch(
        ["' OR 1=1--", "1' AND 1=1--"],
        "sqli",
        "generic",
    )
    originals = [r for r in results if r["strategy"] == "original"]
    assert len(originals) == 2
    assert len(results) > 2


# ══════════════════════════════════════════════════════════════════════════
# RateController
# ══════════════════════════════════════════════════════════════════════════


def test_get_delay_within_range():
    rc = RateController(base_delay=1.0, jitter=0.2)
    delays = [rc.get_delay() for _ in range(50)]
    for d in delays:
        assert d >= 0.0


def test_backoff_on_429():
    rc = RateController(base_delay=0.5, jitter=0.0)
    initial_factor = rc.backoff_factor
    rc.on_response(429)
    assert rc.backoff_factor > initial_factor


def test_backoff_resets_on_200():
    rc = RateController(base_delay=0.5, jitter=0.0)
    rc.on_response(429)
    rc.on_response(429)
    high = rc.backoff_factor
    rc.on_response(200)
    assert rc.backoff_factor < high


def test_ua_rotation():
    rc = RateController()
    old_ua = rc.current_ua
    new_ua = rc.rotate_ua()
    assert new_ua in BROWSER_USER_AGENTS
    assert new_ua != old_ua or len(BROWSER_USER_AGENTS) == 1


def test_get_headers_returns_expected_keys():
    rc = RateController()
    headers = rc.get_headers()
    assert "User-Agent" in headers
    assert "Accept" in headers
    assert "Accept-Language" in headers
    assert "Accept-Encoding" in headers
    assert "Connection" in headers


def test_503_increases_backoff_less_than_429():
    rc1 = RateController(base_delay=0.5, jitter=0.0)
    rc2 = RateController(base_delay=0.5, jitter=0.0)
    rc1.on_response(429)
    rc2.on_response(503)
    assert rc1.backoff_factor > rc2.backoff_factor


# ══════════════════════════════════════════════════════════════════════════
# WAFInfo dataclass
# ══════════════════════════════════════════════════════════════════════════


def test_waf_info_creation():
    info = WAFInfo(
        detected=True,
        vendor="cloudflare",
        confidence=0.85,
        evidence=["header cf-ray"],
        block_status_code=403,
        bypass_level="aggressive",
    )
    assert info.detected is True
    assert info.vendor == "cloudflare"
    assert info.confidence == 0.85
    assert info.bypass_level == "aggressive"


def test_waf_info_defaults():
    info = WAFInfo(detected=False, vendor="none", confidence=0.0)
    assert info.evidence == []
    assert info.block_status_code is None
    assert info.bypass_level == "none"
