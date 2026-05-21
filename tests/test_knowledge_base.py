"""Knowledge base: PoCRegistry, CPEMatcher, dynamic_wordlist."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from autopnex.knowledge_base.poc_registry import PoCRegistry, PoCEntry
from autopnex.knowledge_base.cpe_matcher import CPEMatcher, CVEMatch
from autopnex.knowledge_base import dynamic_wordlist


# ══════════════════════════════════════════════════════════════════════════
# PoCRegistry
# ══════════════════════════════════════════════════════════════════════════


@pytest.fixture()
def poc_dir(tmp_path):
    """Create a temp directory with sample PoC JSON files."""
    entries = [
        {
            "poc_id": "poc-001",
            "vuln_type": "sqli",
            "title": "Union SQLi Generic",
            "tech_stack": ["php", "mysql"],
            "cve_ids": ["CVE-2023-0001"],
            "cvss_score": 9.1,
            "payload": "' UNION SELECT 1,2,3--",
            "expected_response": "column count mismatch",
            "waf_bypass": False,
            "severity": "CRITICAL",
            "description": "Union-based SQL injection",
        },
        {
            "poc_id": "poc-002",
            "vuln_type": "xss",
            "title": "Reflected XSS via img",
            "tech_stack": ["php"],
            "cve_ids": [],
            "cvss_score": 6.1,
            "payload": "<img src=x onerror=alert(1)>",
            "expected_response": "onerror",
            "waf_bypass": True,
            "severity": "HIGH",
            "description": "img onerror reflection",
        },
        {
            "poc_id": "poc-003",
            "vuln_type": "sqli",
            "title": "Error-based SQLi Django",
            "tech_stack": ["django", "postgresql"],
            "cve_ids": ["CVE-2022-34265"],
            "cvss_score": 8.5,
            "payload": "Trunc(kind='...') injection",
            "expected_response": "ProgrammingError",
            "waf_bypass": False,
            "severity": "HIGH",
            "description": "Error-based injection via Trunc",
        },
    ]
    poc_file = tmp_path / "sample.json"
    poc_file.write_text(json.dumps(entries), encoding="utf-8")
    return tmp_path


def test_poc_registry_loads_json(poc_dir):
    reg = PoCRegistry(poc_dir)
    assert len(reg.entries) == 3


def test_poc_registry_empty_dir(tmp_path):
    reg = PoCRegistry(tmp_path)
    assert reg.entries == []


def test_poc_registry_missing_dir(tmp_path):
    reg = PoCRegistry(tmp_path / "nonexistent")
    assert reg.entries == []


def test_poc_query_filters_by_vuln_type(poc_dir):
    reg = PoCRegistry(poc_dir)
    sqli = reg.query(vuln_type="sqli")
    assert len(sqli) == 2
    assert all(e.vuln_type == "sqli" for e in sqli)


def test_poc_query_returns_empty_for_unknown_type(poc_dir):
    reg = PoCRegistry(poc_dir)
    assert reg.query(vuln_type="rce") == []


def test_poc_query_ranks_by_tech_stack_overlap(poc_dir):
    reg = PoCRegistry(poc_dir)
    results = reg.query(vuln_type="sqli", tech_stack=["django", "postgresql"])
    assert results[0].poc_id == "poc-003"


def test_poc_query_waf_bypass_filter(poc_dir):
    reg = PoCRegistry(poc_dir)
    results = reg.query(waf_bypass=True)
    assert len(results) == 1
    assert results[0].waf_bypass is True


def test_poc_query_min_cvss_filter(poc_dir):
    reg = PoCRegistry(poc_dir)
    results = reg.query(min_cvss=8.0)
    assert all(e.cvss_score >= 8.0 for e in results)


def test_poc_query_limit(poc_dir):
    reg = PoCRegistry(poc_dir)
    results = reg.query(limit=1)
    assert len(results) == 1


# ══════════════════════════════════════════════════════════════════════════
# CPEMatcher
# ══════════════════════════════════════════════════════════════════════════


def test_cpe_matches_known_tech():
    matcher = CPEMatcher()
    results = matcher.match(["Apache 2.4.49"])
    assert len(results) > 0
    cve_ids = {r.cve_id for r in results}
    assert "CVE-2021-41773" in cve_ids


def test_cpe_version_match_flag():
    matcher = CPEMatcher()
    results = matcher.match(["Apache 2.4.49"])
    for r in results:
        if r.cve_id == "CVE-2021-41773":
            assert r.version_match is True


def test_cpe_returns_empty_for_unknown_tech():
    matcher = CPEMatcher()
    results = matcher.match(["unknownframework 99.0"])
    assert results == []


def test_cpe_matches_wordpress():
    matcher = CPEMatcher()
    results = matcher.match(["WordPress 5.5.0"])
    cve_ids = {r.cve_id for r in results}
    assert "CVE-2022-21661" in cve_ids


def test_cpe_deduplicates_results():
    matcher = CPEMatcher()
    results = matcher.match(["php 8.1.0", "PHP 8.1.0"])
    cve_ids = [r.cve_id for r in results]
    assert len(cve_ids) == len(set(cve_ids))


def test_cpe_no_version_returns_possible_match():
    matcher = CPEMatcher()
    results = matcher.match(["nginx"])
    assert len(results) > 0
    assert all(r.version_match is False for r in results)


def test_cpe_enrich_prompt_returns_markdown():
    matcher = CPEMatcher()
    text = matcher.enrich_prompt(["Apache 2.4.49"])
    assert "CVE" in text
    assert "###" in text


def test_cpe_enrich_prompt_empty_for_unknown():
    matcher = CPEMatcher()
    text = matcher.enrich_prompt(["unknowntech"])
    assert text == ""


# ══════════════════════════════════════════════════════════════════════════
# dynamic_wordlist
# ══════════════════════════════════════════════════════════════════════════


def test_generate_wordlist_includes_tech_paths():
    paths = dynamic_wordlist.generate_wordlist(["WordPress"], include_common=False)
    assert "/wp-admin/" in paths
    assert "/wp-login.php" in paths


def test_generate_wordlist_django_paths():
    paths = dynamic_wordlist.generate_wordlist(["Django"], include_common=False)
    assert "/admin/" in paths
    assert "/__debug__/" in paths


def test_generate_wordlist_unknown_tech_common_only():
    paths = dynamic_wordlist.generate_wordlist(["SuperUnknownFramework"], include_common=False)
    assert paths == []


def test_generate_wordlist_deduplicates():
    paths = dynamic_wordlist.generate_wordlist(
        ["WordPress", "wordpress"],
        include_common=False,
    )
    assert len(paths) == len(set(paths))


def test_generate_wordlist_spring_paths():
    paths = dynamic_wordlist.generate_wordlist(["Spring"], include_common=False)
    assert "/actuator" in paths
    assert "/actuator/health" in paths
