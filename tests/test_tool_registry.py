"""Tool base / registry smoke tests."""
from __future__ import annotations

from autopnex.tools.base import BaseTool, ToolRegistry, ToolResult


EXPECTED = {
    "port_scan", "tech_detect", "subdomain_find", "nmap_scan",
    "web_scan", "dir_buster", "crawl", "ffuf_scan", "burp_proxy_scan",
    "sqli_detect", "xss_detect", "ssrf_detect", "cmdi_detect", "sqlmap_scan",
    "sqli_exploit", "finding_replay",
}


def test_all_tools_registered():
    names = {t.name for t in ToolRegistry.all()}
    missing = EXPECTED - names
    assert not missing, f"missing tools: {missing}"


def test_openai_schemas_shape():
    schemas = ToolRegistry.openai_schemas()
    assert schemas and all(s["type"] == "function" for s in schemas)
    for s in schemas:
        fn = s["function"]
        assert "name" in fn and "description" in fn and "parameters" in fn
        assert fn["parameters"]["type"] == "object"


def test_execute_unknown_tool_returns_error():
    result = ToolRegistry.execute("nope", {})
    assert not result.success
    assert result.error == "tool_not_registered"


def test_tool_result_to_llm_message_roundtrip():
    r = ToolResult(success=True, tool="demo", summary="ok", parsed_data={"a": 1})
    msg = r.to_llm_message()
    import json

    data = json.loads(msg)
    assert data["success"] is True
    assert data["parsed_data"] == {"a": 1}


def test_external_tools_hidden_when_runtime_disables_them():
    from config.settings import settings

    runtime = settings.snapshot(allow_external_tools=False)
    recon_names = {schema["function"]["name"] for schema in ToolRegistry.openai_schemas(["recon"], runtime)}
    scan_names = {schema["function"]["name"] for schema in ToolRegistry.openai_schemas(["scan"], runtime)}
    vuln_names = {schema["function"]["name"] for schema in ToolRegistry.openai_schemas(["vuln"], runtime)}
    assert "nmap_scan" not in recon_names
    assert "ffuf_scan" not in scan_names
    assert "burp_proxy_scan" not in scan_names
    assert "sqlmap_scan" not in vuln_names
