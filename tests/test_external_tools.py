from __future__ import annotations

from types import SimpleNamespace

from config.settings import settings
from autopnex.tools.base import ToolRegistry


def test_nmap_tool_parses_controlled_xml(monkeypatch):
    monkeypatch.setattr("autopnex.tools.base.shutil.which", lambda _binary: "/tmp/nmap")
    monkeypatch.setattr(
        "autopnex.tools.recon.nmap_scan.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="""
                <nmaprun>
                  <host>
                    <ports>
                      <port protocol="tcp" portid="80">
                        <state state="open" />
                        <service name="http" product="nginx" version="1.25" />
                      </port>
                    </ports>
                  </host>
                </nmaprun>
            """,
            stderr="",
        ),
    )
    runtime = settings.snapshot(allow_external_tools=True, approved_scopes=("active_scan",))
    result = ToolRegistry.execute("nmap_scan", {"target": "http://example.com"}, runtime)
    assert result.success is True
    assert result.parsed_data["open_ports"][0]["port"] == 80
    assert result.parsed_data["open_ports"][0]["service"] == "http"


def test_sqlmap_tool_parses_vulnerable_output(monkeypatch):
    monkeypatch.setattr("autopnex.tools.base.shutil.which", lambda _binary: "/tmp/sqlmap")
    monkeypatch.setattr(
        "autopnex.tools.vuln.sqlmap_scan.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="""
                [INFO] testing if parameter 'id' is dynamic
                [INFO] parameter 'id' appears to be injectable
                [INFO] back-end DBMS: MySQL
            """,
            stderr="",
        ),
    )
    runtime = settings.snapshot(allow_external_tools=True, approved_scopes=("active_scan",))
    result = ToolRegistry.execute(
        "sqlmap_scan",
        {"url": "http://example.com/item?id=1", "parameter": "id"},
        runtime,
    )
    assert result.success is True
    assert result.parsed_data["vulnerable"] is True
    assert result.parsed_data["dbms"] == "MySQL"


def test_external_tool_execution_blocked_when_disabled(monkeypatch):
    monkeypatch.setattr("autopnex.tools.base.shutil.which", lambda _binary: "/tmp/fake")
    runtime = settings.snapshot(allow_external_tools=False)
    result = ToolRegistry.execute("nmap_scan", {"target": "http://example.com"}, runtime)
    assert result.success is False
    assert result.error == "disabled_by_runtime_config"


def test_ffuf_tool_parses_json_lines(monkeypatch):
    monkeypatch.setattr("autopnex.tools.base.shutil.which", lambda _binary: "/tmp/ffuf")
    monkeypatch.setattr(
        "autopnex.tools.scan.ffuf_scan.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"url":"http://example.com/admin","status":200,"words":42,"length":1024}\n',
            stderr="",
        ),
    )
    runtime = settings.snapshot(allow_external_tools=True, approved_scopes=("active_scan",))
    result = ToolRegistry.execute("ffuf_scan", {"target": "http://example.com"}, runtime)
    assert result.success is True
    assert result.parsed_data["hits"][0]["url"] == "http://example.com/admin"


def test_burp_proxy_requires_proxy_url(monkeypatch):
    runtime = settings.snapshot(allow_external_tools=True, approved_scopes=("active_scan",), burp_proxy_url="")
    result = ToolRegistry.execute("burp_proxy_scan", {"target": "http://example.com"}, runtime)
    assert result.success is False
    assert result.error == "missing_burp_proxy_url"
