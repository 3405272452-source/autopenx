from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from config.settings import settings
from autopnex.web.api import app


def test_settings_api_reads_and_persists_env(tmp_path):
    original_env_path = settings.env_path
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "DEEPSEEK_API_KEY=",
                "DEEPSEEK_BASE_URL=https://api.deepseek.com",
                "DEEPSEEK_MODEL=deepseek-chat",
                "AUTOPENX_BURP_PROXY_URL=http://127.0.0.1:8080",
                "AUTOPENX_SCAN_MODE=active",
                "AUTOPENX_ALLOW_EXTERNAL_TOOLS=false",
                "AUTOPENX_ALLOW_LOCAL_TARGETS=false",
                "AUTOPENX_EXPLOIT_ENABLED=false",
            ]
        ),
        encoding="utf-8",
    )
    settings.env_path = env_path
    settings.reload()
    client = TestClient(app)

    try:
        current = client.get("/api/settings")
        assert current.status_code == 200
        assert current.json()["deepseek_model"] == "deepseek-chat"
        assert current.json()["allow_external_tools"] is False

        updated = client.put(
            "/api/settings",
            json={
                "api_key": "sk-test-value",
                "deepseek_base_url": "https://api.deepseek.com/v1",
                "deepseek_model": "deepseek-reasoner",
                "burp_proxy_url": "http://127.0.0.1:8081",
                "scan_mode": "passive",
                "allow_external_tools": True,
                "allow_local_targets": True,
                "exploit_enabled": True,
            },
        )
        assert updated.status_code == 200
        payload = updated.json()
        assert payload["has_api_key"] is True
        assert payload["deepseek_base_url"] == "https://api.deepseek.com/v1"
        assert payload["deepseek_model"] == "deepseek-reasoner"
        assert payload["burp_proxy_url"] == "http://127.0.0.1:8081"
        assert payload["scan_mode"] == "passive"
        assert payload["allow_external_tools"] is True
        assert payload["allow_local_targets"] is True
        assert payload["exploit_enabled"] is True

        contents = env_path.read_text(encoding="utf-8")
        assert "DEEPSEEK_API_KEY=sk-test-value" in contents
        assert "DEEPSEEK_MODEL=deepseek-reasoner" in contents
        assert "AUTOPENX_BURP_PROXY_URL=http://127.0.0.1:8081" in contents
        assert "AUTOPENX_SCAN_MODE=passive" in contents
        assert "AUTOPENX_ALLOW_EXTERNAL_TOOLS=true" in contents
        assert "AUTOPENX_ALLOW_LOCAL_TARGETS=true" in contents
        assert "AUTOPENX_EXPLOIT_ENABLED=true" in contents
    finally:
        settings.env_path = original_env_path
        settings.reload()


def test_health_reflects_settings_payload():
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert "llm_configured" in payload
    assert "model" in payload
    assert "capabilities" in payload


def test_approval_endpoint_returns_signed_token():
    client = TestClient(app)
    response = client.post(
        "/api/approvals",
        json={"target": "http://example.com", "scopes": ["passive", "active_scan"]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["token"]
    assert payload["scopes"] == ["passive", "active_scan"]
