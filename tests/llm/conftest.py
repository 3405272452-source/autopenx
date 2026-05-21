"""Pytest fixtures for DeepSeek contract tests."""
from __future__ import annotations

import logging
from typing import Optional

import pytest

log = logging.getLogger("autopnex.tests.llm")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_deepseek: test requires DeepSeek API access (skipped if unavailable)"
    )
    config.addinivalue_line(
        "markers",
        "integration: integration tests that require external services"
    )


# ---------------------------------------------------------------------------
# LLM API availability check
# ---------------------------------------------------------------------------

_checked: Optional[bool] = None


def _deepseek_available() -> bool:
    global _checked
    if _checked is not None:
        return _checked
    try:
        from config.settings import settings
        if not settings.deepseek_api_key:
            _checked = False
            return False
        from openai import OpenAI
        client = OpenAI(
            api_key=settings.deepseek_api_key,
            base_url=settings.deepseek_base_url,
            timeout=10.0,
        )
        resp = client.chat.completions.create(
            model=settings.deepseek_model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=5,
        )
        _checked = bool(resp.choices and len(resp.choices) > 0)
        return _checked
    except Exception as e:
        log.warning("DeepSeek API check failed: %s", e)
        _checked = False
        return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def llm_available() -> bool:
    return _deepseek_available()


@pytest.fixture(scope="session")
def llm_client(llm_available: bool):
    """Return an LLMClient instance, or skip if unavailable."""
    if not llm_available:
        pytest.skip("DeepSeek API not available")

    from autopnex.orchestrator.llm_client import LLMClient
    return LLMClient()
