"""Tests for the RedactFilter and redact_text utility.

**Property 17: 设置/API Key/配置项的合法性与脱敏**

Validates: Requirements 15.2, 15.10

Tests:
1. ``redact_text`` replaces api_key=xxx with api_key=***
2. ``redact_text`` replaces Bearer xxx with Bearer ***
3. ``redact_text`` replaces JSON "api_key": "xxx" with "api_key": "***"
4. RedactFilter.filter mutates record.msg
"""

from __future__ import annotations

import logging

from hypothesis import given, settings as h_settings
from hypothesis import strategies as st

from cet4_app.infrastructure.logging.redact_filter import RedactFilter, redact_text


# ---------------------------------------------------------------------------
# Strategies for generating secret-like tokens
# ---------------------------------------------------------------------------

# Non-whitespace printable ASCII tokens (simulating API keys / Bearer tokens)
_secret_token = st.text(
    alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E),
    min_size=5,
    max_size=64,
)


# ---------------------------------------------------------------------------
# Test 1: redact_text replaces api_key=xxx with api_key=***
# ---------------------------------------------------------------------------


@h_settings(max_examples=100, deadline=None)
@given(secret=_secret_token)
def test_redact_text_replaces_api_key_equals(secret: str) -> None:
    """api_key=<secret> should become api_key=***."""
    text = f"config api_key={secret} done"
    result = redact_text(text)
    assert secret not in result
    assert "api_key=***" in result


@h_settings(max_examples=50, deadline=None)
@given(secret=_secret_token)
def test_redact_text_replaces_api_key_colon(secret: str) -> None:
    """api_key: <secret> should become api_key: ***."""
    text = f"config api_key: {secret} done"
    result = redact_text(text)
    assert secret not in result
    assert "api_key: ***" in result


@h_settings(max_examples=50, deadline=None)
@given(secret=_secret_token)
def test_redact_text_replaces_api_hyphen_key(secret: str) -> None:
    """api-key=<secret> should also be redacted."""
    text = f"header api-key={secret} end"
    result = redact_text(text)
    assert secret not in result
    assert "api-key=***" in result


# ---------------------------------------------------------------------------
# Test 2: redact_text replaces Bearer xxx with Bearer ***
# ---------------------------------------------------------------------------


@h_settings(max_examples=100, deadline=None)
@given(secret=_secret_token)
def test_redact_text_replaces_bearer_token(secret: str) -> None:
    """Bearer <token> should become Bearer ***."""
    text = f"Authorization: Bearer {secret}"
    result = redact_text(text)
    assert secret not in result
    assert "Bearer ***" in result


@h_settings(max_examples=50, deadline=None)
@given(secret=_secret_token)
def test_redact_text_replaces_bearer_case_insensitive(secret: str) -> None:
    """bearer <token> (lowercase) should also be redacted."""
    text = f"header: bearer {secret} end"
    result = redact_text(text)
    assert secret not in result
    assert "bearer ***" in result


# ---------------------------------------------------------------------------
# Test 3: redact_text replaces JSON "api_key": "xxx" with "api_key": "***"
# ---------------------------------------------------------------------------


@h_settings(max_examples=100, deadline=None)
@given(
    secret=st.text(
        # Avoid double-quote in secret since it would break JSON pattern
        alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E, blacklist_characters='"'),
        min_size=5,
        max_size=64,
    )
)
def test_redact_text_replaces_json_api_key(secret: str) -> None:
    '''"api_key": "<secret>" should become "api_key": "***".'''
    text = f'{{"api_key": "{secret}", "model": "deepseek"}}'
    result = redact_text(text)
    assert secret not in result
    assert '"api_key": "***"' in result


@h_settings(max_examples=50, deadline=None)
@given(
    secret=st.text(
        alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E, blacklist_characters='"'),
        min_size=5,
        max_size=64,
    )
)
def test_redact_text_replaces_json_apikey_variant(secret: str) -> None:
    '''"apikey": "<secret>" should also be redacted.'''
    text = f'{{"apikey": "{secret}"}}'
    result = redact_text(text)
    assert secret not in result
    assert '"apikey": "***"' in result


# ---------------------------------------------------------------------------
# Test 4: RedactFilter.filter mutates record.msg
# ---------------------------------------------------------------------------


@h_settings(max_examples=100, deadline=None)
@given(secret=_secret_token)
def test_redact_filter_mutates_record_msg(secret: str) -> None:
    """RedactFilter.filter should mutate record.msg to redact secrets."""
    filt = RedactFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=f"Calling API with api_key={secret}",
        args=None,
        exc_info=None,
    )
    result = filt.filter(record)

    # Filter always returns True (never drops records)
    assert result is True

    # The secret must be removed from the message
    assert secret not in record.msg
    assert "api_key=***" in record.msg


@h_settings(max_examples=50, deadline=None)
@given(secret=_secret_token)
def test_redact_filter_mutates_record_args_dict(secret: str) -> None:
    """RedactFilter should also redact string values in record.args (dict)."""
    filt = RedactFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Request with header",
        args=None,
        exc_info=None,
    )
    # Manually set args to a dict after construction to avoid LogRecord's
    # internal formatting check that trips on dict args.
    record.args = {"header": f"Bearer {secret}"}
    result = filt.filter(record)

    assert result is True
    assert secret not in record.args["header"]
    assert "Bearer ***" in record.args["header"]


@h_settings(max_examples=50, deadline=None)
@given(secret=_secret_token)
def test_redact_filter_mutates_record_args_tuple(secret: str) -> None:
    """RedactFilter should also redact string values in record.args (tuple)."""
    filt = RedactFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Key is %s",
        args=(f"api_key={secret}",),
        exc_info=None,
    )
    result = filt.filter(record)

    assert result is True
    assert secret not in record.args[0]
    assert "api_key=***" in record.args[0]
