"""Property tests for DeepSeekSettings validation and masking.

**Property 17: 设置/API Key/配置项的合法性与脱敏**

Validates: Requirements 15.2, 15.10

Tests:
1. Valid DeepSeekSettings constructs successfully
2. api_key too short (<20) or too long (>200) rejected
3. temperature out of range rejected
4. ``__repr__`` does NOT contain the actual api_key value (masked)
5. ``has_valid_api_key`` returns True for valid settings, False for None
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings as h_settings
from hypothesis import strategies as st
from pydantic import SecretStr, ValidationError

from cet4_app.domain.settings_model import (
    API_KEY_MASK,
    DeepSeekSettings,
    has_valid_api_key,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Valid api_key: 20..200 printable ASCII characters
_valid_api_key = st.text(
    alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E),
    min_size=20,
    max_size=200,
)

# Valid temperature: 0.0..1.5
_valid_temperature = st.floats(min_value=0.0, max_value=1.5, allow_nan=False, allow_infinity=False)

# Valid max_output_tokens: 256..4096
_valid_max_output_tokens = st.integers(min_value=256, max_value=4096)

# Valid request_timeout_seconds: 5..120
_valid_timeout = st.integers(min_value=5, max_value=120)


# ---------------------------------------------------------------------------
# Test 1: Valid DeepSeekSettings constructs successfully
# ---------------------------------------------------------------------------


@h_settings(max_examples=100, deadline=None)
@given(
    api_key=_valid_api_key,
    temperature=_valid_temperature,
    max_output_tokens=_valid_max_output_tokens,
    timeout=_valid_timeout,
)
def test_valid_settings_construct_successfully(
    api_key: str,
    temperature: float,
    max_output_tokens: int,
    timeout: int,
) -> None:
    """Any combination of in-range parameters constructs without error."""
    settings = DeepSeekSettings(
        api_key=api_key,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
        request_timeout_seconds=timeout,
    )
    assert settings.api_key.get_secret_value() == api_key
    assert settings.temperature == temperature
    assert settings.max_output_tokens == max_output_tokens
    assert settings.request_timeout_seconds == timeout
    assert settings.base_url == "https://api.deepseek.com"
    assert settings.model == "deepseek-v4-flash"


# ---------------------------------------------------------------------------
# Test 2: api_key too short (<20) or too long (>200) rejected
# ---------------------------------------------------------------------------


@h_settings(max_examples=50, deadline=None)
@given(
    api_key=st.text(
        alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E),
        min_size=1,
        max_size=19,
    )
)
def test_api_key_too_short_rejected(api_key: str) -> None:
    """api_key shorter than 20 characters must be rejected."""
    with pytest.raises(ValidationError) as exc_info:
        DeepSeekSettings(api_key=api_key)
    errors = exc_info.value.errors()
    assert any("api_key" in str(e.get("loc", ())) for e in errors)


@h_settings(max_examples=50, deadline=None)
@given(
    api_key=st.text(
        alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E),
        min_size=201,
        max_size=300,
    )
)
def test_api_key_too_long_rejected(api_key: str) -> None:
    """api_key longer than 200 characters must be rejected."""
    with pytest.raises(ValidationError) as exc_info:
        DeepSeekSettings(api_key=api_key)
    errors = exc_info.value.errors()
    assert any("api_key" in str(e.get("loc", ())) for e in errors)


# ---------------------------------------------------------------------------
# Test 3: temperature out of range rejected
# ---------------------------------------------------------------------------


@h_settings(max_examples=50, deadline=None)
@given(
    temperature=st.one_of(
        st.floats(max_value=-0.01, allow_nan=False, allow_infinity=False),
        st.floats(min_value=1.51, max_value=100.0, allow_nan=False, allow_infinity=False),
    )
)
def test_temperature_out_of_range_rejected(temperature: float) -> None:
    """temperature outside [0.0, 1.5] must be rejected."""
    with pytest.raises(ValidationError) as exc_info:
        DeepSeekSettings(
            api_key="a" * 20,
            temperature=temperature,
        )
    errors = exc_info.value.errors()
    assert any("temperature" in str(e.get("loc", ())) for e in errors)


# ---------------------------------------------------------------------------
# Test 4: __repr__ does NOT contain the actual api_key value (masked)
# ---------------------------------------------------------------------------


@h_settings(max_examples=50, deadline=None)
@given(api_key=_valid_api_key)
def test_repr_does_not_contain_api_key(api_key: str) -> None:
    """The repr/str of DeepSeekSettings must mask api_key with '***'."""
    settings = DeepSeekSettings(api_key=api_key)
    repr_str = repr(settings)
    str_str = str(settings)

    # The actual key value must NOT appear
    assert api_key not in repr_str
    assert api_key not in str_str

    # The mask must appear
    assert API_KEY_MASK in repr_str


# ---------------------------------------------------------------------------
# Test 5: has_valid_api_key returns True for valid settings, False for None
# ---------------------------------------------------------------------------


def test_has_valid_api_key_returns_false_for_none() -> None:
    """has_valid_api_key(None) must return False."""
    assert has_valid_api_key(None) is False


@h_settings(max_examples=50, deadline=None)
@given(api_key=_valid_api_key)
def test_has_valid_api_key_returns_true_for_valid(api_key: str) -> None:
    """has_valid_api_key returns True when settings has a valid api_key (>=20 chars)."""
    settings = DeepSeekSettings(api_key=api_key)
    assert has_valid_api_key(settings) is True
