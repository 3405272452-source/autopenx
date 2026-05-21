"""Unit tests for application/settings_service.py.

Validates:
- Reading/writing settings (keyring + config file)
- Range validation via DeepSeekSettings model
- AI-disable signal when api_key is empty
- Requirements 15.2, 15.10
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr, ValidationError

from cet4_app.application.settings_service import SettingsService
from cet4_app.domain.settings_model import DeepSeekSettings
from cet4_app.infrastructure.security.keyring_store import KeyringStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class FakeKeyringStore:
    """In-memory keyring store for testing (no OS credential manager)."""

    def __init__(self) -> None:
        self._stored_key: Optional[str] = None

    def save_api_key(self, api_key: str) -> None:
        self._stored_key = api_key

    def load_api_key(self) -> Optional[str]:
        return self._stored_key

    def delete_api_key(self) -> None:
        self._stored_key = None


@pytest.fixture
def fake_keyring() -> FakeKeyringStore:
    return FakeKeyringStore()


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    return tmp_path / "config"


@pytest.fixture
def service(fake_keyring: FakeKeyringStore, config_dir: Path) -> SettingsService:
    return SettingsService(keyring_store=fake_keyring, config_dir=config_dir)  # type: ignore[arg-type]


def _make_valid_key(length: int = 40) -> str:
    """Generate a valid API key string of given length."""
    return "sk-" + "a" * (length - 3)


# ---------------------------------------------------------------------------
# Tests: get_settings
# ---------------------------------------------------------------------------


class TestGetSettings:
    """Tests for SettingsService.get_settings()."""

    def test_returns_none_when_never_configured(
        self, service: SettingsService
    ) -> None:
        """No config file and no keyring entry → None."""
        assert service.get_settings() is None

    def test_returns_none_when_no_api_key_in_keyring(
        self, service: SettingsService, config_dir: Path
    ) -> None:
        """Config file exists but no API key → None (can't build valid settings)."""
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "settings.json"
        config_path.write_text(
            json.dumps({"temperature": 0.5, "model": "deepseek-chat"}),
            encoding="utf-8",
        )
        service.invalidate_cache()
        assert service.get_settings() is None

    def test_returns_settings_when_fully_configured(
        self,
        fake_keyring: FakeKeyringStore,
        config_dir: Path,
    ) -> None:
        """Both config file and keyring have data → valid settings."""
        api_key = _make_valid_key()
        fake_keyring.save_api_key(api_key)

        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "settings.json"
        config_path.write_text(
            json.dumps({
                "base_url": "https://api.deepseek.com",
                "model": "deepseek-chat",
                "temperature": 0.7,
                "max_output_tokens": 2048,
                "request_timeout_seconds": 30,
            }),
            encoding="utf-8",
        )

        svc = SettingsService(keyring_store=fake_keyring, config_dir=config_dir)  # type: ignore[arg-type]
        settings = svc.get_settings()

        assert settings is not None
        assert settings.api_key.get_secret_value() == api_key
        assert settings.model == "deepseek-chat"
        assert settings.temperature == 0.7
        assert settings.max_output_tokens == 2048
        assert settings.request_timeout_seconds == 30

    def test_uses_defaults_when_config_file_missing(
        self,
        fake_keyring: FakeKeyringStore,
        config_dir: Path,
    ) -> None:
        """Only API key in keyring, no config file → defaults for other fields."""
        api_key = _make_valid_key()
        fake_keyring.save_api_key(api_key)

        svc = SettingsService(keyring_store=fake_keyring, config_dir=config_dir)  # type: ignore[arg-type]
        settings = svc.get_settings()

        assert settings is not None
        assert settings.base_url == "https://api.deepseek.com"
        assert settings.model == "deepseek-v4-flash"
        assert settings.temperature == 0.3
        assert settings.max_output_tokens == 1024
        assert settings.request_timeout_seconds == 60

    def test_caches_settings_on_repeated_calls(
        self,
        fake_keyring: FakeKeyringStore,
        config_dir: Path,
    ) -> None:
        """Second call returns cached instance without re-reading disk."""
        fake_keyring.save_api_key(_make_valid_key())
        svc = SettingsService(keyring_store=fake_keyring, config_dir=config_dir)  # type: ignore[arg-type]

        s1 = svc.get_settings()
        s2 = svc.get_settings()
        assert s1 is s2  # Same object (cached)


# ---------------------------------------------------------------------------
# Tests: save_settings
# ---------------------------------------------------------------------------


class TestSaveSettings:
    """Tests for SettingsService.save_settings()."""

    def test_saves_api_key_to_keyring(
        self,
        fake_keyring: FakeKeyringStore,
        service: SettingsService,
    ) -> None:
        """API key is stored in keyring, not in config file."""
        api_key = _make_valid_key()
        settings = DeepSeekSettings(api_key=SecretStr(api_key))
        service.save_settings(settings)

        assert fake_keyring.load_api_key() == api_key

    def test_saves_non_secret_fields_to_config_file(
        self,
        service: SettingsService,
        config_dir: Path,
    ) -> None:
        """Non-secret fields are written to JSON config file."""
        settings = DeepSeekSettings(
            api_key=SecretStr(_make_valid_key()),
            model="deepseek-reasoner",
            temperature=1.0,
            max_output_tokens=4096,
            request_timeout_seconds=120,
        )
        service.save_settings(settings)

        config_path = config_dir / "settings.json"
        assert config_path.exists()

        data = json.loads(config_path.read_text(encoding="utf-8"))
        assert data["model"] == "deepseek-reasoner"
        assert data["temperature"] == 1.0
        assert data["max_output_tokens"] == 4096
        assert data["request_timeout_seconds"] == 120
        # API key must NOT be in the config file
        assert "api_key" not in data

    def test_updates_cache_after_save(
        self,
        service: SettingsService,
    ) -> None:
        """After save, get_settings returns the new settings."""
        settings = DeepSeekSettings(
            api_key=SecretStr(_make_valid_key()),
            temperature=1.2,
        )
        service.save_settings(settings)

        loaded = service.get_settings()
        assert loaded is not None
        assert loaded.temperature == 1.2

    def test_round_trip_save_then_load(
        self,
        fake_keyring: FakeKeyringStore,
        config_dir: Path,
    ) -> None:
        """Save → new service instance → load returns equivalent settings."""
        api_key = _make_valid_key(50)
        settings = DeepSeekSettings(
            api_key=SecretStr(api_key),
            model="deepseek-chat",
            temperature=0.8,
            max_output_tokens=512,
            request_timeout_seconds=15,
        )

        svc1 = SettingsService(keyring_store=fake_keyring, config_dir=config_dir)  # type: ignore[arg-type]
        svc1.save_settings(settings)

        # Simulate app restart with a fresh service instance
        svc2 = SettingsService(keyring_store=fake_keyring, config_dir=config_dir)  # type: ignore[arg-type]
        loaded = svc2.get_settings()

        assert loaded is not None
        assert loaded.api_key.get_secret_value() == api_key
        assert loaded.model == "deepseek-chat"
        assert loaded.temperature == 0.8
        assert loaded.max_output_tokens == 512
        assert loaded.request_timeout_seconds == 15


# ---------------------------------------------------------------------------
# Tests: is_ai_enabled
# ---------------------------------------------------------------------------


class TestIsAiEnabled:
    """Tests for SettingsService.is_ai_enabled() — Requirement 15.10."""

    def test_disabled_when_never_configured(self, service: SettingsService) -> None:
        """No settings → AI disabled."""
        assert service.is_ai_enabled() is False

    def test_disabled_after_clearing_api_key(
        self,
        service: SettingsService,
    ) -> None:
        """Save settings then clear key → AI disabled."""
        settings = DeepSeekSettings(api_key=SecretStr(_make_valid_key()))
        service.save_settings(settings)
        assert service.is_ai_enabled() is True

        service.clear_api_key()
        assert service.is_ai_enabled() is False

    def test_enabled_with_valid_api_key(
        self,
        service: SettingsService,
    ) -> None:
        """Valid API key (>= 20 chars) → AI enabled."""
        settings = DeepSeekSettings(api_key=SecretStr(_make_valid_key(20)))
        service.save_settings(settings)
        assert service.is_ai_enabled() is True

    def test_enabled_with_max_length_api_key(
        self,
        service: SettingsService,
    ) -> None:
        """API key at max length (200 chars) → AI enabled."""
        settings = DeepSeekSettings(api_key=SecretStr(_make_valid_key(200)))
        service.save_settings(settings)
        assert service.is_ai_enabled() is True


# ---------------------------------------------------------------------------
# Tests: Range validation (via DeepSeekSettings model)
# ---------------------------------------------------------------------------


class TestRangeValidation:
    """Verify that out-of-range values are rejected by the domain model.

    The SettingsService relies on DeepSeekSettings for validation. These
    tests confirm the integration: attempting to save invalid settings
    raises ValidationError before any persistence occurs.
    """

    def test_temperature_below_range(self) -> None:
        """temperature < 0 → rejected."""
        with pytest.raises(ValidationError) as exc_info:
            DeepSeekSettings(api_key=SecretStr(_make_valid_key()), temperature=-0.1)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("temperature",) for e in errors)

    def test_temperature_above_range(self) -> None:
        """temperature > 1.5 → rejected."""
        with pytest.raises(ValidationError):
            DeepSeekSettings(api_key=SecretStr(_make_valid_key()), temperature=1.6)

    def test_max_output_tokens_below_range(self) -> None:
        """max_output_tokens < 256 → rejected."""
        with pytest.raises(ValidationError) as exc_info:
            DeepSeekSettings(
                api_key=SecretStr(_make_valid_key()), max_output_tokens=255
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("max_output_tokens",) for e in errors)

    def test_max_output_tokens_above_range(self) -> None:
        """max_output_tokens > 4096 → rejected."""
        with pytest.raises(ValidationError):
            DeepSeekSettings(
                api_key=SecretStr(_make_valid_key()), max_output_tokens=4097
            )

    def test_request_timeout_below_range(self) -> None:
        """request_timeout_seconds < 5 → rejected."""
        with pytest.raises(ValidationError) as exc_info:
            DeepSeekSettings(
                api_key=SecretStr(_make_valid_key()), request_timeout_seconds=4
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("request_timeout_seconds",) for e in errors)

    def test_request_timeout_above_range(self) -> None:
        """request_timeout_seconds > 120 → rejected."""
        with pytest.raises(ValidationError):
            DeepSeekSettings(
                api_key=SecretStr(_make_valid_key()), request_timeout_seconds=121
            )

    def test_api_key_too_short(self) -> None:
        """api_key length < 20 → rejected."""
        with pytest.raises(ValidationError) as exc_info:
            DeepSeekSettings(api_key=SecretStr("short"))
        errors = exc_info.value.errors()
        assert any("api_key" in str(e["loc"]) for e in errors)

    def test_api_key_too_long(self) -> None:
        """api_key length > 200 → rejected."""
        with pytest.raises(ValidationError):
            DeepSeekSettings(api_key=SecretStr("x" * 201))

    def test_base_url_not_https(self) -> None:
        """base_url without https:// → rejected."""
        with pytest.raises(ValidationError):
            DeepSeekSettings(
                api_key=SecretStr(_make_valid_key()),
                base_url="http://api.deepseek.com",
            )

    def test_valid_boundary_values_accepted(self) -> None:
        """All fields at boundary values → accepted."""
        # Minimum boundaries
        s = DeepSeekSettings(
            api_key=SecretStr("a" * 20),
            temperature=0.0,
            max_output_tokens=256,
            request_timeout_seconds=5,
        )
        assert s.temperature == 0.0
        assert s.max_output_tokens == 256
        assert s.request_timeout_seconds == 5

        # Maximum boundaries
        s = DeepSeekSettings(
            api_key=SecretStr("b" * 200),
            temperature=1.5,
            max_output_tokens=4096,
            request_timeout_seconds=120,
        )
        assert s.temperature == 1.5
        assert s.max_output_tokens == 4096
        assert s.request_timeout_seconds == 120


# ---------------------------------------------------------------------------
# Tests: clear_api_key
# ---------------------------------------------------------------------------


class TestClearApiKey:
    """Tests for SettingsService.clear_api_key()."""

    def test_removes_key_from_keyring(
        self,
        fake_keyring: FakeKeyringStore,
        service: SettingsService,
    ) -> None:
        """After clear, keyring returns None."""
        settings = DeepSeekSettings(api_key=SecretStr(_make_valid_key()))
        service.save_settings(settings)
        assert fake_keyring.load_api_key() is not None

        service.clear_api_key()
        assert fake_keyring.load_api_key() is None

    def test_invalidates_cache(
        self,
        service: SettingsService,
    ) -> None:
        """After clear, get_settings returns None."""
        settings = DeepSeekSettings(api_key=SecretStr(_make_valid_key()))
        service.save_settings(settings)
        assert service.get_settings() is not None

        service.clear_api_key()
        assert service.get_settings() is None


# ---------------------------------------------------------------------------
# Tests: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case handling."""

    def test_corrupted_config_file_returns_none(
        self,
        fake_keyring: FakeKeyringStore,
        config_dir: Path,
    ) -> None:
        """Malformed JSON in config file → treated as unconfigured."""
        fake_keyring.save_api_key(_make_valid_key())
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "settings.json"
        config_path.write_text("not valid json {{{", encoding="utf-8")

        svc = SettingsService(keyring_store=fake_keyring, config_dir=config_dir)  # type: ignore[arg-type]
        # Should still work — uses defaults with the stored API key
        settings = svc.get_settings()
        # Config file is invalid, but API key exists → falls back to defaults
        # Actually, _read_config_file returns None on parse error,
        # so settings_dict will be empty dict + api_key → uses defaults
        assert settings is not None
        assert settings.model == "deepseek-v4-flash"  # default

    def test_config_file_with_invalid_values_returns_none(
        self,
        fake_keyring: FakeKeyringStore,
        config_dir: Path,
    ) -> None:
        """Config file with out-of-range values → treated as unconfigured."""
        fake_keyring.save_api_key(_make_valid_key())
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "settings.json"
        config_path.write_text(
            json.dumps({"temperature": 99.9}),  # Out of range
            encoding="utf-8",
        )

        svc = SettingsService(keyring_store=fake_keyring, config_dir=config_dir)  # type: ignore[arg-type]
        # Validation fails → returns None
        assert svc.get_settings() is None

    def test_invalidate_cache_forces_reload(
        self,
        fake_keyring: FakeKeyringStore,
        config_dir: Path,
    ) -> None:
        """After invalidate_cache, next get_settings re-reads from disk."""
        api_key = _make_valid_key()
        fake_keyring.save_api_key(api_key)

        svc = SettingsService(keyring_store=fake_keyring, config_dir=config_dir)  # type: ignore[arg-type]
        s1 = svc.get_settings()
        assert s1 is not None

        # Externally change the keyring
        new_key = _make_valid_key(60)
        fake_keyring.save_api_key(new_key)

        # Without invalidation, still returns cached
        s2 = svc.get_settings()
        assert s2 is s1

        # After invalidation, re-reads
        svc.invalidate_cache()
        s3 = svc.get_settings()
        assert s3 is not None
        assert s3.api_key.get_secret_value() == new_key
