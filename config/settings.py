"""Runtime configuration and .env persistence helpers."""
from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple

try:
    from dotenv import dotenv_values, set_key
except ImportError:  # pragma: no cover
    dotenv_values = None
    set_key = None


ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
_ACTIVE_RUNTIME: ContextVar[Optional["RuntimeConfig"]] = ContextVar("autopnex_runtime_config", default=None)


def _pick(values: Dict[str, str], name: str, default: str = "") -> str:
    raw = os.getenv(name)
    if raw is None:
        raw = values.get(name, default)
    return str(raw or default).strip()


def _int(values: Dict[str, str], name: str, default: int) -> int:
    raw = _pick(values, name, str(default))
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _float(values: Dict[str, str], name: str, default: float) -> float:
    raw = _pick(values, name, str(default))
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


def _bool(values: Dict[str, str], name: str, default: bool) -> bool:
    raw = _pick(values, name, "true" if default else "false").lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


def _mask_secret(secret: str) -> str:
    secret = (secret or "").strip()
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}...{secret[-4:]}"


@dataclass(frozen=True)
class RuntimeConfig:
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    burp_proxy_url: str = ""
    scan_mode: str = "active"  # passive | active
    allow_external_tools: bool = False
    allow_local_targets: bool = False
    exploit_enabled: bool = False
    approved_scopes: Tuple[str, ...] = ()
    approval_token: str = ""
    approval_expires_at: str = ""
    approval_ttl_seconds: int = 900
    max_iter_per_state: int = 6
    http_timeout: int = 8
    user_agent: str = "AutoPenX/0.1"
    request_delay: float = 0.0
    policy_hmac_key: str = ""
    multi_agent_enabled: bool = False
    max_concurrent_tools: int = 4
    evasion_enabled: bool = False
    waf_bypass_level: str = "none"  # none | light | aggressive
    evasion_proxy_list: str = ""
    evasion_base_delay: float = 0.5
    docker_enabled: bool = False
    docker_image: str = "shannon-tools"
    browser_testing: bool = True
    playwright_timeout: int = 30000
    login_endpoint: str = ""
    login_username_field: str = "username"
    login_password_field: str = "password"
    login_credentials: str = "admin:password,admin:admin,root:root"
    csrf_field: str = ""
    ctf_auto_tooling_enabled: bool = True
    ctf_tool_install_enabled: bool = True
    ctf_workspace_dir: str = "ctf_workspace"

    @property
    def has_llm(self) -> bool:
        return bool(self.deepseek_api_key)

    @property
    def api_key_preview(self) -> str:
        return _mask_secret(self.deepseek_api_key)

    def to_client_dict(self) -> Dict[str, object]:
        return {
            "has_api_key": self.has_llm,
            "api_key_preview": self.api_key_preview,
            "deepseek_base_url": self.deepseek_base_url,
            "deepseek_model": self.deepseek_model,
            "burp_proxy_url": self.burp_proxy_url,
            "scan_mode": self.scan_mode,
            "allow_external_tools": self.allow_external_tools,
            "allow_local_targets": self.allow_local_targets,
            "exploit_enabled": self.exploit_enabled,
            "approved_scopes": list(self.approved_scopes),
            "approval_token_present": bool(self.approval_token),
            "approval_expires_at": self.approval_expires_at,
            "approval_ttl_seconds": self.approval_ttl_seconds,
            "max_iter_per_state": self.max_iter_per_state,
            "http_timeout": self.http_timeout,
            "user_agent": self.user_agent,
            "request_delay": self.request_delay,
            "multi_agent_enabled": self.multi_agent_enabled,
            "max_concurrent_tools": self.max_concurrent_tools,
            "evasion_enabled": self.evasion_enabled,
            "waf_bypass_level": self.waf_bypass_level,
            "evasion_proxy_list": self.evasion_proxy_list,
            "evasion_base_delay": self.evasion_base_delay,
            "docker_enabled": self.docker_enabled,
            "docker_image": self.docker_image,
            "browser_testing": self.browser_testing,
            "playwright_timeout": self.playwright_timeout,
            "login_endpoint": self.login_endpoint,
            "login_username_field": self.login_username_field,
            "login_password_field": self.login_password_field,
            "login_credentials": self.login_credentials,
            "csrf_field": self.csrf_field,
            "ctf_auto_tooling_enabled": self.ctf_auto_tooling_enabled,
            "ctf_tool_install_enabled": self.ctf_tool_install_enabled,
            "ctf_workspace_dir": self.ctf_workspace_dir,
        }


class Settings:
    def __init__(self, env_path: Path = ENV_PATH):
        self.env_path = env_path
        self.deepseek_api_key = ""
        self.deepseek_base_url = "https://api.deepseek.com"
        self.deepseek_model = "deepseek-chat"
        self.burp_proxy_url = ""
        self.scan_mode = "active"
        self.allow_external_tools = False
        self.allow_local_targets = False
        self.exploit_enabled = False
        self.approved_scopes = ()
        self.approval_token = ""
        self.approval_expires_at = ""
        self.approval_ttl_seconds = 900
        self.max_iter_per_state = 6
        self.http_timeout = 8
        self.user_agent = "AutoPenX/0.1"
        self.policy_hmac_key = ""
        self.request_delay = 0.0
        self.multi_agent_enabled = False
        self.max_concurrent_tools = 4
        self.evasion_enabled = False
        self.waf_bypass_level = "none"
        self.evasion_proxy_list = ""
        self.evasion_base_delay = 0.5
        self.docker_enabled = False
        self.docker_image = "shannon-tools"
        self.browser_testing = True
        self.playwright_timeout = 30000
        self.login_endpoint = ""
        self.login_username_field = "username"
        self.login_password_field = "password"
        self.login_credentials = "admin:password,admin:admin,root:root"
        self.csrf_field = ""
        self.ctf_auto_tooling_enabled = True
        self.ctf_tool_install_enabled = True
        self.ctf_workspace_dir = "ctf_workspace"
        self.reload()

    def _env_values(self) -> Dict[str, str]:
        if dotenv_values is None or not self.env_path.exists():
            return {}
        return {k: str(v) for k, v in dotenv_values(self.env_path).items() if k and v is not None}

    def reload(self) -> RuntimeConfig:
        values = self._env_values()
        runtime = RuntimeConfig(
            deepseek_api_key=_pick(values, "DEEPSEEK_API_KEY"),
            deepseek_base_url=_pick(values, "DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            deepseek_model=_pick(values, "DEEPSEEK_MODEL", "deepseek-chat"),
            burp_proxy_url=_pick(values, "AUTOPENX_BURP_PROXY_URL"),
            scan_mode=_pick(values, "AUTOPENX_SCAN_MODE", "active") or "active",
            allow_external_tools=_bool(values, "AUTOPENX_ALLOW_EXTERNAL_TOOLS", False),
            allow_local_targets=_bool(values, "AUTOPENX_ALLOW_LOCAL_TARGETS", False),
            exploit_enabled=_bool(values, "AUTOPENX_EXPLOIT_ENABLED", False),
            approved_scopes=tuple(),
            approval_token="",
            approval_expires_at="",
            approval_ttl_seconds=_int(values, "AUTOPENX_APPROVAL_TTL_SECONDS", 900),
            max_iter_per_state=_int(values, "AUTOPENX_MAX_ITER_PER_STATE", 6),
            http_timeout=_int(values, "AUTOPENX_HTTP_TIMEOUT", 8),
            user_agent=_pick(values, "AUTOPENX_USER_AGENT", "AutoPenX/0.1"),
            policy_hmac_key=_pick(values, "AUTOPENX_POLICY_HMAC_KEY"),
            request_delay=_float(values, "AUTOPENX_REQUEST_DELAY", 0.0),
            multi_agent_enabled=_bool(values, "AUTOPENX_MULTI_AGENT_ENABLED", False),
            max_concurrent_tools=_int(values, "AUTOPENX_MAX_CONCURRENT_TOOLS", 4),
            evasion_enabled=_bool(values, "AUTOPENX_EVASION_ENABLED", False),
            waf_bypass_level=_pick(values, "AUTOPENX_WAF_BYPASS_LEVEL", "none") or "none",
            evasion_proxy_list=_pick(values, "AUTOPENX_EVASION_PROXY_LIST", ""),
            evasion_base_delay=_float(values, "AUTOPENX_EVASION_BASE_DELAY", 0.5),
            docker_enabled=_bool(values, "AUTOPENX_DOCKER_ENABLED", False),
            docker_image=_pick(values, "AUTOPENX_DOCKER_IMAGE", "shannon-tools"),
            browser_testing=_bool(values, "AUTOPENX_BROWSER_TESTING", True),
            playwright_timeout=_int(values, "AUTOPENX_PLAYWRIGHT_TIMEOUT", 30000),
            login_endpoint=_pick(values, "AUTOPENX_LOGIN_ENDPOINT", ""),
            login_username_field=_pick(values, "AUTOPENX_LOGIN_USERNAME_FIELD", "username"),
            login_password_field=_pick(values, "AUTOPENX_LOGIN_PASSWORD_FIELD", "password"),
            login_credentials=_pick(values, "AUTOPENX_LOGIN_CREDENTIALS", "admin:password,admin:admin,root:root"),
            csrf_field=_pick(values, "AUTOPENX_CSRF_FIELD", ""),
            ctf_auto_tooling_enabled=_bool(values, "AUTOPENX_CTF_AUTO_TOOLING_ENABLED", True),
            ctf_tool_install_enabled=_bool(values, "AUTOPENX_CTF_TOOL_INSTALL_ENABLED", True),
            ctf_workspace_dir=_pick(values, "AUTOPENX_CTF_WORKSPACE_DIR", "ctf_workspace"),
        )
        self._apply(runtime)
        return runtime

    def _apply(self, runtime: RuntimeConfig) -> None:
        self.deepseek_api_key = runtime.deepseek_api_key
        self.deepseek_base_url = runtime.deepseek_base_url
        self.deepseek_model = runtime.deepseek_model
        self.burp_proxy_url = runtime.burp_proxy_url
        self.scan_mode = runtime.scan_mode
        self.allow_external_tools = runtime.allow_external_tools
        self.allow_local_targets = runtime.allow_local_targets
        self.exploit_enabled = runtime.exploit_enabled
        self.approved_scopes = runtime.approved_scopes
        self.approval_token = runtime.approval_token
        self.approval_expires_at = runtime.approval_expires_at
        self.approval_ttl_seconds = runtime.approval_ttl_seconds
        self.max_iter_per_state = runtime.max_iter_per_state
        self.http_timeout = runtime.http_timeout
        self.user_agent = runtime.user_agent
        self.policy_hmac_key = runtime.policy_hmac_key
        self.request_delay = runtime.request_delay
        self.multi_agent_enabled = runtime.multi_agent_enabled
        self.max_concurrent_tools = runtime.max_concurrent_tools
        self.evasion_enabled = runtime.evasion_enabled
        self.waf_bypass_level = runtime.waf_bypass_level
        self.evasion_proxy_list = runtime.evasion_proxy_list
        self.evasion_base_delay = runtime.evasion_base_delay
        self.docker_enabled = runtime.docker_enabled
        self.docker_image = runtime.docker_image
        self.browser_testing = runtime.browser_testing
        self.playwright_timeout = runtime.playwright_timeout
        self.login_endpoint = runtime.login_endpoint
        self.login_username_field = runtime.login_username_field
        self.login_password_field = runtime.login_password_field
        self.login_credentials = runtime.login_credentials
        self.csrf_field = runtime.csrf_field
        self.ctf_auto_tooling_enabled = runtime.ctf_auto_tooling_enabled
        self.ctf_tool_install_enabled = runtime.ctf_tool_install_enabled
        self.ctf_workspace_dir = runtime.ctf_workspace_dir

    @property
    def has_llm(self) -> bool:
        return bool(self.deepseek_api_key)

    def snapshot(self, **overrides: object) -> RuntimeConfig:
        data = {
            "deepseek_api_key": self.deepseek_api_key,
            "deepseek_base_url": self.deepseek_base_url,
            "deepseek_model": self.deepseek_model,
            "burp_proxy_url": self.burp_proxy_url,
            "scan_mode": self.scan_mode,
            "allow_external_tools": self.allow_external_tools,
            "allow_local_targets": self.allow_local_targets,
            "exploit_enabled": self.exploit_enabled,
            "approved_scopes": self.approved_scopes,
            "approval_token": self.approval_token,
            "approval_expires_at": self.approval_expires_at,
            "approval_ttl_seconds": self.approval_ttl_seconds,
            "max_iter_per_state": self.max_iter_per_state,
            "http_timeout": self.http_timeout,
            "user_agent": self.user_agent,
            "policy_hmac_key": self.policy_hmac_key,
            "request_delay": self.request_delay,
            "multi_agent_enabled": self.multi_agent_enabled,
            "max_concurrent_tools": self.max_concurrent_tools,
            "evasion_enabled": self.evasion_enabled,
            "waf_bypass_level": self.waf_bypass_level,
            "evasion_proxy_list": self.evasion_proxy_list,
            "evasion_base_delay": self.evasion_base_delay,
            "docker_enabled": self.docker_enabled,
            "docker_image": self.docker_image,
            "browser_testing": self.browser_testing,
            "playwright_timeout": self.playwright_timeout,
            "login_endpoint": self.login_endpoint,
            "login_username_field": self.login_username_field,
            "login_password_field": self.login_password_field,
            "login_credentials": self.login_credentials,
            "csrf_field": self.csrf_field,
            "ctf_auto_tooling_enabled": self.ctf_auto_tooling_enabled,
            "ctf_tool_install_enabled": self.ctf_tool_install_enabled,
            "ctf_workspace_dir": self.ctf_workspace_dir,
        }
        for key, value in overrides.items():
            if value is not None:
                data[key] = value
        return RuntimeConfig(**data)

    def effective(self) -> RuntimeConfig:
        return _ACTIVE_RUNTIME.get() or self.snapshot()

    @contextmanager
    def use_runtime(self, runtime: Optional[RuntimeConfig]) -> Iterator[None]:
        token = _ACTIVE_RUNTIME.set(runtime)
        try:
            yield
        finally:
            _ACTIVE_RUNTIME.reset(token)

    def save_ui_settings(
        self,
        *,
        api_key: Optional[str] = None,
        clear_api_key: bool = False,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        burp_proxy_url: Optional[str] = None,
        scan_mode: Optional[str] = None,
        allow_external_tools: Optional[bool] = None,
        allow_local_targets: Optional[bool] = None,
        exploit_enabled: Optional[bool] = None,
    ) -> RuntimeConfig:
        if set_key is None:  # pragma: no cover
            raise RuntimeError("python-dotenv is required to persist settings")

        self.env_path.parent.mkdir(parents=True, exist_ok=True)
        self.env_path.touch(exist_ok=True)

        if api_key is not None:
            set_key(str(self.env_path), "DEEPSEEK_API_KEY", api_key.strip(), quote_mode="never", encoding="utf-8")
        elif clear_api_key:
            set_key(str(self.env_path), "DEEPSEEK_API_KEY", "", quote_mode="never", encoding="utf-8")

        if base_url is not None:
            set_key(str(self.env_path), "DEEPSEEK_BASE_URL", base_url.strip(), quote_mode="never", encoding="utf-8")
        if model is not None:
            set_key(str(self.env_path), "DEEPSEEK_MODEL", model.strip(), quote_mode="never", encoding="utf-8")
        if burp_proxy_url is not None:
            set_key(str(self.env_path), "AUTOPENX_BURP_PROXY_URL", burp_proxy_url.strip(), quote_mode="never", encoding="utf-8")
        if scan_mode is not None:
            set_key(str(self.env_path), "AUTOPENX_SCAN_MODE", scan_mode.strip(), quote_mode="never", encoding="utf-8")
        if allow_external_tools is not None:
            set_key(
                str(self.env_path),
                "AUTOPENX_ALLOW_EXTERNAL_TOOLS",
                "true" if allow_external_tools else "false",
                quote_mode="never",
                encoding="utf-8",
            )
        if allow_local_targets is not None:
            set_key(
                str(self.env_path),
                "AUTOPENX_ALLOW_LOCAL_TARGETS",
                "true" if allow_local_targets else "false",
                quote_mode="never",
                encoding="utf-8",
            )
        if exploit_enabled is not None:
            set_key(
                str(self.env_path),
                "AUTOPENX_EXPLOIT_ENABLED",
                "true" if exploit_enabled else "false",
                quote_mode="never",
                encoding="utf-8",
            )
        return self.reload()


settings = Settings()
