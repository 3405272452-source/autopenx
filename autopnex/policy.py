"""Policy helpers for approvals, scopes and runtime constraints."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Iterable, Tuple

from config.settings import RuntimeConfig, settings


VALID_SCOPES = ("passive", "active_scan", "auth_required", "exploit")
SCAN_MODES = ("passive", "active")


class PolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class Approval:
    token: str
    scopes: Tuple[str, ...]
    target: str
    expires_at: int


_SECRET_CACHE: Dict[str, str] = {}


def _secret() -> bytes:
    seed = (settings.policy_hmac_key or "").strip()
    if not seed:
        if "key" not in _SECRET_CACHE:
            _SECRET_CACHE["key"] = secrets.token_hex(32)
        seed = _SECRET_CACHE["key"]
    return hashlib.sha256(seed.encode("utf-8")).digest()


def normalise_scopes(scopes: Iterable[str]) -> Tuple[str, ...]:
    unique = []
    for scope in scopes:
        if scope not in VALID_SCOPES:
            raise PolicyError(f"invalid_scope:{scope}")
        if scope not in unique:
            unique.append(scope)
    return tuple(unique)


def create_approval(target: str, scopes: Iterable[str], ttl_seconds: int) -> Approval:
    if not target or target.strip() == "*":
        raise PolicyError("wildcard_target_not_allowed")
    now = int(time.time())
    expires_at = now + max(30, int(ttl_seconds or 0))
    payload = {
        "target": target,
        "scopes": list(normalise_scopes(scopes)),
        "iat": now,
        "exp": expires_at,
        "nonce": secrets.token_hex(8),
    }
    blob = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(_secret(), blob, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=") + "." + base64.urlsafe_b64encode(signature).decode(
        "ascii"
    ).rstrip("=")
    return Approval(token=token, scopes=tuple(payload["scopes"]), target=target, expires_at=expires_at)


def validate_approval(token: str, *, target: str) -> Approval:
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError as exc:
        raise PolicyError("invalid_token_format") from exc
    payload_bytes = base64.urlsafe_b64decode(_pad(payload_b64))
    expected = hmac.new(_secret(), payload_bytes, hashlib.sha256).digest()
    supplied = base64.urlsafe_b64decode(_pad(sig_b64))
    if not hmac.compare_digest(expected, supplied):
        raise PolicyError("invalid_token_signature")
    payload = json.loads(payload_bytes.decode("utf-8"))
    if int(payload.get("exp", 0)) < int(time.time()):
        raise PolicyError("approval_expired")
    approved_target = str(payload.get("target") or "")
    if approved_target == "*":
        raise PolicyError("wildcard_target_not_allowed")
    if approved_target != target:
        raise PolicyError("approval_target_mismatch")
    scopes = normalise_scopes(payload.get("scopes") or [])
    return Approval(token=token, scopes=scopes, target=approved_target, expires_at=int(payload["exp"]))


def apply_scan_policy(
    base_runtime: RuntimeConfig,
    *,
    target: str,
    scan_mode: str | None = None,
    allow_external_tools: bool | None = None,
    allow_local_targets: bool | None = None,
    exploit_enabled: bool | None = None,
    approval_token: str | None = None,
) -> RuntimeConfig:
    selected_scan_mode = scan_mode or base_runtime.scan_mode or "active"
    if selected_scan_mode not in SCAN_MODES:
        raise PolicyError(f"invalid_scan_mode:{selected_scan_mode}")

    scopes: Tuple[str, ...] = tuple()
    expires_at = ""
    if approval_token:
        approval = validate_approval(approval_token, target=target)
        scopes = approval.scopes
        expires_at = str(approval.expires_at)

    wants_external = bool(base_runtime.allow_external_tools if allow_external_tools is None else allow_external_tools)
    wants_exploit = bool(base_runtime.exploit_enabled if exploit_enabled is None else exploit_enabled)
    wants_local = bool(base_runtime.allow_local_targets if allow_local_targets is None else allow_local_targets)

    if selected_scan_mode == "active" and not _has_scope(scopes, "active_scan"):
        wants_external = False
    if wants_exploit and not _has_scope(scopes, "exploit"):
        raise PolicyError("exploit_requires_approval")
    if wants_external and not _has_scope(scopes, "active_scan"):
        raise PolicyError("external_tools_require_active_scan_approval")

    return base_runtime.__class__(
        **{
            **base_runtime.__dict__,
            "scan_mode": selected_scan_mode,
            "allow_external_tools": wants_external,
            "allow_local_targets": wants_local,
            "exploit_enabled": wants_exploit,
            "approved_scopes": scopes,
            "approval_token": approval_token or "",
            "approval_expires_at": expires_at,
        }
    )


def _has_scope(scopes: Tuple[str, ...], required: str) -> bool:
    if required == "passive":
        return True
    if required == "active_scan":
        return "active_scan" in scopes or "exploit" in scopes
    if required == "auth_required":
        return "auth_required" in scopes or "exploit" in scopes
    if required == "exploit":
        return "exploit" in scopes
    return False


def _pad(value: str) -> str:
    return value + "=" * (-len(value) % 4)
