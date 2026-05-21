"""Persistent authentication session manager.

Inspired by Shannon's shannon-auth-session tool. Manages authenticated sessions
(JWT, Cookie, Custom Header) for reuse across IDOR, injection, and escalation tests.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional

from ..base import BaseTool, ToolResult, register
from .._http import normalise_target, request


# In-memory session store
_SESSIONS: Dict[str, Dict[str, Any]] = {}


@register
class SessionManagerTool(BaseTool):
    category = "exploit"
    required_capability = "exploit"
    requires_exploit_enabled = True

    @property
    def name(self) -> str:
        return "session_manager"

    @property
    def description(self) -> str:
        return (
            "Manage persistent authenticated sessions for reuse across tests. "
            "Supports JWT, cookie, and custom header authentication. "
            "Actions: create, get, list, delete, build_headers."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["create", "get", "list", "delete", "build_headers"],
                    "description": "Session management action.",
                },
                "session_id": {
                    "type": "string",
                    "description": "Session ID (for get/delete/build_headers).",
                },
                "target": {
                    "type": "string",
                    "description": "Target URL (for create).",
                },
                "login_endpoint": {
                    "type": "string",
                    "description": "Login endpoint path (for create, e.g. '/api/login').",
                },
                "session_type": {
                    "type": "string",
                    "enum": ["jwt", "cookie", "header"],
                    "description": "Authentication type (for create).",
                },
                "credentials": {
                    "type": "string",
                    "description": 'JSON credentials (for create, e.g. \'{"email":"user@test.com","password":"pass"}\').',
                },
                "auth_token": {
                    "type": "string",
                    "description": "Pre-existing auth token (for create with pre-existing token).",
                },
            },
            "required": ["action"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        action = kwargs.get("action", "")

        if action == "create":
            return self._create_session(kwargs)
        elif action == "get":
            return self._get_session(kwargs)
        elif action == "list":
            return self._list_sessions()
        elif action == "delete":
            return self._delete_session(kwargs)
        elif action == "build_headers":
            return self._build_headers(kwargs)
        else:
            return ToolResult(False, self.name, f"Unknown action: {action}", error="invalid_action")

    def _create_session(self, kwargs: Dict) -> ToolResult:
        target = normalise_target(kwargs.get("target", ""))
        login_endpoint = kwargs.get("login_endpoint", "")
        session_type = kwargs.get("session_type", "jwt")
        credentials_str = kwargs.get("credentials", "{}")
        auth_token = kwargs.get("auth_token", "")

        if not target:
            return ToolResult(False, self.name, "target required for create", error="missing_args")

        session_id = f"sess-{uuid.uuid4().hex[:8]}"
        session_data: Dict[str, Any] = {
            "session_id": session_id,
            "target": target,
            "session_type": session_type,
            "created_at": time.time(),
            "headers": {},
            "cookies": {},
            "token": auth_token,
        }

        if auth_token:
            # Pre-existing token
            if session_type == "jwt":
                session_data["headers"]["Authorization"] = f"Bearer {auth_token}"
            elif session_type == "header":
                session_data["headers"]["Authorization"] = auth_token
            elif session_type == "cookie":
                session_data["cookies"]["session"] = auth_token
        elif login_endpoint:
            # Login to get token
            try:
                credentials = json.loads(credentials_str)
            except json.JSONDecodeError:
                credentials = {"username": credentials_str}

            login_url = target.rstrip("/") + login_endpoint
            resp, err, _ = request("POST", login_url, json_body=credentials)

            if resp is None:
                return ToolResult(False, self.name, f"Login failed: {err}", error=err)

            if resp.status_code not in (200, 201):
                return ToolResult(
                    False, self.name,
                    f"Login returned {resp.status_code}",
                    error=f"login_failed:{resp.status_code}",
                )

            # Extract token based on session type
            body = resp.text or ""
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = {}

            if session_type == "jwt":
                token = data.get("token") or data.get("access_token") or data.get("jwt", "")
                session_data["token"] = token
                session_data["headers"]["Authorization"] = f"Bearer {token}"
            elif session_type == "cookie":
                session_data["cookies"] = dict(resp.cookies)
            elif session_type == "header":
                token = data.get("token") or data.get("api_key", "")
                session_data["token"] = token
                session_data["headers"]["Authorization"] = token
        else:
            return ToolResult(False, self.name, "auth_token or login_endpoint required", error="missing_args")

        _SESSIONS[session_id] = session_data

        return ToolResult(
            success=True,
            tool=self.name,
            summary=f"Session created: {session_id} ({session_type}) for {target}",
            parsed_data={
                "action": "create",
                "session_id": session_id,
                "session_type": session_type,
                "target": target,
                "has_token": bool(session_data.get("token")),
            },
        )

    def _get_session(self, kwargs: Dict) -> ToolResult:
        session_id = kwargs.get("session_id", "")
        session = _SESSIONS.get(session_id)
        if not session:
            return ToolResult(False, self.name, f"Session not found: {session_id}", error="not_found")
        return ToolResult(
            success=True,
            tool=self.name,
            summary=f"Session {session_id}: type={session['session_type']}, target={session['target']}",
            parsed_data={"action": "get", "session": session},
        )

    def _list_sessions(self) -> ToolResult:
        sessions = [
            {
                "session_id": sid,
                "target": s["target"],
                "type": s["session_type"],
                "created_at": s["created_at"],
            }
            for sid, s in _SESSIONS.items()
        ]
        return ToolResult(
            success=True,
            tool=self.name,
            summary=f"{len(sessions)} active sessions",
            parsed_data={"action": "list", "sessions": sessions, "count": len(sessions)},
        )

    def _delete_session(self, kwargs: Dict) -> ToolResult:
        session_id = kwargs.get("session_id", "")
        if session_id in _SESSIONS:
            del _SESSIONS[session_id]
            return ToolResult(True, self.name, f"Session deleted: {session_id}")
        return ToolResult(False, self.name, f"Session not found: {session_id}", error="not_found")

    def _build_headers(self, kwargs: Dict) -> ToolResult:
        session_id = kwargs.get("session_id", "")
        session = _SESSIONS.get(session_id)
        if not session:
            return ToolResult(False, self.name, f"Session not found: {session_id}", error="not_found")

        headers = dict(session.get("headers", {}))
        return ToolResult(
            success=True,
            tool=self.name,
            summary=f"Headers for session {session_id}: {list(headers.keys())}",
            parsed_data={"action": "build_headers", "session_id": session_id, "headers": headers},
        )
