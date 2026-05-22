"""Web Session State Machine - form extraction, login flow, CSRF tracking.

Provides reusable components for Web CTF agents to handle:
* HTML form discovery and parameter extraction
* Cookie/session continuity across redirects
* CSRF token automatic extraction and replay
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

import requests

log = logging.getLogger("autopnex.ctf.web_session")


# ---------------------------------------------------------------------------
# FormExtractor
# ---------------------------------------------------------------------------

@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str = ""
    required: bool = False


@dataclass
class HTMLForm:
    action: str = ""
    method: str = "GET"
    fields: List[FormField] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "fields": [{"name": f.name, "type": f.type, "value": f.value, "required": f.required} for f in self.fields],
            "enctype": self.enctype,
        }


class FormExtractor:
    """Extract HTML forms from response text."""

    @classmethod
    def extract(cls, html_text: str, base_url: str = "") -> List[HTMLForm]:
        forms: List[HTMLForm] = []
        # Match <form ...> ... </form>
        form_blocks = re.findall(r"<form\b([^>]*)>(.*?)</form>", html_text, re.S | re.I)
        for attrs, inner in form_blocks:
            form = HTMLForm()
            form.method = cls._extract_attr(attrs, "method", "GET").upper()
            raw_action = cls._extract_attr(attrs, "action", "")
            form.action = cls._resolve_url(raw_action, base_url)
            form.enctype = cls._extract_attr(attrs, "enctype", "application/x-www-form-urlencoded")

            # Extract inputs
            inputs = re.findall(r"<input\b([^>]*)/?>", inner, re.I)
            for inp_attrs in inputs:
                name = cls._extract_attr(inp_attrs, "name", "")
                if not name:
                    continue
                field_type = cls._extract_attr(inp_attrs, "type", "text").lower()
                value = cls._extract_attr(inp_attrs, "value", "")
                required = cls._extract_attr(inp_attrs, "required", "") != ""
                form.fields.append(FormField(name=name, type=field_type, value=value, required=required))

            # Extract textareas
            textareas = re.findall(r"<textarea\b([^>]*)>(.*?)</textarea>", inner, re.S | re.I)
            for ta_attrs, ta_value in textareas:
                name = cls._extract_attr(ta_attrs, "name", "")
                if name:
                    form.fields.append(FormField(name=name, type="textarea", value=ta_value))

            # Extract selects
            selects = re.findall(r"<select\b([^>]*)>.*?</select>", inner, re.S | re.I)
            for sel_attrs in selects:
                name = cls._extract_attr(sel_attrs, "name", "")
                if name:
                    form.fields.append(FormField(name=name, type="select"))

            forms.append(form)
        return forms

    @staticmethod
    def _extract_attr(tag_attrs: str, attr_name: str, default: str = "") -> str:
        pattern = rf'\b{attr_name}\s*=\s*["\']([^"\']*)["\']'
        match = re.search(pattern, tag_attrs, re.I)
        return match.group(1) if match else default

    @staticmethod
    def _resolve_url(action: str, base_url: str) -> str:
        from urllib.parse import urljoin
        return urljoin(base_url, action) if base_url else action


# ---------------------------------------------------------------------------
# CSRFTokenTracker
# ---------------------------------------------------------------------------

class CSRFTokenTracker:
    """Auto-extract and carry CSRF tokens across requests."""

    COMMON_NAMES = {"csrf_token", "csrfmiddlewaretoken", "_token", "token", "xsrf_token", " authenticity_token"}

    def __init__(self) -> None:
        self._tokens: Dict[str, str] = {}

    def extract_from_text(self, html_text: str) -> Dict[str, str]:
        """Extract CSRF tokens from HTML forms/meta tags."""
        found: Dict[str, str] = {}
        # Form input tokens
        for name in self.COMMON_NAMES:
            pattern = rf'<input[^>]*name=["\']{name}["\'][^>]*value=["\']([^"\']*)["\']'
            match = re.search(pattern, html_text, re.I)
            if match:
                found[name] = match.group(1)
        # Meta tag tokens
        meta_pattern = r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']*)["\']'
        meta_match = re.search(meta_pattern, html_text, re.I)
        if meta_match:
            found["csrf_token"] = meta_match.group(1)
        self._tokens.update(found)
        return found

    def extract_from_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        for key, value in headers.items():
            lowered = key.lower()
            if lowered in ("x-csrf-token", "x-xsrf-token", "csrf-token"):
                self._tokens["csrf_token"] = value
        return dict(self._tokens)

    def inject(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Inject known tokens into request params if not already present."""
        out = dict(params)
        for name, value in self._tokens.items():
            if name not in out:
                out[name] = value
        return out

    def get_tokens(self) -> Dict[str, str]:
        return dict(self._tokens)

    def clear(self) -> None:
        self._tokens.clear()


# ---------------------------------------------------------------------------
# SessionFlowManager
# ---------------------------------------------------------------------------

@dataclass
class FlowState:
    logged_in: bool = False
    last_status_code: int = 0
    redirect_chain: List[str] = field(default_factory=list)
    login_form_found: bool = False
    register_form_found: bool = False
    upload_form_found: bool = False


class SessionFlowManager:
    """Track login/session state across HTTP interactions."""

    LOGIN_INDICATORS = {"login", "signin", "log in", "sign in", "authenticate"}
    REGISTER_INDICATORS = {"register", "signup", "sign up", "create account"}
    UPLOAD_INDICATORS = {"upload", "file", "avatar", "image"}
    SUCCESS_INDICATORS = {"welcome", "dashboard", "profile", "success", "logout", "home"}
    FAILURE_INDICATORS = {"invalid", "error", "incorrect", "failed", "wrong password", "denied"}

    def __init__(self, session: requests.Session) -> None:
        self._session = session
        self._state = FlowState()
        self._csrf_tracker = CSRFTokenTracker()

    @property
    def csrf(self) -> CSRFTokenTracker:
        return self._csrf_tracker

    @property
    def state(self) -> FlowState:
        return self._state

    def observe_response(self, url: str, response: requests.Response) -> None:
        """Observe an HTTP response and update internal state."""
        self._state.last_status_code = response.status_code
        if response.history:
            self._state.redirect_chain = [r.url for r in response.history] + [response.url]
        else:
            self._state.redirect_chain = [response.url]

        body = response.text.lower()
        # Detect forms
        forms = FormExtractor.extract(response.text, base_url=url)
        for form in forms:
            lowered_action = form.action.lower()
            field_names = {f.name.lower() for f in form.fields}
            if any(ind in lowered_action for ind in self.LOGIN_INDICATORS) or {"username", "password"} <= field_names:
                self._state.login_form_found = True
            if any(ind in lowered_action for ind in self.REGISTER_INDICATORS):
                self._state.register_form_found = True
            if any(ind in lowered_action for ind in self.UPLOAD_INDICATORS) or any(f.type == "file" for f in form.fields):
                self._state.upload_form_found = True

        self._csrf_tracker.extract_from_text(response.text)
        self._csrf_tracker.extract_from_headers(dict(response.headers))

        # Infer login success/failure
        if self._state.last_status_code == 302 or any(ind in body for ind in self.SUCCESS_INDICATORS):
            if self._state.login_form_found or "password" in body:
                self._state.logged_in = True
        if any(ind in body for ind in self.FAILURE_INDICATORS):
            self._state.logged_in = False

    def observe_result(self, url: str, result: Dict[str, Any]) -> None:
        """Observe a tool result dict (from http_request) and update state."""
        status = result.get("status_code", 0)
        self._state.last_status_code = status
        self._state.redirect_chain = [result.get("url", url)]
        body = str(result.get("body", "")).lower()
        forms = FormExtractor.extract(str(result.get("body", "")), base_url=url)
        for form in forms:
            lowered_action = form.action.lower()
            field_names = {f.name.lower() for f in form.fields}
            if any(ind in lowered_action for ind in self.LOGIN_INDICATORS) or {"username", "password"} <= field_names:
                self._state.login_form_found = True
            if any(ind in lowered_action for ind in self.REGISTER_INDICATORS):
                self._state.register_form_found = True
            if any(ind in lowered_action for ind in self.UPLOAD_INDICATORS) or any(f.type == "file" for f in form.fields):
                self._state.upload_form_found = True

        self._csrf_tracker.extract_from_text(str(result.get("body", "")))
        headers = result.get("headers", {})
        if isinstance(headers, dict):
            self._csrf_tracker.extract_from_headers(headers)

        if status == 302 or any(ind in body for ind in self.SUCCESS_INDICATORS):
            if self._state.login_form_found or "password" in body:
                self._state.logged_in = True
        if any(ind in body for ind in self.FAILURE_INDICATORS):
            self._state.logged_in = False

    def is_logged_in(self) -> bool:
        return self._state.logged_in

    def summary(self) -> Dict[str, Any]:
        return {
            "logged_in": self._state.logged_in,
            "last_status_code": self._state.last_status_code,
            "redirect_chain": self._state.redirect_chain,
            "login_form_found": self._state.login_form_found,
            "register_form_found": self._state.register_form_found,
            "upload_form_found": self._state.upload_form_found,
            "csrf_tokens": self._csrf_tracker.get_tokens(),
        }
