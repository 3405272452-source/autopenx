"""Subdomain enumeration via the public crt.sh Certificate Transparency API."""
from __future__ import annotations

import ipaddress
import json
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register
from .._http import parsed, request


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@register
class SubdomainFinderTool(BaseTool):
    category = "recon"
    scan_mode_required = "passive"

    @property
    def name(self) -> str:
        return "subdomain_find"

    @property
    def description(self) -> str:
        return "Passive subdomain enumeration using the crt.sh certificate transparency API (no direct probing)."

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Apex domain, e.g. example.com"},
                "limit": {"type": "integer", "description": "Max results to return (default 50)."},
            },
            "required": ["domain"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        domain = kwargs.get("domain") or ""
        if not domain:
            return ToolResult(False, self.name, "domain is required", error="missing_domain")

        if "://" in domain:
            _, host, _ = parsed(domain)
            domain = host
        # Strip leading wildcard/www
        domain = domain.lstrip(".")
        if domain.startswith("www."):
            domain = domain[4:]

        # IP addresses cannot be queried via certificate transparency
        if _is_ip(domain):
            return ToolResult(
                True,
                self.name,
                f"Skipped: {domain} is an IP address, not a domain. "
                "Certificate transparency lookup requires a domain name.",
                parsed_data={"domain": domain, "subdomains": []},
                raw_output="",
            )

        limit = int(kwargs.get("limit") or 50)
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp, err, _ = request("GET", url, timeout=15)
        if resp is None or resp.status_code != 200 or not resp.text.strip():
            return ToolResult(
                False,
                self.name,
                f"crt.sh unavailable ({err or resp.status_code if resp else 'no response'})",
                error=err,
            )
        try:
            data = resp.json()
        except json.JSONDecodeError:
            # crt.sh occasionally returns concatenated JSON objects
            try:
                data = json.loads("[" + resp.text.replace("}\n{", "},{") + "]")
            except Exception:  # noqa: BLE001
                return ToolResult(False, self.name, "crt.sh returned unparseable body", error="json_decode")

        subdomains: List[str] = []
        for entry in data:
            name = (entry.get("name_value") or "").strip()
            for line in name.splitlines():
                line = line.strip().lower().lstrip("*.")
                if line and line.endswith(domain) and line not in subdomains:
                    subdomains.append(line)
                    if len(subdomains) >= limit:
                        break
            if len(subdomains) >= limit:
                break

        summary = f"crt.sh returned {len(subdomains)} unique subdomains for {domain}."
        return ToolResult(
            True,
            self.name,
            summary,
            parsed_data={"domain": domain, "subdomains": subdomains},
            raw_output="\n".join(subdomains),
        )
