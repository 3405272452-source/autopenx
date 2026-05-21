"""Controlled nmap adapter exposed through BaseTool."""
from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from .._http import parsed
from ..base import BaseTool, ToolResult, register


@register
class NmapScanTool(BaseTool):
    category = "recon"
    external_binary = "nmap"
    required_capability = "active_scan"

    @property
    def name(self) -> str:
        return "nmap_scan"

    @property
    def description(self) -> str:
        return (
            "Run a controlled nmap TCP service scan against the target host. "
            "Only available when external tools are enabled and nmap is installed."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Hostname, IP or URL to scan."},
                "top_ports": {
                    "type": "integer",
                    "description": "How many common TCP ports to probe with nmap (default 100).",
                },
                "service_version": {
                    "type": "boolean",
                    "description": "Whether to enable service detection with -sV (default true).",
                },
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = kwargs.get("target", "")
        _, host, _port = parsed(target)
        if not host:
            return ToolResult(False, self.name, "target is required", error="missing_target")

        top_ports = max(1, min(int(kwargs.get("top_ports") or 100), 1000))
        service_version = bool(kwargs.get("service_version", True))
        availability = self.availability()
        binary = availability["binary_path"] or self.external_binary

        cmd: List[str] = [str(binary), "-Pn", "--host-timeout", "120s"]
        if service_version:
            cmd.extend(["-sV", "--version-intensity", "2"])
        cmd.extend(["--top-ports", str(top_ports), "-oX", "-", host])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                False,
                self.name,
                f"nmap timed out scanning {host} (top {top_ports} ports with -sV). "
                "Try reducing top_ports or disabling service_version.",
                error="nmap_timeout",
            )
        xml_output = proc.stdout or ""
        if not xml_output.strip():
            return ToolResult(
                False,
                self.name,
                "nmap produced no XML output",
                raw_output=(proc.stderr or "")[:2000],
                error=f"nmap_exit_{proc.returncode}",
            )

        try:
            open_ports = _parse_open_ports(xml_output)
        except ET.ParseError as exc:
            return ToolResult(
                False,
                self.name,
                f"failed to parse nmap XML: {exc}",
                raw_output=xml_output[:2000],
                error="nmap_xml_parse_error",
            )

        summary = (
            f"nmap found {len(open_ports)} open ports on {host}: "
            + ", ".join(f"{p['port']}/{p['service']}" for p in open_ports[:20])
        )
        return ToolResult(
            success=True,
            tool=self.name,
            summary=summary,
            raw_output=xml_output[:4000],
            parsed_data={
                "host": host,
                "open_ports": open_ports,
                "probed": top_ports,
                "scanner": "nmap",
            },
        )


def _parse_open_ports(xml_output: str) -> List[Dict[str, Any]]:
    root = ET.fromstring(xml_output)
    open_ports: List[Dict[str, Any]] = []
    for port in root.findall(".//host/ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        service_name = service.get("name", "unknown") if service is not None else "unknown"
        product = service.get("product", "") if service is not None else ""
        version = service.get("version", "") if service is not None else ""
        banner = " ".join(part for part in [product, version] if part).strip()
        open_ports.append(
            {
                "port": int(port.get("portid", "0")),
                "service": service_name,
                "banner": banner[:160],
            }
        )
    return open_ports
