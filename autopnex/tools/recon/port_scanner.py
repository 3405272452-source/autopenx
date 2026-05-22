"""Asyncio-based TCP port scanner (pure Python, Windows-friendly)."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register
from .._http import parsed


COMMON_PORTS: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    631: "ipp",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2181: "zookeeper",
    2375: "docker",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    4000: "http-alt",
    4280: "http-docker",
    4443: "https-alt",
    4444: "http-alt",
    5000: "http-alt",
    5432: "postgres",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6443: "kube-api",
    7001: "weblogic",
    7077: "spark",
    7443: "https-alt",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8082: "http-alt",
    8083: "http-alt",
    8084: "http-alt",
    8085: "http-alt",
    8086: "influxdb",
    8088: "http-alt",
    8090: "http-alt",
    8161: "activemq",
    8443: "https-alt",
    8880: "http-alt",
    8888: "http-alt",
    9000: "http-alt",
    9001: "http-alt",
    9042: "cassandra",
    9060: "http-alt",
    9080: "http-alt",
    9090: "prometheus",
    9091: "http-alt",
    9092: "kafka",
    9200: "elasticsearch",
    9300: "elastic-node",
    9443: "https-alt",
    10000: "http-alt",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
    50070: "hadoop",
}


@register
class PortScannerTool(BaseTool):
    category = "recon"

    @property
    def name(self) -> str:
        return "port_scan"

    @property
    def description(self) -> str:
        return (
            "TCP port scanner (pure Python asyncio). Probes a curated list of common "
            "service ports on the target host and reports which are open plus a short banner."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Hostname, IP or full URL (scheme optional).",
                },
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Optional override of port list.",
                },
                "timeout": {
                    "type": "number",
                    "description": "Per-port connect timeout in seconds (default 1.5).",
                },
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = kwargs.get("target")
        if not target:
            return ToolResult(False, self.name, "target is required", error="missing_target")
        ports: List[int] = kwargs.get("ports") or list(COMMON_PORTS.keys())
        timeout: float = float(kwargs.get("timeout") or 1.5)

        _, host, _ = parsed(target)
        if not host:
            return ToolResult(False, self.name, f"cannot resolve host from {target}", error="bad_target")

        open_ports = asyncio.run(_scan(host, ports, timeout))
        summary = (
            f"{host}: {len(open_ports)} open ports of {len(ports)} probed: "
            + ", ".join(f"{p['port']}/{p['service']}" for p in open_ports[:20])
        )
        return ToolResult(
            success=True,
            tool=self.name,
            summary=summary,
            parsed_data={"host": host, "open_ports": open_ports, "probed": len(ports)},
            raw_output="\n".join(
                f"{p['port']}/tcp open {p['service']} banner={p['banner']!r}" for p in open_ports
            ),
        )


async def _probe(host: str, port: int, timeout: float) -> Dict[str, Any] | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError):
        return None
    banner = ""
    try:
        try:
            data = await asyncio.wait_for(reader.read(120), timeout=0.6)
            banner = data.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            banner = ""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
    return {
        "port": port,
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner": banner[:160],
    }


async def _scan(host: str, ports: List[int], timeout: float) -> List[Dict[str, Any]]:
    sem = asyncio.Semaphore(64)

    async def _bounded(p: int):
        async with sem:
            return await _probe(host, p, timeout)

    results = await asyncio.gather(*[_bounded(p) for p in ports])
    return [r for r in results if r]
