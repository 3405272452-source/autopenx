"""Traffic analysis tool: parse pcap files and extract data.

Provides both a standalone function ``traffic_analyze(pcap_path, filter_expr)`` and a
registered ``TrafficAnalyzeTool`` class for use in the tool registry.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import re
from pathlib import Path
from typing import Any, Dict, List, Set

from ..base import BaseTool, ToolResult, register


def traffic_analyze(pcap_path: str, filter_expr: str = "") -> dict:
    """Analyze a pcap/pcapng file for protocols, conversations, and suspicious data.

    Args:
        pcap_path: Path to the pcap/pcapng file.
        filter_expr: Optional display filter expression (tshark syntax).

    Returns:
        Dictionary with keys: protocols, conversations, extracted_data, suspicious.
        On error, includes an 'error' key.
    """
    if not pcap_path:
        return {"error": "pcap_path is required", "protocols": [], "conversations": 0, "extracted_data": [], "suspicious": []}

    path = Path(pcap_path)
    if not path.exists():
        return {"error": f"File not found: {pcap_path}", "protocols": [], "conversations": 0, "extracted_data": [], "suspicious": []}


    # Try tshark first
    tshark_bin = shutil.which("tshark")
    if tshark_bin:
        tshark_result = _run_tshark(tshark_bin, path, filter_expr)
        if tshark_result:
            return tshark_result

    # Fallback: basic pcap header parsing
    return _parse_pcap_basic(path)


def _run_tshark(tshark_bin: str, path: Path, filter_expr: str) -> Dict[str, Any]:
    """Run tshark to analyze pcap file."""
    result: Dict[str, Any] = {
        "protocols": [],
        "conversations": 0,
        "extracted_data": [],
        "suspicious": [],
    }

    # Get protocol hierarchy
    try:
        cmd = [tshark_bin, "-r", str(path), "-q", "-z", "io,phs"]
        if filter_expr:
            cmd.extend(["-Y", filter_expr])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            result["protocols"] = _parse_protocol_hierarchy(proc.stdout)
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Get conversations
    try:
        proc = subprocess.run(
            [tshark_bin, "-r", str(path), "-q", "-z", "conv,tcp"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0:
            result["conversations"] = _count_conversations(proc.stdout)
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Extract HTTP data
    try:
        cmd = [tshark_bin, "-r", str(path), "-Y", "http", "-T", "fields",
               "-e", "http.request.uri", "-e", "http.response.code", "-e", "http.file_data"]
        if filter_expr:
            cmd.extend(["-Y", f"http && ({filter_expr})"])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0 and proc.stdout.strip():
            for line in proc.stdout.strip().split("\n")[:20]:
                if line.strip():
                    result["extracted_data"].append(line.strip())
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Look for suspicious patterns (flags, credentials, etc.)
    try:
        proc = subprocess.run(
            [tshark_bin, "-r", str(path), "-T", "fields", "-e", "data.text"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            flag_pattern = re.compile(r"(flag|ctf|key|secret)\{[^}]+\}", re.IGNORECASE)
            for line in proc.stdout.strip().split("\n"):
                match = flag_pattern.search(line)
                if match:
                    result["suspicious"].append(f"Flag pattern: {match.group(0)}")
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Check for DNS exfiltration
    try:
        proc = subprocess.run(
            [tshark_bin, "-r", str(path), "-Y", "dns", "-T", "fields", "-e", "dns.qry.name"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            dns_queries = proc.stdout.strip().split("\n")
            suspicious_dns = [q for q in dns_queries if len(q) > 50 or _looks_encoded(q)]
            if suspicious_dns:
                result["suspicious"].append(f"Suspicious DNS queries: {len(suspicious_dns)} found")
                result["extracted_data"].extend(suspicious_dns[:5])
    except (subprocess.TimeoutExpired, OSError):
        pass

    return result


def _parse_protocol_hierarchy(output: str) -> List[str]:
    """Parse tshark protocol hierarchy statistics output."""
    protocols: Set[str] = set()
    for line in output.split("\n"):
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("Filter"):
            continue
        # Lines look like: "  eth:ip:tcp:http   frames:123 bytes:456"
        parts = line.split()
        if parts and ":" in parts[0]:
            for proto in parts[0].split(":"):
                proto = proto.strip()
                if proto and proto.isalpha():
                    protocols.add(proto)
        elif parts and parts[0].isalpha():
            protocols.add(parts[0])
    return sorted(protocols)


def _count_conversations(output: str) -> int:
    """Count TCP conversations from tshark output."""
    count = 0
    for line in output.split("\n"):
        line = line.strip()
        if line and not line.startswith("=") and not line.startswith("Filter") and "<->" in line:
            count += 1
    return count


def _looks_encoded(text: str) -> bool:
    """Check if text looks like encoded data (hex, base64)."""
    # Check for hex-like patterns
    if re.match(r"^[0-9a-fA-F]+$", text.replace(".", "").replace("-", "")):
        return len(text) > 20
    # Check for base64-like patterns
    if re.match(r"^[A-Za-z0-9+/=]+$", text.replace(".", "")):
        return len(text) > 30
    return False


def _parse_pcap_basic(path: Path) -> Dict[str, Any]:
    """Basic pcap parsing without tshark (fallback)."""
    result: Dict[str, Any] = {
        "protocols": [],
        "conversations": 0,
        "extracted_data": [],
        "suspicious": [],
    }

    try:
        data = path.read_bytes()
    except (OSError, IOError):
        result["error"] = "Failed to read file"
        return result

    if len(data) < 24:
        result["error"] = "File too small to be a valid pcap"
        return result

    # Check pcap magic number
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
        file_format = "pcap"
    elif magic == 0xD4C3B2A1:
        endian = ">"
        file_format = "pcap"
    elif magic == 0x0A0D0D0A:
        file_format = "pcapng"
        endian = "<"
    else:
        result["error"] = "Not a valid pcap/pcapng file"
        return result

    if file_format == "pcap":
        result = _parse_pcap_packets(data, endian)
    else:
        # pcapng basic info
        result["protocols"].append("pcapng_format")
        result["extracted_data"].append(f"File size: {len(data)} bytes")
        # Try to extract strings for flags
        _scan_pcap_strings(data, result)

    return result


def _parse_pcap_packets(data: bytes, endian: str) -> Dict[str, Any]:
    """Parse pcap file packets to extract basic info."""
    result: Dict[str, Any] = {
        "protocols": [],
        "conversations": 0,
        "extracted_data": [],
        "suspicious": [],
    }

    # Parse global header
    if len(data) < 24:
        return result

    # version_major, version_minor, thiszone, sigfigs, snaplen, network
    network = struct.unpack(f"{endian}I", data[20:24])[0]

    protocols: Set[str] = set()
    conversations: Set[str] = set()
    offset = 24
    packet_count = 0

    # Parse packets
    while offset + 16 <= len(data) and packet_count < 1000:
        # Packet header: ts_sec, ts_usec, incl_len, orig_len
        try:
            incl_len = struct.unpack(f"{endian}I", data[offset + 8:offset + 12])[0]
        except struct.error:
            break

        if incl_len > len(data) - offset - 16 or incl_len > 65535:
            break

        packet_data = data[offset + 16:offset + 16 + incl_len]
        packet_count += 1

        # Parse Ethernet frame (network type 1)
        if network == 1 and len(packet_data) >= 14:
            eth_type = struct.unpack(">H", packet_data[12:14])[0]
            if eth_type == 0x0800:  # IPv4
                protocols.add("IPv4")
                if len(packet_data) >= 34:
                    ip_proto = packet_data[23]
                    src_ip = ".".join(str(b) for b in packet_data[26:30])
                    dst_ip = ".".join(str(b) for b in packet_data[30:34])

                    if ip_proto == 6:
                        protocols.add("TCP")
                        if len(packet_data) >= 38:
                            src_port = struct.unpack(">H", packet_data[34:36])[0]
                            dst_port = struct.unpack(">H", packet_data[36:38])[0]
                            conv_key = f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}"
                            conversations.add(conv_key)
                            if dst_port == 80 or src_port == 80:
                                protocols.add("HTTP")
                            elif dst_port == 443 or src_port == 443:
                                protocols.add("HTTPS")
                            elif dst_port == 53 or src_port == 53:
                                protocols.add("DNS")
                    elif ip_proto == 17:
                        protocols.add("UDP")
                        if len(packet_data) >= 38:
                            src_port = struct.unpack(">H", packet_data[34:36])[0]
                            dst_port = struct.unpack(">H", packet_data[36:38])[0]
                            if dst_port == 53 or src_port == 53:
                                protocols.add("DNS")
                    elif ip_proto == 1:
                        protocols.add("ICMP")
            elif eth_type == 0x0806:
                protocols.add("ARP")
            elif eth_type == 0x86DD:
                protocols.add("IPv6")

        offset += 16 + incl_len

    result["protocols"] = sorted(protocols)
    result["conversations"] = len(conversations)
    result["extracted_data"].append(f"Total packets: {packet_count}")

    # Scan for flag patterns in raw data
    _scan_pcap_strings(data, result)

    return result


def _scan_pcap_strings(data: bytes, result: Dict[str, Any]) -> None:
    """Scan pcap data for flag-like strings."""
    flag_pattern = re.compile(rb"(flag|ctf|key|secret)\{[^}]+\}", re.IGNORECASE)
    for match in flag_pattern.finditer(data):
        try:
            flag_str = match.group(0).decode("utf-8", errors="ignore")
            result["suspicious"].append(f"Flag pattern found: {flag_str}")
        except Exception:
            pass


@register
class TrafficAnalyzeTool(BaseTool):
    """Analyze network traffic captures (pcap/pcapng)."""

    category = "ctf_misc"
    external_binary = "tshark"

    @property
    def name(self) -> str:
        return "traffic_analyze"

    @property
    def description(self) -> str:
        return (
            "Analyze pcap/pcapng network traffic captures. Uses tshark if available "
            "for detailed protocol analysis, otherwise falls back to basic pcap header "
            "parsing. Extracts protocols, conversations, and suspicious data patterns."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "pcap_path": {
                    "type": "string",
                    "description": "Path to the pcap/pcapng file to analyze",
                },
                "filter_expr": {
                    "type": "string",
                    "description": "Optional tshark display filter expression",
                },
            },
            "required": ["pcap_path"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        pcap_path = kwargs.get("pcap_path", "")
        filter_expr = kwargs.get("filter_expr", "")

        result = traffic_analyze(pcap_path, filter_expr)

        if "error" in result:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=result["error"],
                error=result["error"],
            )

        summary_parts = []
        if result["protocols"]:
            summary_parts.append(f"Protocols: {', '.join(result['protocols'][:5])}")
        summary_parts.append(f"Conversations: {result['conversations']}")
        if result["suspicious"]:
            summary_parts.append(f"Suspicious: {len(result['suspicious'])} items")

        return ToolResult(
            success=True,
            tool=self.name,
            summary=" | ".join(summary_parts),
            parsed_data=result,
        )
