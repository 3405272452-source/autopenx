"""Remote interaction tool: connect to TCP services and send payloads.

Provides both an async standalone function ``remote_interact(...)`` and a
registered ``RemoteInteractTool`` class for use in the tool registry.
"""
from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict

from ..base import BaseTool, ToolResult, register


async def remote_interact(
    host: str,
    port: int,
    payload: bytes,
    recv_timeout: float = 5.0,
) -> dict:
    """Connect to a remote TCP service, send payload, and receive response.

    Opens a TCP connection to host:port, sends the payload bytes, then
    reads the response until timeout or connection close.

    Args:
        host: Target hostname or IP address.
        port: Target TCP port number.
        payload: Bytes to send after connecting.
        recv_timeout: Timeout in seconds for receiving data. Defaults to 5.0.

    Returns:
        Dictionary with keys:
        - success: bool - whether the interaction completed without error
        - response: bytes - data received from the server
        - error: str - error message if interaction failed (empty on success)
    """
    if not host:
        return {"success": False, "response": b"", "error": "host is required"}

    if not (1 <= port <= 65535):
        return {"success": False, "response": b"", "error": f"invalid port: {port}"}

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=recv_timeout,
        )
    except asyncio.TimeoutError:
        return {"success": False, "response": b"", "error": f"connection timeout to {host}:{port}"}
    except OSError as e:
        return {"success": False, "response": b"", "error": f"connection failed: {e}"}

    response_data = b""
    try:
        # Read any initial banner/prompt
        try:
            banner = await asyncio.wait_for(reader.read(4096), timeout=recv_timeout)
            response_data += banner
        except asyncio.TimeoutError:
            pass  # No banner, that's fine

        # Send payload
        writer.write(payload)
        await writer.drain()

        # Read response
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=recv_timeout)
                if not chunk:
                    break
                response_data += chunk
        except asyncio.TimeoutError:
            pass  # Timeout reading is expected — we got what we could

        return {"success": True, "response": response_data, "error": ""}

    except OSError as e:
        return {"success": False, "response": response_data, "error": f"I/O error: {e}"}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass


def _remote_interact_sync(
    host: str,
    port: int,
    payload: bytes,
    recv_timeout: float = 5.0,
) -> dict:
    """Synchronous wrapper around remote_interact for use in the tool class.

    Uses a plain socket for compatibility in synchronous contexts.
    """
    if not host:
        return {"success": False, "response": b"", "error": "host is required"}

    if not (1 <= port <= 65535):
        return {"success": False, "response": b"", "error": f"invalid port: {port}"}

    sock = None
    response_data = b""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(recv_timeout)
        sock.connect((host, port))

        # Read any initial banner
        try:
            banner = sock.recv(4096)
            response_data += banner
        except socket.timeout:
            pass

        # Send payload
        sock.sendall(payload)

        # Read response
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
        except socket.timeout:
            pass  # Timeout is expected

        return {"success": True, "response": response_data, "error": ""}

    except socket.timeout:
        return {"success": False, "response": response_data, "error": f"connection timeout to {host}:{port}"}
    except OSError as e:
        return {"success": False, "response": response_data, "error": f"connection failed: {e}"}
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


@register
class RemoteInteractTool(BaseTool):
    """Connect to remote TCP services and send exploit payloads."""

    category = "ctf_pwn"
    requires_exploit_enabled = True

    @property
    def name(self) -> str:
        return "remote_interact"

    @property
    def description(self) -> str:
        return (
            "Connect to a remote TCP service (e.g., nc challenge), send a payload, "
            "and receive the response. Used for pwn challenges that require "
            "interacting with a remote binary service."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Target hostname or IP address",
                },
                "port": {
                    "type": "integer",
                    "description": "Target TCP port number",
                },
                "payload": {
                    "type": "string",
                    "description": "Payload to send (hex-encoded bytes)",
                },
                "recv_timeout": {
                    "type": "number",
                    "description": "Timeout in seconds for receiving data",
                    "default": 5.0,
                },
            },
            "required": ["host", "port", "payload"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        host = kwargs.get("host", "")
        port = kwargs.get("port")
        payload_hex = kwargs.get("payload", "")
        recv_timeout = kwargs.get("recv_timeout", 5.0)

        if not host or port is None:
            return ToolResult(
                success=False,
                tool=self.name,
                summary="host and port are required",
                error="missing_args",
            )

        try:
            port = int(port)
        except (ValueError, TypeError):
            return ToolResult(
                success=False,
                tool=self.name,
                summary="port must be an integer",
                error="invalid_args",
            )

        # Decode hex payload
        try:
            if payload_hex:
                payload = bytes.fromhex(payload_hex)
            else:
                payload = b""
        except ValueError:
            # Try as raw string if not valid hex
            payload = payload_hex.encode("utf-8") if isinstance(payload_hex, str) else payload_hex

        try:
            recv_timeout = float(recv_timeout)
        except (ValueError, TypeError):
            recv_timeout = 5.0

        result = _remote_interact_sync(host, port, payload, recv_timeout)

        if not result["success"]:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=f"Failed to interact with {host}:{port}: {result['error']}",
                error=result["error"],
                parsed_data={
                    "host": host,
                    "port": port,
                    "response_hex": result["response"].hex() if result["response"] else "",
                    "response_text": result["response"].decode("utf-8", errors="replace") if result["response"] else "",
                },
            )

        response_text = result["response"].decode("utf-8", errors="replace")
        return ToolResult(
            success=True,
            tool=self.name,
            summary=f"Received {len(result['response'])} bytes from {host}:{port}",
            raw_output=response_text[:3000],
            parsed_data={
                "host": host,
                "port": port,
                "response_hex": result["response"].hex()[:2000],
                "response_text": response_text[:2000],
                "response_length": len(result["response"]),
            },
        )
