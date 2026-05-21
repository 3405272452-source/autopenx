"""Plan non-Docker public exposure methods for CTF helper services."""
from __future__ import annotations

import platform
import shlex
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult


def _q(value: str) -> str:
    return shlex.quote(str(value))


class CTFTunnelHelperTool(BaseTool):
    category = "ctf_web"
    requires_exploit_enabled = True
    required_capability = "exploit"

    @property
    def name(self) -> str:
        return "ctf_tunnel_helper"

    @property
    def description(self) -> str:
        return (
            "Generate non-Docker public exposure plans for CTF helper services. Supports ngrok TCP, "
            "frp, chisel reverse tunnels, SSH reverse port forwarding, bore.pub, and free public MySQL. "
            "Returns Chinese action summaries, download suggestions, commands, and next tool arguments."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "local_host": {"type": "string", "description": "Local service host. Default: 127.0.0.1."},
                "local_port": {"type": "integer", "description": "Local service port, e.g. 3306."},
                "service": {"type": "string", "description": "Service name, e.g. mysql/http/listener. Default: mysql."},
                "preferred_method": {
                    "type": "string",
                    "enum": ["auto", "ngrok_tcp", "frp", "chisel", "ssh_reverse", "bore", "free_mysql"],
                    "description": "Preferred exposure method. Default: auto.",
                },
                "vps_host": {"type": "string", "description": "VPS host/IP for frp/chisel/ssh reverse tunnel."},
                "vps_user": {"type": "string", "description": "SSH username for reverse tunnel. Default: root."},
                "remote_port": {"type": "integer", "description": "Remote public TCP port. Default: same as local_port."},
                "ngrok_authtoken_present": {"type": "boolean", "description": "Whether ngrok authtoken is configured."},
            },
            "required": ["local_port"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        local_host = str(kwargs.get("local_host") or "127.0.0.1")
        local_port = int(kwargs.get("local_port") or 3306)
        service = str(kwargs.get("service") or "mysql")
        preferred = str(kwargs.get("preferred_method") or "auto")
        vps_host = str(kwargs.get("vps_host") or "<your-vps-ip>")
        vps_user = str(kwargs.get("vps_user") or "root")
        remote_port = int(kwargs.get("remote_port") or local_port)
        ngrok_ready = bool(kwargs.get("ngrok_authtoken_present", False))
        system = platform.system().lower()

        downloads = _download_suggestions(system)
        methods = _methods(
            local_host=local_host,
            local_port=local_port,
            service=service,
            vps_host=vps_host,
            vps_user=vps_user,
            remote_port=remote_port,
            ngrok_ready=ngrok_ready,
        )
        selected = methods if preferred == "auto" else [m for m in methods if m["name"] == preferred]
        if not selected:
            selected = methods

        action_summary = [
            f"当前目标：把本机 {local_host}:{local_port} 的 {service} 服务暴露给公网 CTF 目标访问。",
            "本机 Docker 不可用时，优先级建议：已有 ngrok token 用 ngrok_tcp；有 VPS 用 frp/chisel/SSH 反代；无 VPS 可尝试 bore.pub 或直接使用免费公网 MySQL。",
            "如果缺少二进制工具，Agent 应先调用 download_tool_url 下载到 ctf_workspace/downloads，再用 run_tool_script 或手动命令运行。",
        ]
        parsed = {
            "service": service,
            "local_host": local_host,
            "local_port": local_port,
            "preferred_method": preferred,
            "recommended_methods": selected,
            "all_methods": methods,
            "download_suggestions": downloads,
            "chinese_action_summary": action_summary,
            "next_tool_if_mysql_ready": "phar_pdo_chain",
            "next_tool_if_missing_binary": "download_tool_url",
        }
        raw = "\n\n".join(
            [
                "中文行动摘要:\n" + "\n".join(f"- {item}" for item in action_summary),
                "推荐暴露方式:\n" + "\n\n".join(_format_method(item) for item in selected),
                "可下载工具候选:\n" + "\n".join(f"- {item['name']}: {item['url']}" for item in downloads),
            ]
        )
        return ToolResult(True, self.name, "已生成非 Docker 公网暴露方案。", raw_output=raw, parsed_data=parsed)


def _methods(*, local_host: str, local_port: int, service: str, vps_host: str, vps_user: str, remote_port: int, ngrok_ready: bool) -> List[Dict[str, Any]]:
    return [
        {
            "name": "ngrok_tcp",
            "title": "ngrok TCP 隧道",
            "best_when": "有 ngrok 账号和 authtoken，想快速暴露 MySQL/TCP 服务。",
            "commands": [
                "ngrok config add-authtoken <NGROK_AUTHTOKEN>" if not ngrok_ready else "ngrok config check",
                f"ngrok tcp {local_port}",
                "从 ngrok 输出中提取 tcp://host:port，并把 host/port 传给 phar_pdo_chain。",
            ],
            "notes": ["ngrok 免费账号通常支持 TCP，但需要登录和 authtoken。", "目标必须能出网访问 ngrok 分配的 host:port。"],
        },
        {
            "name": "frp",
            "title": "frp 反向代理到 VPS",
            "best_when": "你有公网 VPS，可以长期稳定暴露 TCP 服务。",
            "commands": [
                f"在 VPS 上运行 frps，监听 bind_port=7000，并放通 {remote_port}/tcp。",
                f"本机 frpc 配置: type=tcp, local_ip={local_host}, local_port={local_port}, remote_port={remote_port}",
                "将 VPS_IP 和 remote_port 传给 phar_pdo_chain。",
            ],
            "notes": ["适合 MySQL 这类原始 TCP。", "VPS 安全组和系统防火墙都要放行 remote_port。"],
        },
        {
            "name": "chisel",
            "title": "chisel reverse TCP 隧道",
            "best_when": "你有 VPS，但不想配置 frp。",
            "commands": [
                "VPS: chisel server --reverse --port 8000",
                f"本机: chisel client {vps_host}:8000 R:{remote_port}:{local_host}:{local_port}",
                f"将 {vps_host}:{remote_port} 传给 phar_pdo_chain。",
            ],
            "notes": ["chisel 单文件，适合 Agent 自动下载。", "VPS 需要放行 8000 和 remote_port。"],
        },
        {
            "name": "ssh_reverse",
            "title": "SSH 反向端口转发",
            "best_when": "你已有 VPS SSH 权限，且 sshd 允许 GatewayPorts。",
            "commands": [
                "VPS /etc/ssh/sshd_config 设置 GatewayPorts clientspecified 或 yes，然后重启 sshd。",
                f"ssh -N -R 0.0.0.0:{remote_port}:{local_host}:{local_port} {vps_user}@{vps_host}",
                f"将 {vps_host}:{remote_port} 传给 phar_pdo_chain。",
            ],
            "notes": ["无需额外工具。", "很多 VPS 默认 GatewayPorts 为 no，需修改配置。"],
        },
        {
            "name": "bore",
            "title": "bore.pub 临时 TCP 隧道",
            "best_when": "没有 VPS，想尝试免费临时 TCP 隧道。",
            "commands": [
                f"bore local {local_port} --to bore.pub",
                "从输出中读取 bore.pub 分配的公网端口。",
                "将 bore.pub 和分配端口传给 phar_pdo_chain。",
            ],
            "notes": ["公共服务稳定性不保证。", "若 CTF 目标不能访问 bore.pub，需要换 ngrok/frp/VPS。"],
        },
        {
            "name": "free_mysql",
            "title": "直接使用免费公网 MySQL",
            "best_when": "本机不方便启动或暴露 MySQL。",
            "commands": [
                "注册支持 remote TCP MySQL 的免费数据库服务。",
                "导入 ctf_mysql_helper 生成的 SQL。",
                "将服务商给出的 host/port/user/password/db_name 传给 phar_pdo_chain。",
            ],
            "notes": ["优先选择允许任意来源连接或能白名单 CTF 出口 IP 的服务。", "CTF 结束后删除数据库和账号。"],
        },
    ]


def _download_suggestions(system: str) -> List[Dict[str, str]]:
    if "windows" in system:
        return [
            {"name": "ngrok_windows_amd64", "url": "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip"},
            {"name": "chisel_windows_amd64", "url": "https://github.com/jpillora/chisel/releases/latest/download/chisel_windows_amd64.gz"},
            {"name": "bore_windows_amd64", "url": "https://github.com/ekzhang/bore/releases/latest/download/bore-v0.5.0-x86_64-pc-windows-msvc.zip"},
            {"name": "frp_windows_amd64", "url": "https://github.com/fatedier/frp/releases/latest"},
        ]
    return [
        {"name": "ngrok_linux_amd64", "url": "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz"},
        {"name": "chisel_linux_amd64", "url": "https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz"},
        {"name": "bore_linux_amd64", "url": "https://github.com/ekzhang/bore/releases/latest/download/bore-v0.5.0-x86_64-unknown-linux-musl.tar.gz"},
        {"name": "frp_linux_amd64", "url": "https://github.com/fatedier/frp/releases/latest"},
    ]


def _format_method(method: Dict[str, Any]) -> str:
    parts = [f"[{method['name']}] {method['title']}", f"适用场景: {method['best_when']}", "命令/步骤:"]
    parts.extend("  " + str(cmd) for cmd in method.get("commands", []))
    notes = method.get("notes") or []
    if notes:
        parts.append("注意事项:")
        parts.extend("  " + str(note) for note in notes)
    return "\n".join(parts)
