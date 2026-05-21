"""CTF Pwn exploitation tools package.

Provides tools for binary exploitation challenges:
- checksec: Analyze binary protection mechanisms
- rop_chain: Find ROP gadgets for chain construction
- format_string: Generate format string exploit payloads
- remote_interact: TCP socket interaction with remote services
"""
from autopnex.tools.base import ToolRegistry
from .checksec import ChecksecTool, checksec
from .rop_chain import ROPChainTool, rop_chain
from .format_string import FormatStringTool, format_string_exploit
from .remote_interact import RemoteInteractTool, remote_interact

ToolRegistry.register(ChecksecTool)
ToolRegistry.register(ROPChainTool)
ToolRegistry.register(FormatStringTool)
ToolRegistry.register(RemoteInteractTool)

# Registry dict for programmatic access to all pwn tool functions
CTF_PWN_TOOLS = {
    "checksec": checksec,
    "rop_chain": rop_chain,
    "format_string_exploit": format_string_exploit,
    "remote_interact": remote_interact,
}

__all__ = [
    "ChecksecTool",
    "ROPChainTool",
    "FormatStringTool",
    "RemoteInteractTool",
    "checksec",
    "rop_chain",
    "format_string_exploit",
    "remote_interact",
    "CTF_PWN_TOOLS",
]
