"""Unit tests for CTF Pwn tools (Task 11.7).

Tests cover:
- checksec: binary protection analysis (mocked subprocess)
- rop_chain: ROP gadget finding and chain generation
- format_string: format string payload generation
- remote_interact: TCP socket interaction (mocked socket)
"""
from __future__ import annotations

import asyncio
import struct
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autopnex.tools.ctf_pwn.checksec import checksec, _parse_elf_headers
from autopnex.tools.ctf_pwn.rop_chain import (
    rop_chain,
    _parse_ropgadget_output,
    _filter_useful_gadgets,
    _build_chain_template,
)
from autopnex.tools.ctf_pwn.format_string import format_string_exploit, _pack_address, _addr_size
from autopnex.tools.ctf_pwn.remote_interact import remote_interact, _remote_interact_sync


# =============================================================================
# Helper: create a minimal valid ELF binary for testing
# =============================================================================

def _create_minimal_elf(
    bits: int = 64,
    pie: bool = False,
    nx: bool = True,
    canary: bool = False,
) -> bytes:
    """Create a minimal ELF binary for testing checksec parsing.

    This creates a bare-bones ELF with program headers that checksec can parse.
    """
    if bits == 64:
        # ELF64 header
        e_ident = b"\x7fELF"  # magic
        e_ident += b"\x02"  # EI_CLASS: 64-bit
        e_ident += b"\x01"  # EI_DATA: little-endian
        e_ident += b"\x01"  # EI_VERSION
        e_ident += b"\x00" * 9  # padding

        e_type = struct.pack("<H", 3 if pie else 2)  # ET_DYN or ET_EXEC
        e_machine = struct.pack("<H", 0x3E)  # x86_64
        e_version = struct.pack("<I", 1)
        e_entry = struct.pack("<Q", 0x401000)
        e_phoff = struct.pack("<Q", 64)  # program headers start right after ELF header
        e_shoff = struct.pack("<Q", 0)  # no section headers
        e_flags = struct.pack("<I", 0)
        e_ehsize = struct.pack("<H", 64)
        e_phentsize = struct.pack("<H", 56)  # size of program header entry

        # We'll have 1-2 program headers
        ph_count = 1  # PT_GNU_STACK
        if nx:
            ph_count = 1

        e_phnum = struct.pack("<H", ph_count)
        e_shentsize = struct.pack("<H", 64)
        e_shnum = struct.pack("<H", 0)
        e_shstrndx = struct.pack("<H", 0)

        elf_header = (
            e_ident + e_type + e_machine + e_version + e_entry +
            e_phoff + e_shoff + e_flags + e_ehsize + e_phentsize +
            e_phnum + e_shentsize + e_shnum + e_shstrndx
        )

        # PT_GNU_STACK program header (64-bit)
        PT_GNU_STACK = 0x6474E551
        p_type = struct.pack("<I", PT_GNU_STACK)
        p_flags = struct.pack("<I", 0x06 if nx else 0x07)  # RW (no X) if NX, RWX otherwise
        p_offset = struct.pack("<Q", 0)
        p_vaddr = struct.pack("<Q", 0)
        p_paddr = struct.pack("<Q", 0)
        p_filesz = struct.pack("<Q", 0)
        p_memsz = struct.pack("<Q", 0)
        p_align = struct.pack("<Q", 0x10)

        ph_gnu_stack = p_type + p_flags + p_offset + p_vaddr + p_paddr + p_filesz + p_memsz + p_align

        data = elf_header + ph_gnu_stack

        # Add __stack_chk_fail string if canary is enabled
        if canary:
            data += b"\x00__stack_chk_fail\x00"

        return data

    else:
        # ELF32 header
        e_ident = b"\x7fELF"
        e_ident += b"\x01"  # EI_CLASS: 32-bit
        e_ident += b"\x01"  # EI_DATA: little-endian
        e_ident += b"\x01"  # EI_VERSION
        e_ident += b"\x00" * 9

        e_type = struct.pack("<H", 3 if pie else 2)
        e_machine = struct.pack("<H", 0x03)  # x86
        e_version = struct.pack("<I", 1)
        e_entry = struct.pack("<I", 0x08048000)
        e_phoff = struct.pack("<I", 52)  # program headers after ELF header
        e_shoff = struct.pack("<I", 0)
        e_flags = struct.pack("<I", 0)
        e_ehsize = struct.pack("<H", 52)
        e_phentsize = struct.pack("<H", 32)

        ph_count = 1
        e_phnum = struct.pack("<H", ph_count)
        e_shentsize = struct.pack("<H", 40)
        e_shnum = struct.pack("<H", 0)
        e_shstrndx = struct.pack("<H", 0)

        elf_header = (
            e_ident + e_type + e_machine + e_version + e_entry +
            e_phoff + e_shoff + e_flags + e_ehsize + e_phentsize +
            e_phnum + e_shentsize + e_shnum + e_shstrndx
        )

        # PT_GNU_STACK (32-bit)
        PT_GNU_STACK = 0x6474E551
        p_type = struct.pack("<I", PT_GNU_STACK)
        p_offset = struct.pack("<I", 0)
        p_vaddr = struct.pack("<I", 0)
        p_paddr = struct.pack("<I", 0)
        p_filesz = struct.pack("<I", 0)
        p_memsz = struct.pack("<I", 0)
        p_flags = struct.pack("<I", 0x06 if nx else 0x07)
        p_align = struct.pack("<I", 0x10)

        ph_gnu_stack = p_type + p_offset + p_vaddr + p_paddr + p_filesz + p_memsz + p_flags + p_align

        data = elf_header + ph_gnu_stack

        if canary:
            data += b"\x00__stack_chk_fail\x00"

        return data


# =============================================================================
# Tests for checksec
# =============================================================================

class TestChecksec:
    """Tests for the checksec standalone function."""

    def test_missing_binary_path(self):
        """checksec returns error when binary_path is empty."""
        result = checksec("")
        assert "error" in result
        assert "required" in result["error"].lower()

    def test_nonexistent_file(self):
        """checksec returns error for non-existent file."""
        result = checksec("/nonexistent/path/binary")
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_invalid_elf_file(self):
        """checksec returns error for non-ELF file."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"This is not an ELF file at all")
            f.flush()
            result = checksec(f.name)
        assert "error" in result
        assert "ELF" in result["error"]

    def test_parse_64bit_elf_nx_enabled(self):
        """checksec correctly detects NX enabled on 64-bit ELF."""
        elf_data = _create_minimal_elf(bits=64, nx=True, pie=False)
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(elf_data)
            f.flush()
            result = checksec(f.name)
        assert "error" not in result
        assert result["nx"] is True
        assert result["bits"] == 64
        assert result["arch"] == "x86_64"

    def test_parse_64bit_elf_pie_enabled(self):
        """checksec correctly detects PIE on 64-bit ELF."""
        elf_data = _create_minimal_elf(bits=64, pie=True)
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(elf_data)
            f.flush()
            result = checksec(f.name)
        assert "error" not in result
        assert result["pie"] is True

    def test_parse_64bit_elf_no_pie(self):
        """checksec correctly detects no PIE on 64-bit ELF."""
        elf_data = _create_minimal_elf(bits=64, pie=False)
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(elf_data)
            f.flush()
            result = checksec(f.name)
        assert "error" not in result
        assert result["pie"] is False

    def test_parse_32bit_elf(self):
        """checksec correctly parses 32-bit ELF."""
        elf_data = _create_minimal_elf(bits=32, nx=True, pie=False)
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(elf_data)
            f.flush()
            result = checksec(f.name)
        assert "error" not in result
        assert result["bits"] == 32
        assert result["arch"] == "x86"
        assert result["nx"] is True

    def test_parse_canary_detected(self):
        """checksec detects stack canary via __stack_chk_fail string."""
        elf_data = _create_minimal_elf(bits=64, canary=True)
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(elf_data)
            f.flush()
            result = checksec(f.name)
        assert "error" not in result
        assert result["canary"] is True

    def test_parse_no_canary(self):
        """checksec reports no canary when __stack_chk_fail is absent."""
        elf_data = _create_minimal_elf(bits=64, canary=False)
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(elf_data)
            f.flush()
            result = checksec(f.name)
        assert "error" not in result
        assert result["canary"] is False

    @patch("autopnex.tools.ctf_pwn.checksec.shutil.which", return_value="/usr/bin/checksec")
    @patch("autopnex.tools.ctf_pwn.checksec.subprocess.run")
    def test_uses_external_checksec_when_available(self, mock_run, mock_which):
        """checksec uses external binary when available."""
        # Create a dummy file so path.exists() passes
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            f.flush()
            fname = f.name

        # Use the actual file path as the JSON key
        import json
        json_output = json.dumps({
            fname: {"nx": "enabled", "pie": "enabled", "canary": "disabled", "relro": "Full RELRO", "arch": "amd64", "bits": "64"}
        })
        mock_run.return_value = MagicMock(returncode=0, stdout=json_output)

        result = checksec(fname)
        assert result.get("source") == "checksec_binary"
        assert result["nx"] is True
        assert result["pie"] is True


# =============================================================================
# Tests for rop_chain
# =============================================================================

class TestRopChain:
    """Tests for the rop_chain standalone function."""

    def test_missing_binary_path(self):
        """rop_chain returns error when binary_path is empty."""
        result = rop_chain("")
        assert "error" in result
        assert result["gadgets"] == []
        assert result["chain"] == []

    def test_nonexistent_file(self):
        """rop_chain returns error for non-existent file."""
        result = rop_chain("/nonexistent/binary")
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_returns_structure_with_no_ropgadget(self):
        """rop_chain returns valid structure even without ROPgadget installed."""
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(_create_minimal_elf(bits=64))
            f.flush()
            with patch("autopnex.tools.ctf_pwn.rop_chain.shutil.which", return_value=None):
                result = rop_chain(f.name)
        assert "gadgets" in result
        assert "chain" in result
        assert "payload_template" in result
        assert isinstance(result["gadgets"], list)
        assert isinstance(result["chain"], list)
        assert isinstance(result["payload_template"], str)

    def test_parse_ropgadget_output(self):
        """_parse_ropgadget_output correctly parses ROPgadget format."""
        output = (
            "Gadgets information\n"
            "============================================================\n"
            "0x0000000000401234 : pop rdi ; ret\n"
            "0x0000000000401238 : pop rsi ; ret\n"
            "0x000000000040123c : ret\n"
            "\n"
            "Unique gadgets found: 3\n"
        )
        gadgets = _parse_ropgadget_output(output)
        assert len(gadgets) == 3
        assert gadgets[0]["address"] == "0x0000000000401234"
        assert gadgets[0]["gadget"] == "pop rdi ; ret"
        assert gadgets[2]["gadget"] == "ret"

    def test_filter_useful_gadgets(self):
        """_filter_useful_gadgets keeps only useful gadgets."""
        gadgets = [
            {"address": "0x401234", "gadget": "pop rdi ; ret"},
            {"address": "0x401238", "gadget": "mov eax, 0x1 ; nop ; add rsp, 0x8 ; ret"},
            {"address": "0x40123c", "gadget": "ret"},
            {"address": "0x401240", "gadget": "syscall ; ret"},
        ]
        useful = _filter_useful_gadgets(gadgets)
        # pop rdi, ret, and syscall should be kept
        assert len(useful) >= 3
        gadget_strs = [g["gadget"] for g in useful]
        assert "pop rdi ; ret" in gadget_strs
        assert "ret" in gadget_strs
        assert "syscall ; ret" in gadget_strs

    def test_build_chain_template_system(self):
        """_build_chain_template generates system/binsh chain."""
        gadgets = [
            {"address": "0x401234", "gadget": "pop rdi ; ret"},
            {"address": "0x40123c", "gadget": "ret"},
        ]
        result = _build_chain_template("system_binsh", gadgets)
        assert "chain" in result
        assert "payload_template" in result
        assert len(result["chain"]) > 0
        assert "system()" in result["chain"][-1]
        assert "p64" in result["payload_template"]

    def test_build_chain_template_execve(self):
        """_build_chain_template generates execve chain."""
        gadgets = [
            {"address": "0x401234", "gadget": "pop rdi ; ret"},
            {"address": "0x401238", "gadget": "pop rsi ; ret"},
            {"address": "0x40123c", "gadget": "pop rdx ; ret"},
            {"address": "0x401240", "gadget": "pop rax ; ret"},
            {"address": "0x401244", "gadget": "syscall ; ret"},
        ]
        result = _build_chain_template("execve", gadgets)
        assert len(result["chain"]) > 0
        assert "syscall" in result["chain"][-1].lower()

    @patch("autopnex.tools.ctf_pwn.rop_chain.shutil.which", return_value="/usr/bin/ROPgadget")
    @patch("autopnex.tools.ctf_pwn.rop_chain.subprocess.run")
    def test_rop_chain_with_external_tool(self, mock_run, mock_which):
        """rop_chain uses ROPgadget when available."""
        mock_run.return_value = MagicMock(
            stdout="0x0000000000401234 : pop rdi ; ret\n0x0000000000401238 : ret\n",
            stderr="",
            returncode=0,
        )
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(_create_minimal_elf(bits=64))
            f.flush()
            result = rop_chain(f.name, target="system")
        assert len(result["gadgets"]) == 2
        assert result["gadgets"][0]["gadget"] == "pop rdi ; ret"


# =============================================================================
# Tests for format_string_exploit
# =============================================================================

class TestFormatStringExploit:
    """Tests for the format_string_exploit standalone function."""

    def test_invalid_offset(self):
        """format_string_exploit returns error for offset < 1."""
        result = format_string_exploit(offset=0, target_addr=0x601000, value=0x41)
        assert "error" in result
        assert result["payload"] == b""

    def test_invalid_address(self):
        """format_string_exploit returns error for negative address."""
        result = format_string_exploit(offset=6, target_addr=-1, value=0x41)
        assert "error" in result
        assert result["payload"] == b""

    def test_basic_x64_payload(self):
        """format_string_exploit generates non-empty payload for x64."""
        result = format_string_exploit(
            offset=6,
            target_addr=0x601040,
            value=0x42,
            arch="x64",
        )
        assert "error" not in result
        assert len(result["payload"]) > 0
        assert len(result["writes"]) > 0
        assert "explanation" in result
        assert "0x601040" in result["explanation"]

    def test_basic_x86_payload(self):
        """format_string_exploit generates non-empty payload for x86."""
        result = format_string_exploit(
            offset=7,
            target_addr=0x08049000,
            value=0xdeadbeef,
            arch="x86",
        )
        assert "error" not in result
        assert len(result["payload"]) > 0
        assert len(result["writes"]) > 0

    def test_payload_contains_hhn(self):
        """format_string_exploit uses %hhn for byte-by-byte writes."""
        result = format_string_exploit(
            offset=6,
            target_addr=0x601040,
            value=0x41,
            arch="x64",
        )
        # The payload should contain %hhn format specifiers
        payload_str = result["payload"].decode("ascii", errors="replace")
        assert "hhn" in payload_str

    def test_writes_list_structure(self):
        """format_string_exploit writes list has correct structure."""
        result = format_string_exploit(
            offset=6,
            target_addr=0x601040,
            value=0xABCD,
            arch="x64",
        )
        assert len(result["writes"]) >= 1
        for write in result["writes"]:
            assert "address" in write
            assert "value" in write
            assert "byte_index" in write
            assert "format_spec" in write

    def test_x64_address_packing(self):
        """_pack_address packs x64 addresses as 8 bytes little-endian."""
        packed = _pack_address(0x7fff12345678, "x64")
        assert len(packed) == 8
        assert struct.unpack("<Q", packed)[0] == 0x7fff12345678

    def test_x86_address_packing(self):
        """_pack_address packs x86 addresses as 4 bytes little-endian."""
        packed = _pack_address(0x08049000, "x86")
        assert len(packed) == 4
        assert struct.unpack("<I", packed)[0] == 0x08049000

    def test_addr_size_x64(self):
        """_addr_size returns 8 for x64 architectures."""
        assert _addr_size("x64") == 8
        assert _addr_size("amd64") == 8
        assert _addr_size("x86_64") == 8

    def test_addr_size_x86(self):
        """_addr_size returns 4 for x86 architectures."""
        assert _addr_size("x86") == 4
        assert _addr_size("i386") == 4

    def test_multi_byte_write(self):
        """format_string_exploit handles multi-byte values correctly."""
        result = format_string_exploit(
            offset=6,
            target_addr=0x601040,
            value=0x12345678,
            arch="x64",
        )
        assert "error" not in result
        # Should have multiple writes for a multi-byte value
        assert len(result["writes"]) >= 2


# =============================================================================
# Tests for remote_interact
# =============================================================================

class TestRemoteInteract:
    """Tests for the remote_interact async function."""

    def test_empty_host(self):
        """remote_interact returns error for empty host."""
        result = asyncio.run(remote_interact("", 1234, b"hello"))
        assert result["success"] is False
        assert "host" in result["error"].lower()

    def test_invalid_port_zero(self):
        """remote_interact returns error for port 0."""
        result = asyncio.run(remote_interact("localhost", 0, b"hello"))
        assert result["success"] is False
        assert "port" in result["error"].lower()

    def test_invalid_port_too_high(self):
        """remote_interact returns error for port > 65535."""
        result = asyncio.run(remote_interact("localhost", 99999, b"hello"))
        assert result["success"] is False
        assert "port" in result["error"].lower()

    def test_connection_refused(self):
        """remote_interact handles connection refused gracefully."""
        # Use a port that's almost certainly not listening
        result = asyncio.run(remote_interact("127.0.0.1", 19999, b"test", recv_timeout=1.0))
        assert result["success"] is False
        assert result["error"] != ""

    @patch("autopnex.tools.ctf_pwn.remote_interact.asyncio.open_connection")
    def test_successful_interaction(self, mock_open_conn):
        """remote_interact returns response on successful connection."""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.drain = AsyncMock()

        # First read returns banner, second read returns response, third returns empty
        mock_reader.read = AsyncMock(side_effect=[
            b"Welcome!\n",
            b"flag{test_flag_123}\n",
            b"",
        ])

        mock_open_conn.return_value = (mock_reader, mock_writer)

        result = asyncio.run(remote_interact("challenge.ctf.com", 9999, b"exploit\n", recv_timeout=2.0))
        assert result["success"] is True
        assert b"Welcome!" in result["response"]
        assert b"flag{test_flag_123}" in result["response"]

    @patch("autopnex.tools.ctf_pwn.remote_interact.asyncio.open_connection")
    def test_timeout_during_connection(self, mock_open_conn):
        """remote_interact handles connection timeout."""
        mock_open_conn.side_effect = asyncio.TimeoutError()

        result = asyncio.run(remote_interact("unreachable.host", 1234, b"test", recv_timeout=1.0))
        assert result["success"] is False
        assert "timeout" in result["error"].lower()


class TestRemoteInteractSync:
    """Tests for the synchronous _remote_interact_sync helper."""

    def test_empty_host(self):
        """_remote_interact_sync returns error for empty host."""
        result = _remote_interact_sync("", 1234, b"hello")
        assert result["success"] is False
        assert "host" in result["error"].lower()

    def test_invalid_port(self):
        """_remote_interact_sync returns error for invalid port."""
        result = _remote_interact_sync("localhost", 0, b"hello")
        assert result["success"] is False
        assert "port" in result["error"].lower()

    @patch("autopnex.tools.ctf_pwn.remote_interact.socket.socket")
    def test_successful_sync_interaction(self, mock_socket_cls):
        """_remote_interact_sync returns response on successful connection."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # recv returns banner, then response, then empty
        mock_sock.recv = MagicMock(side_effect=[
            b"Banner\n",
            b"Response data\n",
            b"",
        ])

        result = _remote_interact_sync("localhost", 8080, b"payload\n", recv_timeout=2.0)
        assert result["success"] is True
        assert b"Banner" in result["response"]
        assert b"Response data" in result["response"]
        mock_sock.sendall.assert_called_once_with(b"payload\n")

    @patch("autopnex.tools.ctf_pwn.remote_interact.socket.socket")
    def test_connection_timeout_sync(self, mock_socket_cls):
        """_remote_interact_sync handles socket timeout."""
        import socket as socket_mod
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = socket_mod.timeout("timed out")

        result = _remote_interact_sync("unreachable", 1234, b"test", recv_timeout=1.0)
        assert result["success"] is False
        assert "timeout" in result["error"].lower()


# =============================================================================
# Tests for CTF_PWN_TOOLS registry
# =============================================================================

class TestCTFPwnToolsRegistry:
    """Tests for the CTF_PWN_TOOLS registry dict."""

    def test_registry_contains_all_tools(self):
        """CTF_PWN_TOOLS contains all four tool functions."""
        from autopnex.tools.ctf_pwn import CTF_PWN_TOOLS

        assert "checksec" in CTF_PWN_TOOLS
        assert "rop_chain" in CTF_PWN_TOOLS
        assert "format_string_exploit" in CTF_PWN_TOOLS
        assert "remote_interact" in CTF_PWN_TOOLS

    def test_registry_values_are_callable(self):
        """All CTF_PWN_TOOLS values are callable functions."""
        from autopnex.tools.ctf_pwn import CTF_PWN_TOOLS

        for name, func in CTF_PWN_TOOLS.items():
            assert callable(func), f"{name} is not callable"

    def test_exports_available(self):
        """All expected symbols are importable from the package."""
        from autopnex.tools.ctf_pwn import (
            ChecksecTool,
            ROPChainTool,
            FormatStringTool,
            RemoteInteractTool,
            checksec,
            rop_chain,
            format_string_exploit,
            remote_interact,
            CTF_PWN_TOOLS,
        )
        # Just verify they're importable and not None
        assert ChecksecTool is not None
        assert ROPChainTool is not None
        assert FormatStringTool is not None
        assert RemoteInteractTool is not None
