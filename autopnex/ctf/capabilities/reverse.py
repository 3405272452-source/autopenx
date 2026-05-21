"""Reverse CTF Capability - static triage, string extraction, decompiler bridge.

Operates on binary attachments: runs strings/file/readelf/objdump,
extracts interesting strings, detects check/compare functions,
and bridges to IDA Pro / jadx when available.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import CTFCapability

log = logging.getLogger("autopnex.ctf.capabilities.reverse")


class ReverseCTFCapability(CTFCapability):
    name = "reverse"

    def suggest_tools(self) -> Dict[str, Any]:
        return {
            "recommended_tools": [
                "file_analyze",
                "run_python",
                "ctf_tool_manager",
                "ctf_knowledge_search",
            ]
        }

    def run_preflight(self, agent: Any) -> None:
        """Run static triage on any attached binaries."""
        if not agent._files:
            return
        for file_path in agent._files:
            triage = self._static_triage(file_path)
            if triage:
                agent._messages.append({
                    "role": "user",
                    "content": (
                        f"Static triage for {Path(file_path).name}:\n"
                        + self._format_triage(triage)
                    ),
                })
                agent._state.add_step(0, "reverse_triage", {"file": file_path}, str(triage)[:500])

                # Persist triage to artifact store
                if hasattr(agent, "_artifact_store"):
                    agent._artifact_store.register_snapshot(
                        label=f"reverse_triage_{Path(file_path).name}",
                        data=triage,
                    )

            # APK: auto-decompile with jadx
            if triage.get("file_type") == "ZIP archive" and file_path.lower().endswith(".apk"):
                decompile_info = self._try_jadx_decompile(file_path, agent)
                if decompile_info:
                    agent._messages.append({
                        "role": "user",
                        "content": decompile_info,
                    })
                    agent._state.add_step(0, "jadx_decompile", {"file": file_path}, decompile_info[:500])

            # JS file: extract API endpoints and crypto logic
            if file_path.lower().endswith(".js") or file_path.lower().endswith(".mjs"):
                js_analysis = self._analyze_js_file(file_path)
                if js_analysis:
                    agent._messages.append({
                        "role": "user",
                        "content": js_analysis,
                    })
                    agent._state.add_step(0, "js_analysis", {"file": file_path}, js_analysis[:500])

            # ZIP source package (non-APK): scan internal JS and config files
            if triage.get("file_type") == "ZIP archive" and not file_path.lower().endswith(".apk"):
                zip_analysis = self._analyze_zip_source(file_path, agent)
                if zip_analysis:
                    agent._messages.append({
                        "role": "user",
                        "content": zip_analysis,
                    })
                    agent._state.add_step(0, "zip_source_analysis", {"file": file_path}, zip_analysis[:500])

    def run_helpers(
        self,
        *,
        agent: Any,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if tool_name == "file_analyze":
            file_path = tool_args.get("file_path", "")
            if file_path and Path(file_path).exists():
                triage = self._static_triage(file_path)
                if triage.get("interesting_strings"):
                    return {
                        "helper": "reverse_strings_analysis",
                        "file": file_path,
                        "interesting_strings": triage["interesting_strings"][:20],
                        "suspected_checks": triage.get("suspected_checks", []),
                    }
        return None

    # -- static triage -----------------------------------------------------

    @staticmethod
    def _static_triage(file_path: str) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.exists():
            return {"error": "file not found"}

        data = path.read_bytes()
        file_type = ReverseCTFCapability._detect_magic(data[:16])

        triage: Dict[str, Any] = {
            "file_type": file_type,
            "size": len(data),
        }

        # strings extraction
        strings_list = ReverseCTFCapability._extract_strings(path)
        triage["strings_count"] = len(strings_list)
        triage["interesting_strings"] = ReverseCTFCapability._filter_interesting_strings(strings_list)

        # Binary analysis commands
        if file_type in {"ELF binary", "PE executable"}:
            triage["file_info"] = ReverseCTFCapability._run_cmd(["file", str(path)])
            triage["readelf_headers"] = ReverseCTFCapability._run_cmd(["readelf", "-h", str(path)])
            triage["symbols"] = ReverseCTFCapability._run_cmd(["nm", str(path)], fallback="")
            triage["suspected_checks"] = ReverseCTFCapability._find_check_functions(triage.get("symbols", ""))

        # Android APK -> suggest jadx
        if file_type == "ZIP archive" and path.suffix.lower() == ".apk":
            triage["note"] = "APK detected: suggest jadx for decompilation"

        return triage

    @staticmethod
    def _detect_magic(header: bytes) -> str:
        if header[:4] == b"\x7fELF":
            return "ELF binary"
        if header[:2] == b"MZ":
            return "PE executable"
        if header[:4] == b"PK\x03\x04":
            return "ZIP archive"
        if header[:4] == b"%PDF":
            return "PDF document"
        if header[:8] == b"\x89PNG\r\n\x1a\n":
            return "PNG image"
        return "unknown"

    @staticmethod
    def _extract_strings(path: Path, min_len: int = 4) -> List[str]:
        if shutil.which("strings"):
            try:
                out = subprocess.run(
                    ["strings", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                return [s for s in out.stdout.splitlines() if len(s) >= min_len]
            except Exception:
                pass
        # Pure-Python fallback
        data = path.read_bytes()
        return [s.decode("ascii") for s in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]

    @staticmethod
    def _filter_interesting_strings(strings_list: List[str]) -> List[str]:
        patterns = [
            r"flag\{",
            r"FLAG\{",
            r"password",
            r"secret",
            r"correct",
            r"wrong",
            r"input",
            r"scanf",
            r"strcmp",
            r"memcmp",
            r"check",
            r"validate",
            r"encode",
            r"decode",
            r"base64",
            r"AES",
            r"RSA",
            r"key",
            r"encrypt",
            r"decrypt",
            r"MD5",
            r"SHA",
            r"win",
            r"lose",
            r"congratulations",
        ]
        interesting = []
        seen = set()
        for s in strings_list:
            for pat in patterns:
                if re.search(pat, s, re.IGNORECASE) and s not in seen:
                    interesting.append(s)
                    seen.add(s)
                    break
        return interesting[:50]

    @staticmethod
    def _run_cmd(cmd: List[str], fallback: str = "") -> str:
        if not shutil.which(cmd[0]):
            return fallback
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return out.stdout[:2000]
        except Exception:
            return fallback

    @staticmethod
    def _find_check_functions(symbols_text: str) -> List[str]:
        checks = []
        for line in symbols_text.splitlines():
            if any(k in line for k in ("check", "verify", "validate", "compare", "cmp", "auth")):
                checks.append(line.strip().split()[-1] if line.strip() else line)
        return checks[:10]

    @staticmethod
    def _format_triage(triage: Dict[str, Any]) -> str:
        parts = [
            f"- File type: {triage.get('file_type', 'unknown')}",
            f"- Size: {triage.get('size', 0)} bytes",
        ]
        if triage.get("interesting_strings"):
            parts.append("- Interesting strings:")
            for s in triage["interesting_strings"][:10]:
                parts.append(f"  - {s}")
        if triage.get("suspected_checks"):
            parts.append("- Suspected check functions:")
            for fn in triage["suspected_checks"][:5]:
                parts.append(f"  - {fn}")
        if triage.get("note"):
            parts.append(f"- Note: {triage['note']}")
        return "\n".join(parts)

    # -- jadx decompile ------------------------------------------------------

    def _try_jadx_decompile(self, apk_path: str, agent: Any) -> Optional[str]:
        """Attempt to decompile APK using jadx CLI."""
        jadx_paths = [
            os.environ.get("JADX_PATH", ""),
            r"F:\download\jadx-1.5.3\bin\jadx.bat",
            r"F:\download\jadx-1.5.3\bin\jadx",
            "jadx",
        ]
        jadx_cmd = None
        for p in jadx_paths:
            if p and (shutil.which(p) or Path(p).exists()):
                jadx_cmd = p
                break

        if not jadx_cmd:
            return None

        output_dir = Path(agent._tool_workspace.root) / "jadx_out" / Path(apk_path).stem
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            proc = subprocess.run(
                [jadx_cmd, "-d", str(output_dir), apk_path],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0 and not list(output_dir.rglob("*.java")):
                return f"jadx exit_code={proc.returncode}: {proc.stderr[:500]}"
        except Exception as exc:
            return f"jadx failed: {exc}"

        java_files = list(output_dir.rglob("*.java"))
        results = [
            f"APK decompiled to {output_dir}",
            f"Total Java files: {len(java_files)}",
        ]

        # Extract entry points and API/crypto-related classes
        interesting_patterns = ["MainActivity", "Login", "Api", "Service", "Http", "Network", "Crypto", "Encrypt", "Flag"]
        for f in java_files:
            rel_path = str(f.relative_to(output_dir))
            if any(pat in rel_path for pat in interesting_patterns):
                content = f.read_text(encoding="utf-8", errors="ignore")[:2000]
                results.append(f"\n--- {rel_path} ---\n{content[:1500]}")

        # Register artifact
        if hasattr(agent, "_artifact_store"):
            agent._artifact_store.register_snapshot(
                label=f"jadx_{Path(apk_path).name}",
                data={
                    "output_dir": str(output_dir),
                    "java_files": [str(f.relative_to(output_dir)) for f in java_files[:50]],
                },
            )

        return "\n".join(results[:30])

    # -- JS analysis --------------------------------------------------------

    @staticmethod
    def _analyze_js_file(js_path: str) -> Optional[str]:
        path = Path(js_path)
        if not path.exists():
            return None
        content = path.read_text(encoding="utf-8", errors="ignore")

        results = [f"JS file analysis: {path.name}"]

        # API endpoints / routes
        endpoints: set[str] = set()
        for pat in [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post)\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
            r'["\'](/api/[^"\']+)["\']',
        ]:
            for m in re.finditer(pat, content):
                endpoints.add(m.group(1))
        if endpoints:
            results.append("Detected API endpoints/routes:")
            for ep in sorted(endpoints)[:15]:
                results.append(f"  - {ep}")

        # Crypto-related code snippets
        crypto_keywords = ["encrypt", "decrypt", "AES", "RSA", "CryptoJS", "md5", "sha256", "base64", "xor", "hmac"]
        crypto_lines = []
        for i, line in enumerate(content.splitlines()):
            if any(kw in line.lower() for kw in crypto_keywords):
                crypto_lines.append(f"  L{i+1}: {line.strip()[:120]}")
        if crypto_lines:
            results.append("Crypto-related code snippets:")
            results.extend(crypto_lines[:10])

        # Flag-like strings
        flag_matches = re.findall(r'[A-Za-z0-9_]+\{[^}]*\}', content, re.IGNORECASE)
        if flag_matches:
            results.append(f"Flag patterns found: {flag_matches[:5]}")

        return "\n".join(results) if len(results) > 1 else None

    # -- ZIP source analysis ------------------------------------------------

    def _analyze_zip_source(self, zip_path: str, agent: Any) -> Optional[str]:
        path = Path(zip_path)
        if not path.exists():
            return None

        results = [f"Source package analysis: {path.name}"]

        try:
            with zipfile.ZipFile(path, "r") as zf:
                js_files = [n for n in zf.namelist() if n.lower().endswith(".js") and not n.startswith("__MACOSX")]
                results.append(f"JS files inside archive: {len(js_files)}")

                for js_name in js_files[:5]:
                    try:
                        content = zf.read(js_name).decode("utf-8", errors="ignore")
                        endpoints = set(re.findall(r'["\']([^"\']*\/(?:api|flag|login|admin|user)[^"\']*)["\']', content))
                        crypto_hints = [
                            line.strip()[:120]
                            for line in content.splitlines()
                            if any(kw in line.lower() for kw in ["encrypt", "aes", "cryptoj", "token", "api", "fetch", "axios"])
                        ]
                        if endpoints or crypto_hints:
                            results.append(f"\n--- {js_name} ---")
                            if endpoints:
                                results.append("  Endpoints: " + ", ".join(sorted(endpoints)[:8]))
                            if crypto_hints:
                                results.append("  Crypto/Network hints:")
                                for hint in crypto_hints[:5]:
                                    results.append(f"    {hint}")
                    except Exception:
                        pass
        except Exception as exc:
            return f"Failed to analyze zip: {exc}"

        # Register artifact
        if hasattr(agent, "_artifact_store"):
            agent._artifact_store.register_snapshot(
                label=f"zip_source_{Path(zip_path).name}",
                data={"js_files_found": len(js_files) if 'js_files' in dir() else 0},
            )

        return "\n".join(results) if len(results) > 1 else None
