"""Source attachment analysis for CTF challenges.

The analyzer is intentionally static and read-only: it inspects uploaded source
archives in memory, extracts a compact set of routes, parameters and risky PHP
constructs, and feeds that context to the CTF agent.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List


_TEXT_SUFFIXES = {".php", ".html", ".htm", ".js", ".txt", ".ini", ".conf", ".env", ".sql"}
_MAX_FILE_BYTES = 512_000
_MAX_ARCHIVE_ENTRIES = 250
_MAX_NESTED_DEPTH = 3

_DANGEROUS_PATTERNS: Dict[str, re.Pattern[str]] = {
    "unserialize": re.compile(r"\bunserialize\s*\(", re.I),
    "php_magic_method": re.compile(r"function\s+__(destruct|wakeup|toString|call|get|set|invoke)\s*\(", re.I),
    "file_read": re.compile(r"\b(file_get_contents|readfile|fopen|include|require|include_once|require_once)\s*\(", re.I),
    "file_write": re.compile(r"\b(file_put_contents|fwrite|move_uploaded_file)\s*\(", re.I),
    "file_delete": re.compile(r"\b(unlink|rmdir)\s*\(", re.I),
    "path_probe": re.compile(r"\b(file_exists|is_file|getimagesize|exif_read_data)\s*\(", re.I),
    "command_exec": re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(", re.I),
    "dynamic_call": re.compile(r"\b(call_user_func|call_user_func_array|eval|assert|preg_replace)\s*\(", re.I),
    "base64": re.compile(r"\bbase64_(decode|encode)\s*\(", re.I),
    "session": re.compile(r"\$_SESSION\b", re.I),
    "superglobal": re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b", re.I),
    "pdo_fetch_mode": re.compile(r"PDO::ATTR_DEFAULT_FETCH_MODE|FETCH_CLASS|FETCH_PROPS_LATE|262152", re.I),
    "pdo_connection_options": re.compile(r"\bdsn\b|mysql:host|PDO_connect|con_options", re.I),
}

_FORM_RE = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.I | re.S)
_INPUT_NAME_RE = re.compile(r"\bname\s*=\s*['\"]?([^'\"\s>]+)", re.I)
_ATTR_RE = re.compile(r"\b(action|method|enctype)\s*=\s*['\"]?([^'\"\s>]+)", re.I)
_SUPERGLOBAL_PARAM_RE = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", re.I)
_CLASS_RE = re.compile(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)", re.I)
_METHOD_RE = re.compile(r"function\s+(__[A-Za-z0-9_]+|[A-Za-z_][A-Za-z0-9_]*)\s*\(", re.I)


@dataclass
class SourceFinding:
    file: str
    kind: str
    detail: str
    line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"file": self.file, "kind": self.kind, "detail": self.detail, "line": self.line}


@dataclass
class SourceAnalysis:
    root_file: str
    files: List[Dict[str, Any]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    parameters: List[Dict[str, str]] = field(default_factory=list)
    classes: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[SourceFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_file": self.root_file,
            "files": self.files,
            "forms": self.forms,
            "parameters": self.parameters,
            "classes": self.classes,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
        }

    def to_prompt_context(self, *, max_findings: int = 35) -> str:
        lines = [f"Attachment: {self.root_file}"]
        if self.files:
            lines.append("Files: " + ", ".join(item["path"] for item in self.files[:30]))
        if self.forms:
            lines.append("Forms:")
            for form in self.forms[:10]:
                lines.append(
                    f"- {form.get('file')}: {form.get('method', 'GET')} {form.get('action', '')} "
                    f"fields={','.join(form.get('fields', []))}"
                )
        if self.parameters:
            params = [f"{p['source']}[{p['name']}]" for p in self.parameters[:30]]
            lines.append("User-controlled parameters: " + ", ".join(params))
        if self.classes:
            lines.append("Classes and methods:")
            for cls in self.classes[:15]:
                lines.append(f"- {cls.get('file')}: class {cls.get('name')} methods={','.join(cls.get('methods', []))}")
        if self.findings:
            lines.append("Risky source patterns:")
            for finding in self.findings[:max_findings]:
                loc = f"{finding.file}:{finding.line}" if finding.line else finding.file
                lines.append(f"- {loc} [{finding.kind}] {finding.detail}")
        if self.errors:
            lines.append("Analysis errors: " + "; ".join(self.errors[:5]))
        return "\n".join(lines)


def analyze_attachment(path: str | Path) -> SourceAnalysis:
    target = Path(path)
    analysis = SourceAnalysis(root_file=str(target))
    if not target.exists():
        analysis.errors.append(f"file_not_found:{target}")
        return analysis

    try:
        data = target.read_bytes()
    except OSError as exc:
        analysis.errors.append(f"read_error:{exc}")
        return analysis

    if zipfile.is_zipfile(io.BytesIO(data)):
        _analyze_zip_bytes(data, prefix="", analysis=analysis, depth=0)
    else:
        _analyze_file(target.name, data, analysis)
    _dedupe_analysis(analysis)
    return analysis


def analyze_attachments(paths: Iterable[str | Path]) -> List[SourceAnalysis]:
    return [analyze_attachment(path) for path in paths]


def _analyze_zip_bytes(data: bytes, *, prefix: str, analysis: SourceAnalysis, depth: int) -> None:
    if depth > _MAX_NESTED_DEPTH:
        analysis.errors.append(f"max_nested_depth:{prefix or '<root>'}")
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for index, info in enumerate(archive.infolist()):
                if index >= _MAX_ARCHIVE_ENTRIES:
                    analysis.errors.append(f"archive_entry_limit:{prefix or '<root>'}")
                    break
                if info.is_dir():
                    continue
                name = f"{prefix}{info.filename}"
                analysis.files.append({"path": name, "size": info.file_size})
                if info.file_size > _MAX_FILE_BYTES:
                    continue
                try:
                    content = archive.read(info)
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    analysis.errors.append(f"zip_read_error:{name}:{exc}")
                    continue
                if zipfile.is_zipfile(io.BytesIO(content)):
                    _analyze_zip_bytes(content, prefix=f"{name}!/", analysis=analysis, depth=depth + 1)
                elif Path(info.filename).suffix.lower() in _TEXT_SUFFIXES:
                    _analyze_file(name, content, analysis)
    except zipfile.BadZipFile as exc:
        analysis.errors.append(f"bad_zip:{prefix or '<root>'}:{exc}")


def _analyze_file(name: str, data: bytes, analysis: SourceAnalysis) -> None:
    text = _decode_text(data)
    if text is None:
        return
    _extract_forms(name, text, analysis)
    _extract_parameters(name, text, analysis)
    _extract_classes(name, text, analysis)
    _extract_findings(name, text, analysis)
    _extract_chain_hints(name, text, analysis)


def _decode_text(data: bytes) -> str | None:
    for encoding in ("utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def _extract_forms(name: str, text: str, analysis: SourceAnalysis) -> None:
    for match in _FORM_RE.finditer(text):
        attrs = {key.lower(): value for key, value in _ATTR_RE.findall(match.group("attrs"))}
        fields = _INPUT_NAME_RE.findall(match.group("body"))
        analysis.forms.append(
            {
                "file": name,
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "GET").upper(),
                "enctype": attrs.get("enctype", ""),
                "fields": sorted(set(fields)),
            }
        )


def _extract_parameters(name: str, text: str, analysis: SourceAnalysis) -> None:
    for source, param in _SUPERGLOBAL_PARAM_RE.findall(text):
        analysis.parameters.append({"file": name, "source": source.upper(), "name": param})


def _extract_classes(name: str, text: str, analysis: SourceAnalysis) -> None:
    classes = _CLASS_RE.findall(text)
    if not classes:
        return
    methods = sorted(set(_METHOD_RE.findall(text)))
    for cls in classes:
        analysis.classes.append({"file": name, "name": cls, "methods": methods})


def _extract_findings(name: str, text: str, analysis: SourceAnalysis) -> None:
    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        compact = line.strip()
        if not compact:
            continue
        for kind, pattern in _DANGEROUS_PATTERNS.items():
            if pattern.search(compact):
                analysis.findings.append(SourceFinding(file=name, kind=kind, detail=compact[:240], line=line_no))


def _extract_chain_hints(name: str, text: str, analysis: SourceAnalysis) -> None:
    lower = text.lower()
    if "file_exists" in lower and "unlink" in lower:
        analysis.findings.append(
            SourceFinding(
                file=name,
                kind="phar_trigger_candidate",
                detail="file_exists()/unlink() on user-controlled path can trigger phar:// metadata deserialization.",
            )
        )
    if "__set" in lower and "file_get_contents" in lower:
        analysis.findings.append(
            SourceFinding(
                file=name,
                kind="php_set_file_read_gadget",
                detail="__set() reads $this->filePath; can become a file-read gadget when property assignment is attacker-controlled.",
            )
        )
    if "pdo_connect" in lower and "attr_default_fetch_mode" in lower:
        analysis.findings.append(
            SourceFinding(
                file=name,
                kind="pdo_fetch_class_candidate",
                detail="PDO fetch mode is object-controllable; FETCH_CLASS|FETCH_PROPS_LATE (262152) can instantiate a class from query results.",
            )
        )


def _dedupe_analysis(analysis: SourceAnalysis) -> None:
    def dedupe_dicts(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        result = []
        for item in items:
            key = tuple(sorted((k, tuple(v) if isinstance(v, list) else v) for k, v in item.items()))
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    analysis.files = dedupe_dicts(analysis.files)
    analysis.forms = dedupe_dicts(analysis.forms)
    analysis.parameters = dedupe_dicts(analysis.parameters)
    analysis.classes = dedupe_dicts(analysis.classes)
    seen_findings = set()
    deduped_findings = []
    for finding in analysis.findings:
        key = (finding.file, finding.kind, finding.detail, finding.line)
        if key in seen_findings:
            continue
        seen_findings.add(key)
        deduped_findings.append(finding)
    analysis.findings = deduped_findings
