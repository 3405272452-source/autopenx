"""Source code audit agent for CTF Web challenges.

Performs static analysis on leaked source code to identify dangerous sinks,
user-controlled sources, and data flow paths from sources to sinks. Suggests
exploitation routes (sqli, cmdi, ssti, lfi, etc.) based on the identified flows.

Used by the multi-agent orchestrator after source code is obtained (e.g., via
source_leak, .bak file exposure, or source map recovery).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# --- Sink patterns by language ---

_PHP_SINKS: Dict[str, re.Pattern[str]] = {
    "eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
    "exec": re.compile(r"\bexec\s*\(", re.IGNORECASE),
    "system": re.compile(r"\bsystem\s*\(", re.IGNORECASE),
    "passthru": re.compile(r"\bpassthru\s*\(", re.IGNORECASE),
    "shell_exec": re.compile(r"\bshell_exec\s*\(", re.IGNORECASE),
    "popen": re.compile(r"\bpopen\s*\(", re.IGNORECASE),
    "proc_open": re.compile(r"\bproc_open\s*\(", re.IGNORECASE),
    "query": re.compile(r"\b(?:mysql_query|mysqli_query|->query)\s*\(", re.IGNORECASE),
    "prepare": re.compile(r"\b->prepare\s*\(", re.IGNORECASE),
    "render": re.compile(r"\b(?:render|display|twig.*render)\s*\(", re.IGNORECASE),
    "include": re.compile(r"\b(?:include|include_once|require|require_once)\s*[\s(]", re.IGNORECASE),
    "unserialize": re.compile(r"\bunserialize\s*\(", re.IGNORECASE),
    "file_get_contents": re.compile(r"\bfile_get_contents\s*\(", re.IGNORECASE),
    "file_put_contents": re.compile(r"\bfile_put_contents\s*\(", re.IGNORECASE),
    "preg_replace": re.compile(r"\bpreg_replace\s*\(", re.IGNORECASE),
    "assert": re.compile(r"\bassert\s*\(", re.IGNORECASE),
    "call_user_func": re.compile(r"\bcall_user_func(?:_array)?\s*\(", re.IGNORECASE),
}

_PYTHON_SINKS: Dict[str, re.Pattern[str]] = {
    "eval": re.compile(r"\beval\s*\("),
    "exec": re.compile(r"\bexec\s*\("),
    "system": re.compile(r"\bos\.system\s*\("),
    "popen": re.compile(r"\bos\.popen\s*\("),
    "subprocess": re.compile(r"\bsubprocess\.(?:call|run|Popen|check_output)\s*\("),
    "render_template_string": re.compile(r"\brender_template_string\s*\("),
    "query": re.compile(r"\b(?:execute|cursor\.execute|db\.execute|\.raw)\s*\("),
    "pickle_loads": re.compile(r"\bpickle\.loads\s*\("),
    "yaml_load": re.compile(r"\byaml\.load\s*\("),
}

_NODE_SINKS: Dict[str, re.Pattern[str]] = {
    "eval": re.compile(r"\beval\s*\("),
    "exec": re.compile(r"\b(?:child_process\.)?exec(?:Sync)?\s*\("),
    "spawn": re.compile(r"\b(?:child_process\.)?spawn(?:Sync)?\s*\("),
    "query": re.compile(r"\b(?:\.query|\.execute|sequelize\.query)\s*\("),
    "render": re.compile(r"\b(?:res\.render|\.render)\s*\("),
    "include": re.compile(r"\brequire\s*\("),
    "unserialize": re.compile(r"\b(?:unserialize|deserialize|JSON\.parse)\s*\("),
    "vm_run": re.compile(r"\bvm\.run(?:InContext|InNewContext)?\s*\("),
}

# --- Source patterns by language ---

_PHP_SOURCES: Dict[str, re.Pattern[str]] = {
    "$_GET": re.compile(r"\$_GET\s*\["),
    "$_POST": re.compile(r"\$_POST\s*\["),
    "$_REQUEST": re.compile(r"\$_REQUEST\s*\["),
    "$_COOKIE": re.compile(r"\$_COOKIE\s*\["),
    "$_FILES": re.compile(r"\$_FILES\s*\["),
    "$_SERVER": re.compile(r"\$_SERVER\s*\["),
    "php://input": re.compile(r"php://input", re.IGNORECASE),
}

_PYTHON_SOURCES: Dict[str, re.Pattern[str]] = {
    "request.args": re.compile(r"\brequest\.args"),
    "request.form": re.compile(r"\brequest\.form"),
    "request.json": re.compile(r"\brequest\.json"),
    "request.data": re.compile(r"\brequest\.data"),
    "request.files": re.compile(r"\brequest\.files"),
    "request.cookies": re.compile(r"\brequest\.cookies"),
    "request.headers": re.compile(r"\brequest\.headers"),
}

_NODE_SOURCES: Dict[str, re.Pattern[str]] = {
    "req.body": re.compile(r"\breq\.body"),
    "req.params": re.compile(r"\breq\.params"),
    "req.query": re.compile(r"\breq\.query"),
    "req.headers": re.compile(r"\breq\.headers"),
    "req.cookies": re.compile(r"\breq\.cookies"),
    "req.files": re.compile(r"\breq\.files"),
}

# --- Sink-to-route mapping ---

_SINK_ROUTE_MAP: Dict[str, List[str]] = {
    "eval": ["cmdi", "rce"],
    "exec": ["cmdi", "rce"],
    "system": ["cmdi"],
    "passthru": ["cmdi"],
    "shell_exec": ["cmdi"],
    "popen": ["cmdi"],
    "proc_open": ["cmdi"],
    "subprocess": ["cmdi"],
    "spawn": ["cmdi"],
    "query": ["sqli"],
    "prepare": ["sqli"],
    "render": ["ssti"],
    "render_template_string": ["ssti"],
    "include": ["lfi"],
    "unserialize": ["php_pop", "deserialization"],
    "pickle_loads": ["deserialization"],
    "yaml_load": ["deserialization"],
    "file_get_contents": ["ssrf", "lfi"],
    "file_put_contents": ["upload", "rce"],
    "preg_replace": ["rce"],
    "assert": ["rce"],
    "call_user_func": ["rce"],
    "vm_run": ["rce"],
}

# --- Variable tracking pattern for simple data flow ---

_PHP_VAR_ASSIGN_RE = re.compile(
    r"(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+?)(?:;|$)", re.MULTILINE
)

_PYTHON_VAR_ASSIGN_RE = re.compile(
    r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+?)(?:\n|$)", re.MULTILINE
)


@dataclass
class SinkInfo:
    """Information about a dangerous sink found in source code."""

    function: str
    file: str
    line: int
    context: str

    def __repr__(self) -> str:
        return f"Sink({self.function} at {self.file}:{self.line})"


@dataclass
class SourceInfo:
    """Information about a user-controlled source found in source code."""

    variable: str
    file: str
    line: int

    def __repr__(self) -> str:
        return f"Source({self.variable} at {self.file}:{self.line})"


@dataclass
class DataFlow:
    """A data flow path from a user-controlled source to a dangerous sink."""

    source: SourceInfo
    sink: SinkInfo
    path: List[str] = field(default_factory=list)
    exploitable: bool = True

    def __repr__(self) -> str:
        return f"Flow({self.source.variable} -> {self.sink.function})"


@dataclass
class AuditResult:
    """Complete audit result containing sinks, sources, flows, and suggested routes."""

    sinks: List[SinkInfo] = field(default_factory=list)
    sources: List[SourceInfo] = field(default_factory=list)
    flows: List[DataFlow] = field(default_factory=list)
    suggested_routes: List[str] = field(default_factory=list)

    def to_prompt_context(self, *, max_flows: int = 10) -> str:
        """Format audit result as prompt context for the LLM agent."""
        lines = ["Source Audit Results:"]

        if self.sources:
            lines.append(f"  User-controlled sources ({len(self.sources)}):")
            for src in self.sources[:15]:
                lines.append(f"    - {src.variable} at {src.file}:{src.line}")

        if self.sinks:
            lines.append(f"  Dangerous sinks ({len(self.sinks)}):")
            for sink in self.sinks[:15]:
                lines.append(f"    - {sink.function}() at {sink.file}:{sink.line}")

        if self.flows:
            lines.append(f"  Data flows ({len(self.flows)}):")
            for flow in self.flows[:max_flows]:
                path_str = " -> ".join(flow.path) if flow.path else "direct"
                lines.append(
                    f"    - {flow.source.variable} -> {flow.sink.function}() "
                    f"[path: {path_str}] {'EXPLOITABLE' if flow.exploitable else 'filtered'}"
                )

        if self.suggested_routes:
            lines.append(f"  Suggested exploitation routes: {', '.join(self.suggested_routes)}")

        return "\n".join(lines)


class SourceAuditAgent:
    """Static source code auditor that identifies source-to-sink data flows.

    Analyzes leaked source code to find dangerous sinks (eval, exec, query,
    render, include, unserialize, system, passthru) and user-controlled sources
    ($_GET, $_POST, $_REQUEST, request.args, req.body, req.params), then traces
    data flow paths and suggests exploitation routes.
    """

    def audit(self, source_code: str, language: str = "php") -> AuditResult:
        """Audit source code for security vulnerabilities.

        Args:
            source_code: The source code content to analyze.
            language: Programming language ("php", "python", "node"/"javascript").

        Returns:
            AuditResult with identified sinks, sources, flows, and suggested routes.
        """
        result = AuditResult()

        if not source_code or not source_code.strip():
            return result

        # Normalize language
        lang = language.lower().strip()
        if lang in ("js", "javascript", "typescript", "ts"):
            lang = "node"
        elif lang in ("py", "python3"):
            lang = "python"

        # Get patterns for the language
        sink_patterns = self._get_sink_patterns(lang)
        source_patterns = self._get_source_patterns(lang)

        # Find sinks
        result.sinks = self._find_sinks(source_code, sink_patterns)

        # Find sources
        result.sources = self._find_sources(source_code, source_patterns)

        # Trace data flows
        result.flows = self._trace_flows(source_code, result.sources, result.sinks, lang)

        # Suggest exploitation routes
        result.suggested_routes = self._suggest_routes(result.sinks, result.flows)

        return result

    def _get_sink_patterns(self, language: str) -> Dict[str, re.Pattern[str]]:
        """Get sink patterns for the specified language."""
        if language == "python":
            return _PYTHON_SINKS
        elif language == "node":
            return _NODE_SINKS
        else:
            return _PHP_SINKS

    def _get_source_patterns(self, language: str) -> Dict[str, re.Pattern[str]]:
        """Get source patterns for the specified language."""
        if language == "python":
            return _PYTHON_SOURCES
        elif language == "node":
            return _NODE_SOURCES
        else:
            return _PHP_SOURCES

    def _find_sinks(
        self, source_code: str, patterns: Dict[str, re.Pattern[str]], file_name: str = "<input>"
    ) -> List[SinkInfo]:
        """Find all dangerous sinks in the source code."""
        sinks: List[SinkInfo] = []
        lines = source_code.splitlines()

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                continue

            for func_name, pattern in patterns.items():
                if pattern.search(stripped):
                    context = stripped[:200]
                    sinks.append(SinkInfo(
                        function=func_name,
                        file=file_name,
                        line=line_no,
                        context=context,
                    ))

        return sinks

    def _find_sources(
        self, source_code: str, patterns: Dict[str, re.Pattern[str]], file_name: str = "<input>"
    ) -> List[SourceInfo]:
        """Find all user-controlled sources in the source code."""
        sources: List[SourceInfo] = []
        lines = source_code.splitlines()
        seen: Set[Tuple[str, int]] = set()

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                continue

            for var_name, pattern in patterns.items():
                if pattern.search(stripped):
                    key = (var_name, line_no)
                    if key not in seen:
                        seen.add(key)
                        sources.append(SourceInfo(
                            variable=var_name,
                            file=file_name,
                            line=line_no,
                        ))

        return sources

    def _trace_flows(
        self,
        source_code: str,
        sources: List[SourceInfo],
        sinks: List[SinkInfo],
        language: str,
    ) -> List[DataFlow]:
        """Trace data flow paths from sources to sinks.

        Uses a simplified intra-procedural analysis: checks if a source and sink
        appear in proximity (same function/block) or if a variable assigned from
        a source is later used in a sink call.
        """
        flows: List[DataFlow] = []
        lines = source_code.splitlines()

        if not sources or not sinks:
            return flows

        # Build a map of variable assignments from sources
        var_from_source: Dict[str, SourceInfo] = {}
        for source in sources:
            if source.line <= len(lines):
                line_content = lines[source.line - 1]
                # Extract the variable being assigned from this source
                assigned_vars = self._extract_assigned_vars(line_content, language)
                for var in assigned_vars:
                    var_from_source[var] = source

        # Check each sink for direct source usage or tainted variable usage
        for sink in sinks:
            if sink.line <= len(lines):
                sink_line = lines[sink.line - 1]

                # Check for direct source in sink line
                for source in sources:
                    if self._source_in_line(source.variable, sink_line, language):
                        flows.append(DataFlow(
                            source=source,
                            sink=sink,
                            path=["direct"],
                            exploitable=True,
                        ))

                # Check for tainted variables in sink line
                for var_name, source in var_from_source.items():
                    if var_name in sink_line and source.line != sink.line:
                        # Check if there's any sanitization between source and sink
                        sanitized = self._check_sanitization(
                            lines, source.line, sink.line, var_name, language
                        )
                        flows.append(DataFlow(
                            source=source,
                            sink=sink,
                            path=[f"${var_name}" if language == "php" else var_name],
                            exploitable=not sanitized,
                        ))

        # Deduplicate flows
        seen_flows: Set[Tuple[str, int, str, int]] = set()
        unique_flows: List[DataFlow] = []
        for flow in flows:
            key = (flow.source.variable, flow.source.line, flow.sink.function, flow.sink.line)
            if key not in seen_flows:
                seen_flows.add(key)
                unique_flows.append(flow)

        return unique_flows

    def _extract_assigned_vars(self, line: str, language: str) -> List[str]:
        """Extract variable names being assigned in a line."""
        vars_found: List[str] = []

        if language == "php":
            # Match $var = ...
            matches = re.findall(r"(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*=", line)
            vars_found.extend(matches)
        elif language == "python":
            # Match var = ...
            matches = re.findall(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=(?!=)", line)
            vars_found.extend(matches)
        elif language == "node":
            # Match var/let/const name = ... or name = ...
            matches = re.findall(
                r"(?:var|let|const)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=", line
            )
            if not matches:
                matches = re.findall(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=(?!=)", line)
            vars_found.extend(matches)

        return vars_found

    def _source_in_line(self, source_variable: str, line: str, language: str) -> bool:
        """Check if a source variable pattern appears in a line."""
        # Escape special regex chars in the variable name
        escaped = re.escape(source_variable)
        return bool(re.search(escaped, line))

    def _check_sanitization(
        self,
        lines: List[str],
        source_line: int,
        sink_line: int,
        var_name: str,
        language: str,
    ) -> bool:
        """Check if there's sanitization between source and sink lines.

        Looks for common sanitization functions applied to the variable.
        """
        sanitizers_php = [
            "htmlspecialchars", "htmlentities", "intval", "floatval",
            "addslashes", "mysql_real_escape_string", "mysqli_real_escape_string",
            "filter_var", "filter_input", "strip_tags", "escapeshellarg",
            "escapeshellcmd", "prepared", "bindParam", "bindValue",
        ]
        sanitizers_python = [
            "escape", "sanitize", "clean", "filter", "validate",
            "int(", "float(", "bleach", "markupsafe",
        ]
        sanitizers_node = [
            "escape", "sanitize", "validator", "parseInt", "parseFloat",
            "encodeURI", "encodeURIComponent", "DOMPurify",
        ]

        if language == "python":
            sanitizers = sanitizers_python
        elif language == "node":
            sanitizers = sanitizers_node
        else:
            sanitizers = sanitizers_php

        # Check lines between source and sink for sanitization
        start = min(source_line, sink_line)
        end = max(source_line, sink_line)

        for i in range(start - 1, min(end, len(lines))):
            line = lines[i]
            if var_name in line:
                for sanitizer in sanitizers:
                    if sanitizer.lower() in line.lower():
                        return True

        return False

    def _suggest_routes(
        self, sinks: List[SinkInfo], flows: List[DataFlow]
    ) -> List[str]:
        """Suggest exploitation routes based on identified sinks and flows.

        Prioritizes routes that have exploitable data flows.
        """
        routes: Set[str] = set()

        # Routes from exploitable flows (higher confidence)
        for flow in flows:
            if flow.exploitable:
                sink_name = flow.sink.function
                if sink_name in _SINK_ROUTE_MAP:
                    routes.update(_SINK_ROUTE_MAP[sink_name])

        # Routes from sinks without confirmed flows (lower confidence, still useful)
        if not routes:
            for sink in sinks:
                if sink.function in _SINK_ROUTE_MAP:
                    routes.update(_SINK_ROUTE_MAP[sink.function])

        return sorted(routes)
