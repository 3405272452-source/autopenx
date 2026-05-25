"""Intelligent tool output summarizer for Phase 2 Workers.

This module provides smart summarization of tool execution results,
replacing the crude `json.dumps(result)[:8000]` truncation with
context-aware summarization that preserves critical information
(flags, flag-adjacent context, key findings) while trimming noise
(large HTML bodies, repeated content, CSS/JS blocks).

CRITICAL INVARIANT: Flag candidates, flag-adjacent context, and
FLAG_FOUND markers are NEVER truncated or lost during summarization.
"""

from __future__ import annotations

import re
from typing import List


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Regex patterns for common CTF flag formats
FLAG_PATTERNS: List[str] = [
    r"flag\{[^}]*\}",
    r"FLAG\{[^}]*\}",
    r"ctf\{[^}]*\}",
    r"CTF\{[^}]*\}",
    r"hctf\{[^}]*\}",
    r"sctf\{[^}]*\}",
    r"hitcon\{[^}]*\}",
    r"bctf\{[^}]*\}",
    r"[a-zA-Z]+\{[a-zA-Z0-9_\-!@#$%^&*()+=,./?]+\}",
    r"FLAG_FOUND",
]

# Compiled flag patterns for performance
_COMPILED_FLAG_PATTERNS = [re.compile(p, re.IGNORECASE) for p in FLAG_PATTERNS]

# HTTP headers that should always be preserved in summaries
PRIORITY_HEADERS = {
    "content-type",
    "set-cookie",
    "location",
    "server",
    "x-powered-by",
    "www-authenticate",
    "content-disposition",
    "x-flag",
    "flag",
}

# Patterns for content that can be safely trimmed
_CSS_BLOCK_RE = re.compile(r"<style[^>]*>.*?</style>", re.DOTALL | re.IGNORECASE)
_JS_BLOCK_RE = re.compile(r"<script[^>]*>.*?</script>", re.DOTALL | re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

# Patterns for extracting useful HTML elements
_FORM_RE = re.compile(r"<form[^>]*>.*?</form>", re.DOTALL | re.IGNORECASE)
_LINK_RE = re.compile(r'<a\s+[^>]*href=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
_INPUT_RE = re.compile(r"<input[^>]*>", re.IGNORECASE)
_ENDPOINT_RE = re.compile(
    r'(?:href|src|action|url)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def summarize_tool_result(
    tool_name: str, raw_output: str, max_chars: int = 2000
) -> str:
    """Summarize a tool's raw output to fit within max_chars.

    Dispatches to specialized summarizers based on tool_name. Always
    preserves flag candidates and FLAG_FOUND markers regardless of
    max_chars constraint.

    Args:
        tool_name: Name of the tool that produced the output
                   (e.g., "http_request", "run_python", "python_execute").
        raw_output: The raw output string from tool execution.
        max_chars: Maximum character limit for the summary (default 2000).

    Returns:
        A summarized version of the output that fits within max_chars,
        with all flag-related content preserved intact.
    """
    if not raw_output:
        return ""

    # If output already fits, return as-is
    if len(raw_output) <= max_chars:
        return raw_output

    # Extract flag context first — these MUST be preserved
    flag_contexts = _extract_flag_context(raw_output)

    # Dispatch to specialized summarizer based on tool name
    tool_lower = tool_name.lower()
    if tool_lower in ("http_request", "recon_scan", "curl"):
        summary = _summarize_http_response(raw_output, max_chars)
    elif tool_lower in ("run_python", "python_execute", "python"):
        summary = _summarize_python_result(raw_output, max_chars)
    else:
        # Generic summarization for unknown tools
        summary = _summarize_generic(raw_output, max_chars)

    # CRITICAL: Ensure all flag contexts are present in the final summary
    summary = _ensure_flags_preserved(summary, flag_contexts, max_chars)

    return summary


# ---------------------------------------------------------------------------
# Specialized Summarizers
# ---------------------------------------------------------------------------


def _summarize_http_response(raw_output: str, max_chars: int) -> str:
    """Summarize HTTP response output.

    Preserves:
        - Status code and status line
        - Priority headers (Content-Type, Set-Cookie, Location, etc.)
        - Body key fragments (forms, links, endpoints)
        - Flag matches and FLAG_FOUND markers

    Truncates:
        - Large HTML bodies
        - CSS/JS blocks
        - HTML comments
        - Repeated content
    """
    parts: List[str] = []
    remaining = raw_output

    # Try to separate headers from body (common HTTP response format)
    header_section = ""
    body_section = remaining

    # Check for HTTP status line pattern
    status_match = re.match(
        r"(HTTP/[\d.]+\s+\d+[^\n]*)", remaining, re.IGNORECASE
    )
    if status_match:
        parts.append(status_match.group(1))

    # Look for header/body separator (\r\n\r\n or \n\n)
    separator_match = re.search(r"\r?\n\r?\n", remaining)
    if separator_match:
        header_section = remaining[: separator_match.start()]
        body_section = remaining[separator_match.end() :]
    else:
        # Try JSON format: look for "status_code", "headers", "body" keys
        status_code_match = re.search(
            r'"status_code"\s*:\s*(\d+)', remaining
        )
        if status_code_match:
            parts.append(f"[Status: {status_code_match.group(1)}]")

    # Extract priority headers
    if header_section:
        for line in header_section.split("\n"):
            line_stripped = line.strip()
            if ":" in line_stripped:
                header_name = line_stripped.split(":")[0].strip().lower()
                if header_name in PRIORITY_HEADERS:
                    parts.append(line_stripped)

    # Also extract headers from JSON format
    headers_match = re.search(
        r'"headers"\s*:\s*\{([^}]*)\}', remaining, re.DOTALL
    )
    if headers_match:
        headers_text = headers_match.group(1)
        for header_name in PRIORITY_HEADERS:
            header_pattern = re.compile(
                rf'"{re.escape(header_name)}"\s*:\s*"([^"]*)"',
                re.IGNORECASE,
            )
            match = header_pattern.search(headers_text)
            if match:
                parts.append(f"{header_name}: {match.group(1)}")

    # Process body: remove noise, keep useful content
    clean_body = body_section

    # Remove CSS and JS blocks
    clean_body = _CSS_BLOCK_RE.sub("[CSS removed]", clean_body)
    clean_body = _JS_BLOCK_RE.sub("[JS removed]", clean_body)
    clean_body = _COMMENT_RE.sub("", clean_body)

    # Extract forms (important for CTF)
    forms = _FORM_RE.findall(clean_body)
    if forms:
        # Keep forms but truncate each to reasonable size
        for form in forms[:3]:
            form_summary = form[:300]
            if len(form) > 300:
                form_summary += "..."
            parts.append(f"[Form]: {form_summary}")

    # Extract links and endpoints
    links = _LINK_RE.findall(clean_body)
    if links:
        unique_links = list(dict.fromkeys(links))[:15]
        parts.append(f"[Links]: {', '.join(unique_links)}")

    endpoints = _ENDPOINT_RE.findall(clean_body)
    if endpoints:
        unique_endpoints = list(dict.fromkeys(endpoints))[:15]
        # Filter out common static resources
        useful_endpoints = [
            ep
            for ep in unique_endpoints
            if not re.match(
                r".*\.(css|js|png|jpg|gif|ico|svg|woff|ttf)$",
                ep,
                re.IGNORECASE,
            )
        ]
        if useful_endpoints:
            parts.append(f"[Endpoints]: {', '.join(useful_endpoints)}")

    # Extract input fields
    inputs = _INPUT_RE.findall(clean_body)
    if inputs:
        parts.append(f"[Inputs]: {' | '.join(inputs[:10])}")

    # Calculate remaining budget for body text
    current_size = sum(len(p) for p in parts) + len(parts) * 2  # newline separators
    body_budget = max_chars - current_size - 100  # reserve 100 chars for safety

    if body_budget > 0 and clean_body:
        # Strip HTML tags for readable body excerpt
        text_body = re.sub(r"<[^>]+>", " ", clean_body)
        text_body = re.sub(r"\s+", " ", text_body).strip()

        if text_body and len(text_body) > body_budget:
            # Keep beginning and end (flags often at end)
            head_size = body_budget * 2 // 3
            tail_size = body_budget - head_size - 30
            if tail_size > 0:
                text_body = (
                    text_body[:head_size]
                    + "\n...[truncated]...\n"
                    + text_body[-tail_size:]
                )
            else:
                text_body = text_body[:body_budget]
        if text_body:
            parts.append(f"[Body excerpt]: {text_body}")

    result = "\n".join(parts)

    # Final size check
    if len(result) > max_chars:
        result = result[:max_chars - 20] + "\n...[truncated]"

    return result


def _summarize_python_result(raw_output: str, max_chars: int) -> str:
    """Summarize Python execution result output.

    Preserves:
        - stdout key fragments
        - stderr content
        - Exception/traceback info
        - Flag matches

    Truncates:
        - Large data dumps
        - Repeated output lines
    """
    parts: List[str] = []

    # Try to parse structured output (stdout/stderr/exception)
    stdout_match = re.search(
        r'"stdout"\s*:\s*"((?:[^"\\]|\\.)*)"', raw_output, re.DOTALL
    )
    stderr_match = re.search(
        r'"stderr"\s*:\s*"((?:[^"\\]|\\.)*)"', raw_output, re.DOTALL
    )
    exception_match = re.search(
        r'"(?:exception|error|traceback)"\s*:\s*"((?:[^"\\]|\\.)*)"',
        raw_output,
        re.DOTALL | re.IGNORECASE,
    )
    returncode_match = re.search(
        r'"(?:returncode|return_code|exit_code)"\s*:\s*(-?\d+)', raw_output
    )

    is_structured = stdout_match or stderr_match or exception_match

    if is_structured:
        if returncode_match:
            parts.append(f"[Exit code: {returncode_match.group(1)}]")

        if exception_match:
            exc_text = _unescape_json_str(exception_match.group(1))
            # Always preserve full exception info
            parts.append(f"[Exception]: {exc_text[:500]}")

        if stderr_match:
            stderr_text = _unescape_json_str(stderr_match.group(1))
            if stderr_text.strip():
                parts.append(f"[Stderr]: {stderr_text[:500]}")

        if stdout_match:
            stdout_text = _unescape_json_str(stdout_match.group(1))
            stdout_text = _deduplicate_lines(stdout_text)

            # Calculate remaining budget for stdout
            current_size = sum(len(p) for p in parts) + len(parts) * 2
            stdout_budget = max_chars - current_size - 50

            if stdout_budget > 0:
                if len(stdout_text) > stdout_budget:
                    # Keep beginning and end
                    head_size = stdout_budget * 2 // 3
                    tail_size = stdout_budget - head_size - 30
                    if tail_size > 0:
                        stdout_text = (
                            stdout_text[:head_size]
                            + "\n...[truncated]...\n"
                            + stdout_text[-tail_size:]
                        )
                    else:
                        stdout_text = stdout_text[:stdout_budget]
                parts.append(f"[Stdout]: {stdout_text}")
    else:
        # Unstructured output — treat as raw text
        text = _deduplicate_lines(raw_output)

        # Look for error/exception patterns
        error_lines: List[str] = []
        other_lines: List[str] = []
        for line in text.split("\n"):
            if re.search(
                r"(error|exception|traceback|failed|errno)",
                line,
                re.IGNORECASE,
            ):
                error_lines.append(line)
            else:
                other_lines.append(line)

        if error_lines:
            parts.append(
                f"[Errors]: {chr(10).join(error_lines[:10])}"
            )

        # Budget for remaining output
        current_size = sum(len(p) for p in parts) + len(parts) * 2
        remaining_budget = max_chars - current_size - 50

        if remaining_budget > 0:
            other_text = "\n".join(other_lines)
            if len(other_text) > remaining_budget:
                head_size = remaining_budget * 2 // 3
                tail_size = remaining_budget - head_size - 30
                if tail_size > 0:
                    other_text = (
                        other_text[:head_size]
                        + "\n...[truncated]...\n"
                        + other_text[-tail_size:]
                    )
                else:
                    other_text = other_text[:remaining_budget]
            if other_text.strip():
                parts.append(other_text)

    result = "\n".join(parts)

    if len(result) > max_chars:
        result = result[:max_chars - 20] + "\n...[truncated]"

    return result


def _summarize_generic(raw_output: str, max_chars: int) -> str:
    """Generic summarization for unknown tool types.

    Keeps beginning and end of output, deduplicates repeated lines.
    """
    text = _deduplicate_lines(raw_output)

    if len(text) <= max_chars:
        return text

    # Keep beginning and end
    head_size = max_chars * 2 // 3
    tail_size = max_chars - head_size - 30
    if tail_size > 0:
        return (
            text[:head_size]
            + "\n...[truncated]...\n"
            + text[-tail_size:]
        )
    return text[:max_chars - 20] + "\n...[truncated]"


# ---------------------------------------------------------------------------
# Flag Context Extraction
# ---------------------------------------------------------------------------


def _extract_flag_context(text: str) -> List[str]:
    """Find all flag-like patterns and return them with surrounding context.

    Searches for common CTF flag formats and returns each match plus
    50 characters of context before and after.

    Args:
        text: The text to search for flag patterns.

    Returns:
        List of strings, each containing a flag match with surrounding
        context (50 chars before and after the match).
    """
    contexts: List[str] = []
    seen_flags: set = set()

    for pattern in _COMPILED_FLAG_PATTERNS:
        for match in pattern.finditer(text):
            flag_value = match.group(0)
            # Deduplicate
            if flag_value in seen_flags:
                continue
            seen_flags.add(flag_value)

            # Extract surrounding context
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end]
            contexts.append(context)

    return contexts


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------


def _ensure_flags_preserved(
    summary: str, flag_contexts: List[str], max_chars: int
) -> str:
    """Ensure all flag contexts are present in the summary.

    If any flag context is missing from the summary, append it.
    This is the CRITICAL safety net that guarantees flags are never lost.

    The max_chars limit is EXCEEDED if necessary to preserve flags —
    flag preservation takes absolute priority over size constraints.
    """
    if not flag_contexts:
        return summary

    missing_contexts: List[str] = []
    for ctx in flag_contexts:
        # Check if the core flag value is present in summary
        # Extract the flag value from context for checking
        flag_present = False
        for pattern in _COMPILED_FLAG_PATTERNS:
            for match in pattern.finditer(ctx):
                if match.group(0) in summary:
                    flag_present = True
                    break
            if flag_present:
                break

        if not flag_present:
            missing_contexts.append(ctx)

    if missing_contexts:
        # Append missing flag contexts — NEVER truncate these
        flag_section = "\n[FLAG CANDIDATES PRESERVED]:\n" + "\n---\n".join(
            missing_contexts
        )
        summary = summary + flag_section

    return summary


def _deduplicate_lines(text: str, max_repeats: int = 3) -> str:
    """Remove consecutive duplicate lines, keeping at most max_repeats.

    Useful for trimming repeated output from loops or data dumps.
    """
    lines = text.split("\n")
    if len(lines) <= 1:
        return text

    result_lines: List[str] = []
    prev_line = None
    repeat_count = 0

    for line in lines:
        if line == prev_line:
            repeat_count += 1
            if repeat_count <= max_repeats:
                result_lines.append(line)
            elif repeat_count == max_repeats + 1:
                result_lines.append(f"  ... [{repeat_count}+ repeated lines omitted]")
        else:
            prev_line = line
            repeat_count = 0
            result_lines.append(line)

    return "\n".join(result_lines)


def _unescape_json_str(s: str) -> str:
    """Unescape common JSON string escape sequences."""
    return (
        s.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\r", "\r")
        .replace('\\"', '"')
        .replace("\\\\", "\\")
    )
