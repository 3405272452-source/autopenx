"""Property-based tests for new Web helpers (round 7, task 7.5).

Properties covered:

- **Property 10: NoSQLi 载荷有效性**
  *For any* URL parameter name in the NoSQLi parameter set, the NoSQLi
  helper SHALL generate syntactically valid MongoDB injection payloads
  that can be embedded in HTTP requests.

  **Validates: Requirements 6.1**

- **Property 11: XSS 载荷上下文适配**
  *For any* HTML context type (body/attribute/script/url), the XSS helper
  SHALL generate payloads that are syntactically appropriate for that
  context and contain executable JavaScript.

  **Validates: Requirements 6.2**

- **Property 12: 策略引擎去重**
  *For any* sequence of (tool, args) pairs containing duplicates, the
  StrategyEngine SHALL reject duplicate entries and only allow each unique
  pair to execute once.

  **Validates: Requirements 6.5**

Feature: ctf-web-agent-round7
"""
from __future__ import annotations

import json
import re
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from autopnex.ctf.helpers.web import (
    NOSQLI_PARAM_NAMES,
    NOSQLI_PAYLOADS_MONGO,
    XSS_CONTEXTS,
    XSS_PAYLOADS,
    try_nosqli_flag_from_tool_result,
)
from autopnex.ctf.strategy import StrategyEngine


# ---------------------------------------------------------------------------
# Helper: stub agent that mimics the React_Agent surface area helpers consume
# ---------------------------------------------------------------------------


def _make_agent_stub(*, exploit_enabled: bool = True) -> SimpleNamespace:
    """Create a lightweight agent stub for invoking helpers in isolation.

    The real ``CTFReActAgent`` exposes ``runtime_config``, ``_session``,
    ``target``, and ``_check_flag_in_text``. We only need attribute parity
    so the helpers run end-to-end without touching the network or LLMs.
    """
    runtime_config = SimpleNamespace(
        exploit_enabled=exploit_enabled,
        http_timeout=5,
    )

    response = MagicMock()
    response.status_code = 200
    response.text = ""
    response.url = "http://target.test/"
    response.headers = {}

    session = MagicMock()
    session.get.return_value = response
    session.post.return_value = response

    return SimpleNamespace(
        runtime_config=runtime_config,
        target="http://target.test/",
        _session=session,
        _check_flag_in_text=lambda _text: None,  # never finds a flag → exhaustive sweep
    )


# ---------------------------------------------------------------------------
# Property 10: NoSQLi payload validity
# ---------------------------------------------------------------------------


# Recognised MongoDB query operators that must appear in any "valid" payload
_VALID_MONGO_OPERATORS = {
    "$gt", "$gte", "$lt", "$lte", "$ne", "$eq",
    "$in", "$nin", "$exists", "$regex", "$where",
    "$or", "$and", "$not", "$type", "$mod", "$size",
    "$all", "$elemMatch",
}


class TestProperty10NoSQLiPayloadValidity:
    """**Property 10: NoSQLi 载荷有效性** — Validates: Requirements 6.1"""

    def test_static_payloads_are_valid_json_with_mongo_operators(self):
        """Every static payload must parse as JSON and contain a Mongo operator.

        **Validates: Requirements 6.1**
        """
        assert NOSQLI_PAYLOADS_MONGO, "payload list must not be empty"
        for payload in NOSQLI_PAYLOADS_MONGO:
            parsed = json.loads(payload)
            assert isinstance(parsed, dict), f"payload {payload!r} is not a JSON object"
            assert any(k in _VALID_MONGO_OPERATORS for k in parsed.keys()), (
                f"payload {payload!r} contains no recognised MongoDB operator"
            )

    @given(param_name=st.sampled_from(sorted(NOSQLI_PARAM_NAMES)))
    @settings(
        max_examples=15,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_helper_emits_mongo_operator_for_any_param(self, param_name: str):
        """For every parameter name in the NoSQLi set, the helper issues at
        least one HTTP request whose construction encodes a syntactically
        valid MongoDB injection (key ``param[$op]`` for GET, or a JSON body
        with a ``$op`` value for POST).

        **Validates: Requirements 6.1**
        """
        agent = _make_agent_stub()
        url = f"http://target.test/login?{param_name}=alice"
        try_nosqli_flag_from_tool_result(
            agent=agent,
            tool_name="http_request",
            tool_args={"url": url},
            tool_result={"url": url, "body": ""},
        )

        get_calls = list(agent._session.get.call_args_list)
        post_calls = list(agent._session.post.call_args_list)

        assert get_calls or post_calls, (
            f"helper issued no HTTP requests for param {param_name!r}"
        )

        # GET strategy: at least one call must have a Mongo operator in the
        # form ``<param>[$op]`` injected as a parameter key.
        get_has_mongo_key = False
        operator_pattern = re.compile(r"\[\$[a-zA-Z]+\]")
        for call in get_calls:
            params = call.kwargs.get("params") or {}
            if not isinstance(params, dict):
                continue
            joined_keys = " ".join(str(k) for k in params.keys())
            if operator_pattern.search(joined_keys):
                get_has_mongo_key = True
                break

        # POST strategy: at least one call must include a JSON body whose
        # value is a sub-document with a Mongo operator key.
        post_has_mongo_value = False
        for call in post_calls:
            json_body = call.kwargs.get("json")
            if not isinstance(json_body, dict):
                continue
            for value in json_body.values():
                if isinstance(value, dict) and any(
                    k in _VALID_MONGO_OPERATORS for k in value.keys()
                ):
                    post_has_mongo_value = True
                    break
            if post_has_mongo_value:
                break

        assert get_has_mongo_key or post_has_mongo_value, (
            "helper did not generate a syntactically valid MongoDB injection "
            f"for param {param_name!r}; "
            f"get_calls={len(get_calls)}, post_calls={len(post_calls)}"
        )

    def test_helper_skips_non_nosqli_param(self):
        """Sanity: a URL with no NoSQLi-related parameters and no NoSQL
        body hint must NOT trigger any HTTP requests.
        """
        agent = _make_agent_stub()
        url = "http://target.test/page?id=42"  # 'id' is not in NOSQLI_PARAM_NAMES
        result = try_nosqli_flag_from_tool_result(
            agent=agent,
            tool_name="http_request",
            tool_args={"url": url},
            tool_result={"url": url, "body": "<html>plain html</html>"},
        )
        assert result is None
        agent._session.get.assert_not_called()
        agent._session.post.assert_not_called()


# ---------------------------------------------------------------------------
# Property 11: XSS context-appropriate payloads
# ---------------------------------------------------------------------------


def _is_html_body_payload(payload: str) -> bool:
    """body context: payload must contain a tag (`<...>`)."""
    return "<" in payload and ">" in payload


def _is_attribute_payload(payload: str) -> bool:
    """attribute context: payload must (a) break out of a quoted attribute
    via `"` or `'`, and (b) introduce an event handler (``on*=``)."""
    has_quote_break = ('"' in payload) or ("'" in payload)
    has_handler = re.search(r"\bon[a-z]+\s*=", payload, re.IGNORECASE) is not None
    return has_quote_break and has_handler


def _is_script_payload(payload: str) -> bool:
    """script context: payload must either close the JS string literal
    (``;`` after a quote / before ``//``) or close the ``<script>`` tag."""
    return ";" in payload or "</script>" in payload.lower()


def _is_url_payload(payload: str) -> bool:
    """url context: payload must use a JS-executing URL scheme."""
    lowered = payload.lower().lstrip()
    return lowered.startswith("javascript:") or lowered.startswith("data:")


_CONTEXT_PREDICATES = {
    "html_body": _is_html_body_payload,
    "attribute": _is_attribute_payload,
    "script": _is_script_payload,
    "url": _is_url_payload,
}


def _contains_executable_js(payload: str) -> bool:
    """A payload contains executable JavaScript if it includes at least one
    common JS execution sink (``alert(``, an event handler, a ``<script>``
    tag, or a ``javascript:`` scheme)."""
    lowered = payload.lower()
    markers = (
        "alert(", "prompt(", "confirm(",
        "onerror", "onload", "onfocus", "onmouseover",
        "<script", "javascript:",
    )
    return any(m in lowered for m in markers)


class TestProperty11XSSContextAdaptation:
    """**Property 11: XSS 载荷上下文适配** — Validates: Requirements 6.2"""

    def test_xss_contexts_have_payload_buckets(self):
        """Each advertised context maps to a non-empty payload bucket.

        **Validates: Requirements 6.2**
        """
        assert XSS_CONTEXTS, "XSS_CONTEXTS must not be empty"
        for ctx in XSS_CONTEXTS:
            assert ctx in XSS_PAYLOADS, f"context {ctx!r} missing from XSS_PAYLOADS"
            assert XSS_PAYLOADS[ctx], f"context {ctx!r} has empty payload list"
            assert ctx in _CONTEXT_PREDICATES, (
                f"context {ctx!r} has no structural predicate registered in this test "
                "— if a new context was added, extend _CONTEXT_PREDICATES."
            )

    @given(context=st.sampled_from(XSS_CONTEXTS))
    @settings(
        max_examples=25,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_every_payload_is_context_appropriate_and_executable(self, context: str):
        """For any HTML context, every bucket payload (a) satisfies the
        context's structural predicate and (b) contains at least one common
        JavaScript execution sink.

        **Validates: Requirements 6.2**
        """
        predicate = _CONTEXT_PREDICATES[context]
        for payload in XSS_PAYLOADS[context]:
            assert predicate(payload), (
                f"payload {payload!r} does not satisfy structural predicate "
                f"for context {context!r}"
            )
            assert _contains_executable_js(payload), (
                f"payload {payload!r} for context {context!r} contains no "
                "recognised JavaScript execution sink"
            )

    @given(context=st.sampled_from(XSS_CONTEXTS))
    @settings(max_examples=15, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_payloads_are_unique_within_context(self, context: str):
        """Within a single context, payloads must be unique — duplicates
        provide no additional coverage and signal authoring mistakes.
        """
        bucket = XSS_PAYLOADS[context]
        assert len(bucket) == len(set(bucket)), (
            f"duplicate payloads in XSS_PAYLOADS[{context!r}]: {bucket}"
        )


# ---------------------------------------------------------------------------
# Property 12: StrategyEngine deduplication
# ---------------------------------------------------------------------------


# Generators ---------------------------------------------------------------

# Args values are restricted to simple JSON-friendly types so hashing via
# json.dumps(..., sort_keys=True, default=str) is deterministic.
_arg_value = st.one_of(
    st.text(min_size=0, max_size=10),
    st.integers(min_value=-1000, max_value=1000),
    st.booleans(),
    st.none(),
)
_args_dict = st.dictionaries(
    keys=st.text(min_size=1, max_size=8),
    values=_arg_value,
    min_size=0,
    max_size=4,
)
_tool_name = st.sampled_from([
    "http_request", "scan_flag", "decode_data", "file_analyze",
    "run_python", "ctf_knowledge_search", "run_tool_script",
])
_tool_call: st.SearchStrategy[Tuple[str, Dict[str, Any]]] = st.tuples(_tool_name, _args_dict)


def _call_hash(call: Tuple[str, Dict[str, Any]]) -> str:
    """Stable hash key used by Hypothesis ``unique_by`` to enforce that a
    sampled list contains pairwise-distinct (tool, args) calls."""
    tool, args = call
    return StrategyEngine._hash_args(tool, args)


def _duplicated_calls(
    base_calls: List[Tuple[str, Dict[str, Any]]],
    duplicate_indices: List[int],
) -> List[Tuple[str, Dict[str, Any]]]:
    """Construct a sequence guaranteed to contain duplicates by re-emitting
    selected items from ``base_calls`` at the end."""
    if not base_calls:
        return base_calls
    extras = [base_calls[i % len(base_calls)] for i in duplicate_indices]
    return list(base_calls) + extras


class TestProperty12StrategyEngineDedup:
    """**Property 12: 策略引擎去重** — Validates: Requirements 6.5"""

    def test_same_pair_blocked_after_record(self):
        """Recording a (tool, args) pair flips ``should_attempt`` to False."""
        engine = StrategyEngine()
        tool, args = "http_request", {"url": "http://t/?id=1"}

        assert engine.should_attempt(tool, args) is True, (
            "fresh engine must allow any unseen (tool, args) pair"
        )
        engine.record_tool_result(tool, args, {"status_code": 200, "body": ""})
        assert engine.should_attempt(tool, args) is False, (
            "engine must reject the same (tool, args) pair after recording"
        )

    def test_different_args_remain_independent(self):
        """Recording one pair does not affect the attemptability of others."""
        engine = StrategyEngine()
        engine.record_tool_result("http_request", {"url": "http://t/?id=1"}, {})
        assert engine.should_attempt("http_request", {"url": "http://t/?id=2"}) is True
        assert engine.should_attempt("scan_flag", {"text": "abc"}) is True

    @given(
        base_calls=st.lists(_tool_call, min_size=1, max_size=15),
        duplicate_indices=st.lists(st.integers(min_value=0, max_value=20), min_size=1, max_size=10),
    )
    @settings(
        max_examples=25,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_dedup_invariant_across_duplicated_sequences(
        self,
        base_calls: List[Tuple[str, Dict[str, Any]]],
        duplicate_indices: List[int],
    ):
        """For any sequence of (tool, args) pairs *with duplicates* injected,
        after recording the entire sequence the StrategyEngine's dedup set
        equals the set of distinct pairs, and every pair from the input is
        rejected by ``should_attempt``.

        **Validates: Requirements 6.5**
        """
        calls = _duplicated_calls(base_calls, duplicate_indices)

        # Independently compute the ground-truth set of unique hashes
        expected_hashes = {
            StrategyEngine._hash_args(tool, args) for tool, args in calls
        }

        engine = StrategyEngine()
        for tool, args in calls:
            engine.record_tool_result(tool, args, {"status_code": 200})

        # The dedup tracker matches the ground-truth unique set exactly
        assert engine._attempted_hashes == expected_hashes

        # Every input pair (including the duplicates) is now blocked
        for tool, args in calls:
            assert engine.should_attempt(tool, args) is False, (
                f"engine should reject already-recorded ({tool!r}, {args!r})"
            )

    @given(calls=st.lists(_tool_call, min_size=1, max_size=15))
    @settings(
        max_examples=15,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_replaying_the_same_sequence_is_idempotent(
        self,
        calls: List[Tuple[str, Dict[str, Any]]],
    ):
        """Replaying the exact same (tool, args) sequence does not grow the
        dedup tracker — i.e. duplicates are *rejected*, not re-counted.

        **Validates: Requirements 6.5**
        """
        engine = StrategyEngine()
        for tool, args in calls:
            engine.record_tool_result(tool, args, {})
        snapshot = set(engine._attempted_hashes)

        # Record the same list again — set must not grow
        for tool, args in calls:
            engine.record_tool_result(tool, args, {})

        assert engine._attempted_hashes == snapshot, (
            "recording an already-seen sequence must be idempotent w.r.t. dedup tracker"
        )

    @given(calls=st.lists(_tool_call, min_size=2, max_size=10, unique_by=_call_hash))
    @settings(
        max_examples=15,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_unique_pairs_all_recorded_once(
        self,
        calls: List[Tuple[str, Dict[str, Any]]],
    ):
        """For a sequence of pairwise-distinct (tool, args), every pair is
        admitted exactly once and the dedup set has exactly len(calls)
        members afterwards.

        **Validates: Requirements 6.5**
        """
        engine = StrategyEngine()
        for tool, args in calls:
            assert engine.should_attempt(tool, args) is True
            engine.record_tool_result(tool, args, {})

        assert len(engine._attempted_hashes) == len(calls)
