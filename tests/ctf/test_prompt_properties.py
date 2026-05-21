"""Property-based tests for PromptCompiler token budget invariant.

Property 4 (from design doc):
    For any combination of blackboard state, route, and history, the output
    of build_messages() SHALL have estimated token count <= TokenBudget.total
    (max_input_tokens).

**Validates: Requirements 6.1, 6.3**

Uses Hypothesis with at least 30 examples.
"""
from __future__ import annotations

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from autopnex.ctf.prompt_compiler import (
    PromptCompiler,
    TokenBudget,
    estimate_tokens_heuristic,
)
from autopnex.ctf.web_state_blackboard import WebStateBlackboard


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_ROUTE_NAMES = st.sampled_from([
    "recon", "source_leak", "lfi", "ssti", "sqli", "cmdi",
    "ssrf", "jwt", "upload", "idor", "xss",
    "php_pop", "graphql", "websocket",
])

_FLAG_FORMATS = st.sampled_from([
    r"flag\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"[A-Za-z0-9_]+\{[^}]+\}",
])

_CHALLENGE_TYPES = st.sampled_from([None, "web", "crypto", "pwn", "misc"])

# Generate realistic evidence entries to populate the blackboard
_EVIDENCE_ENTRY = st.tuples(
    st.sampled_from(["source_leak", "lfi", "ssti", "sqli", "cmdi", "ssrf"]),
    st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    st.sampled_from(["probe", "exploit", "recon"]),
    st.text(min_size=5, max_size=200, alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z"))),
)

# Generate history messages of varying sizes
_HISTORY_MESSAGE = st.fixed_dictionaries({
    "role": st.sampled_from(["user", "assistant", "tool"]),
    "content": st.text(
        min_size=0,
        max_size=500,
        alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")),
    ),
})

# Token budget with varying limits
_TOKEN_BUDGET = st.builds(
    TokenBudget,
    max_input_tokens=st.integers(min_value=2000, max_value=16000),
    core_prompt_budget=st.integers(min_value=200, max_value=1000),
    task_context_budget=st.integers(min_value=300, max_value=1500),
    state_summary_budget=st.integers(min_value=500, max_value=3000),
    route_card_budget=st.integers(min_value=500, max_value=2000),
    history_budget=st.integers(min_value=500, max_value=5000),
    tool_definitions_budget=st.integers(min_value=200, max_value=1000),
)


# ---------------------------------------------------------------------------
# Helper: build a populated blackboard
# ---------------------------------------------------------------------------

def _build_blackboard(evidence_entries, target_url="http://test.local:8080"):
    """Create a blackboard with evidence entries populated."""
    bb = WebStateBlackboard(target_url=target_url)

    for route, score, source, observation in evidence_entries:
        bb.add_evidence(route=route, score=score, source=source, observation=observation)

    # Add some endpoints to make state_summary richer
    bb.record_endpoint("/", method="GET", status_code=200, content_type="text/html")
    bb.record_endpoint("/login", method="POST", status_code=200, content_type="text/html")
    bb.record_endpoint("/api/users", method="GET", status_code=200, content_type="application/json")

    return bb


# ---------------------------------------------------------------------------
# Property Test: Token Budget Invariant
# ---------------------------------------------------------------------------

@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(
    route=_ROUTE_NAMES,
    flag_format=_FLAG_FORMATS,
    challenge_type=_CHALLENGE_TYPES,
    evidence_entries=st.lists(_EVIDENCE_ENTRY, min_size=0, max_size=15),
    history=st.lists(_HISTORY_MESSAGE, min_size=0, max_size=20),
    budget=_TOKEN_BUDGET,
)
def test_build_messages_never_exceeds_token_budget(
    route, flag_format, challenge_type, evidence_entries, history, budget
):
    """**Validates: Requirements 6.1, 6.3**

    Property 4: build_messages() output estimated tokens never exceed
    TokenBudget.max_input_tokens (the total budget).
    """
    # Setup
    blackboard = _build_blackboard(evidence_entries)
    compiler = PromptCompiler(budget=budget)

    # Exercise
    messages = compiler.build_messages(
        target="http://test.local:8080",
        flag_format=flag_format,
        challenge_type=challenge_type,
        blackboard=blackboard,
        route=route,
        previous_messages=history if history else None,
    )

    # Verify: estimate tokens and check against budget
    estimated_tokens = compiler.estimate_tokens(messages)

    assert estimated_tokens <= budget.max_input_tokens, (
        f"build_messages() produced {estimated_tokens} estimated tokens, "
        f"exceeding budget of {budget.max_input_tokens}. "
        f"Route={route}, evidence_count={len(evidence_entries)}, "
        f"history_count={len(history)}"
    )


@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(
    route=_ROUTE_NAMES,
    evidence_entries=st.lists(_EVIDENCE_ENTRY, min_size=0, max_size=10),
)
def test_build_messages_returns_valid_message_structure(route, evidence_entries):
    """**Validates: Requirements 6.1, 6.3**

    Additional structural invariant: build_messages() always returns a list
    of dicts with 'role' and 'content' keys, and the first message is always
    a system message.
    """
    blackboard = _build_blackboard(evidence_entries)
    compiler = PromptCompiler()

    messages = compiler.build_messages(
        target="http://test.local:8080",
        flag_format=r"flag\{[^}]+\}",
        blackboard=blackboard,
        route=route,
    )

    # --- Invariant: non-empty list ---
    assert len(messages) >= 1, "build_messages() must return at least one message"

    # --- Invariant: all messages have role and content ---
    for i, msg in enumerate(messages):
        assert "role" in msg, f"Message {i} missing 'role' key"
        assert "content" in msg, f"Message {i} missing 'content' key"
        assert msg["role"] in ("system", "user", "assistant", "tool"), (
            f"Message {i} has invalid role: {msg['role']}"
        )

    # --- Invariant: first message is system ---
    assert messages[0]["role"] == "system", (
        f"First message must be system, got: {messages[0]['role']}"
    )
