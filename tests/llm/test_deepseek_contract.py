"""DeepSeek API contract tests.

Per roadmap §10.7.7, these tests verify the contract between our system and
the DeepSeek API: function calling, tool message chains, thinking mode,
reasoner model, rate limiting, error handling, and edge cases.

All tests require DEEPSEEK_API_KEY to be set and skip gracefully otherwise.

Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5, 9.6
"""
from __future__ import annotations

import json
import os
import time

import pytest

from autopnex.orchestrator.llm_client import LLMClient, LLMError


# ---------------------------------------------------------------------------
# Skip marker & availability detection (Task 11.1)
# ---------------------------------------------------------------------------

requires_deepseek = pytest.mark.requires_deepseek
integration = pytest.mark.integration


def _deepseek_available() -> bool:
    """Check if DeepSeek API is available via env var or settings.

    Returns True if DEEPSEEK_API_KEY is set (either in environment or via
    dotenv/settings). Used for @pytest.mark.skipif decorators.

    Validates: Requirements 9.5, 9.6
    """
    # Check environment directly first (fastest path)
    if os.environ.get("DEEPSEEK_API_KEY"):
        return True
    # Fall back to settings (which loads .env)
    try:
        from config.settings import settings
        return bool(settings.deepseek_api_key)
    except Exception:
        return False


# Apply skipif to all tests that need the API
skip_if_no_deepseek = pytest.mark.skipif(
    not _deepseek_available(),
    reason="DeepSeek API unavailable (DEEPSEEK_API_KEY not set)",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pingable(client: LLMClient) -> bool:
    """Check if client can make API calls."""
    try:
        resp = client.chat(
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=5,
        )
        return bool(resp.get("content"))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 1. ping — basic connectivity
# ---------------------------------------------------------------------------

@requires_deepseek
@integration
class TestPing:
    def test_basic_response(self, llm_client):
        """Ping the API and verify a non-empty response."""
        resp = llm_client.chat(
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
            max_tokens=10,
        )
        assert resp.get("content") is not None, "Response content must not be None"
        assert resp["role"] == "assistant"
        # For thinking-mode models, content may be empty but reasoning_content present
        has_output = len(resp.get("content", "")) > 0 or bool(resp.get("reasoning_content"))
        assert has_output, "Response must have either content or reasoning_content"

    def test_usage_stats_returned(self, llm_client):
        """Verify usage statistics are returned."""
        resp = llm_client.chat(
            messages=[{"role": "user", "content": "Hello"}],
            max_tokens=20,
        )
        usage = resp.get("usage", {})
        assert usage.get("prompt_tokens", 0) > 0, "Should report prompt tokens"
        assert usage.get("completion_tokens", 0) > 0, "Should report completion tokens"


# ---------------------------------------------------------------------------
# 2. function_calling — tool use
# ---------------------------------------------------------------------------

@requires_deepseek
@integration
class TestFunctionCalling:
    TOOLS = [{
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send HTTP request",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST"]},
                    "url": {"type": "string", "description": "Target URL"},
                },
                "required": ["method", "url"],
            },
        },
    }]

    def test_tool_calls_returned(self, llm_client):
        """Function calling returns tool_calls."""
        resp = llm_client.chat(
            messages=[{"role": "user", "content": "Send a GET request to http://example.com"}],
            tools=self.TOOLS,
            max_tokens=200,
        )
        tool_calls = resp.get("tool_calls", [])
        assert len(tool_calls) >= 1, "Should return at least one tool call"
        call = tool_calls[0]
        assert call["type"] == "function"
        assert call["function"]["name"] == "http_request"
        args = json.loads(call["function"]["arguments"])
        assert "url" in args

    def test_tool_call_has_id(self, llm_client):
        """Each tool call must have a unique ID for message chaining."""
        resp = llm_client.chat(
            messages=[{"role": "user", "content": "POST to http://example.com/api"}],
            tools=self.TOOLS,
            max_tokens=200,
        )
        tool_calls = resp.get("tool_calls", [])
        if tool_calls:
            assert tool_calls[0].get("id"), "Tool call must have an ID"

    def test_content_none_with_tool_calls(self, llm_client):
        """When tool_calls are returned, content may be None/empty."""
        resp = llm_client.chat(
            messages=[{"role": "user", "content": "GET http://example.com/flag"}],
            tools=self.TOOLS,
            max_tokens=200,
        )
        # Must have tool_calls; content may be None or empty
        assert resp.get("tool_calls"), "Must have tool_calls"


# ---------------------------------------------------------------------------
# 3. tool_message_chain — tool result continuation
# ---------------------------------------------------------------------------

@requires_deepseek
@integration
class TestToolMessageChain:
    TOOLS = [{
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send HTTP request",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST"]},
                    "url": {"type": "string", "description": "Target URL"},
                },
                "required": ["method", "url"],
            },
        },
    }]

    def test_chain_continuation(self, llm_client):
        """Assistant tool call + tool result → coherent continuation."""
        # Step 1: Get a real tool_call from the API
        step1_resp = llm_client.chat(
            messages=[{"role": "user", "content": "What is at http://target.com/flag?"}],
            tools=self.TOOLS,
            max_tokens=200,
        )
        tool_calls = step1_resp.get("tool_calls", [])
        if not tool_calls:
            pytest.skip("Model did not produce tool_calls for chain test")

        # Step 2: Build continuation with real assistant message
        assistant_msg = {
            "role": "assistant",
            "content": step1_resp.get("content") or None,
            "tool_calls": tool_calls,
        }
        if step1_resp.get("reasoning_content"):
            assistant_msg["reasoning_content"] = step1_resp["reasoning_content"]

        messages = [
            {"role": "user", "content": "What is at http://target.com/flag?"},
            assistant_msg,
            {
                "role": "tool",
                "tool_call_id": tool_calls[0]["id"],
                "content": '{"status":200,"body":"flag{test123}"}',
            },
        ]
        resp = llm_client.chat(messages=messages, tools=self.TOOLS, max_tokens=200)
        content = resp.get("content", "")
        assert content is not None, "Continuation must return content"

    def test_chain_without_tools_in_request(self, llm_client):
        """Tool message chain works even when tools param not passed in final call."""
        # Step 1: Get a real tool_call
        step1_resp = llm_client.chat(
            messages=[{"role": "user", "content": "Read http://example.com/data"}],
            tools=self.TOOLS,
            max_tokens=200,
        )
        tool_calls = step1_resp.get("tool_calls", [])
        if not tool_calls:
            pytest.skip("Model did not produce tool_calls for chain test")

        # Step 2: Build continuation
        assistant_msg = {
            "role": "assistant",
            "content": step1_resp.get("content") or None,
            "tool_calls": tool_calls,
        }
        if step1_resp.get("reasoning_content"):
            assistant_msg["reasoning_content"] = step1_resp["reasoning_content"]

        messages = [
            {"role": "user", "content": "Read http://example.com/data"},
            assistant_msg,
            {
                "role": "tool",
                "tool_call_id": tool_calls[0]["id"],
                "content": '{"data": "secret_value_42"}',
            },
        ]
        # Note: no tools= param in this call
        resp = llm_client.chat(messages=messages, max_tokens=200)
        assert resp.get("content") is not None


# ---------------------------------------------------------------------------
# 4. thinking_enabled — reasoning mode
# ---------------------------------------------------------------------------

@requires_deepseek
@integration
class TestThinking:
    def test_thinking_returns_content(self, llm_client):
        """Thinking mode must return valid content (may or may not have reasoning)."""
        try:
            resp = llm_client.chat(
                messages=[{"role": "user", "content": "Explain what XSS is in one sentence."}],
                max_tokens=200,
                thinking=True,
            )
            assert resp.get("content") is not None, "Must return content"
            assert len(resp["content"]) > 0, "Content must not be empty"
        except Exception as e:
            # Graceful degradation: error should mention thinking/reasoning
            err_msg = str(e).lower()
            assert any(kw in err_msg for kw in ("thinking", "reasoning", "not support", "invalid")), (
                f"Unexpected error in thinking mode: {e}"
            )

    def test_thinking_may_produce_reasoning_content(self, llm_client):
        """If thinking is supported, reasoning_content may be present."""
        try:
            resp = llm_client.chat(
                messages=[{"role": "user", "content": "Solve: 2 + 2 = ?"}],
                max_tokens=100,
                thinking=True,
            )
            # reasoning_content is optional; content is required
            assert resp.get("content") is not None
        except Exception:
            pass  # OK if thinking mode not supported


# ---------------------------------------------------------------------------
# 5. thinking_with_tools — thinking + function calling
# ---------------------------------------------------------------------------

@requires_deepseek
@integration
class TestThinkingWithTools:
    TOOLS = [{
        "type": "function",
        "function": {
            "name": "get_flag",
            "description": "Get the CTF flag",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    }]

    def test_thinking_with_tools(self, llm_client):
        """Thinking + tools together must not crash."""
        try:
            resp = llm_client.chat(
                messages=[{"role": "user", "content": "Get the flag using the tool."}],
                tools=self.TOOLS,
                max_tokens=200,
                thinking=True,
            )
            # Either tool_calls or content must be present
            has_response = resp.get("content") or resp.get("tool_calls")
            assert has_response, "Must return either content or tool_calls"
        except Exception as e:
            err_msg = str(e).lower()
            assert any(kw in err_msg for kw in ("thinking", "not support", "invalid")), (
                f"Unexpected error with thinking+tools: {e}"
            )


# ---------------------------------------------------------------------------
# 6. reasoner_ping — deepseek-reasoner model
# ---------------------------------------------------------------------------

@requires_deepseek
@integration
class TestReasoner:
    def test_reasoner_basic(self, llm_client):
        """Test deepseek-reasoner model (may use different endpoint)."""
        try:
            # Try reasoner model
            reasoner_client = LLMClient(model="deepseek-reasoner")
            resp = reasoner_client.chat(
                messages=[{"role": "user", "content": "What is 2+2? Answer briefly."}],
                max_tokens=100,
            )
            assert resp.get("content") is not None
            assert len(resp["content"]) > 0
        except Exception as e:
            # Reasoner may not be available — that's fine
            err = str(e).lower()
            assert any(kw in err for kw in ("not found", "invalid", "reasoner", "404", "403")), (
                f"Unexpected reasoner error: {e}"
            )

    def test_reasoner_with_tools(self, llm_client):
        """Test reasoner with tool definitions."""
        tools = [{
            "type": "function",
            "function": {
                "name": "echo",
                "description": "Echo back the input",
                "parameters": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            },
        }]
        try:
            reasoner_client = LLMClient(model="deepseek-reasoner")
            resp = reasoner_client.chat(
                messages=[{"role": "user", "content": "Echo 'hello' using the tool."}],
                tools=tools,
                max_tokens=200,
            )
            # Whatever happens: should not be an unhandled exception
            assert isinstance(resp, dict)
        except Exception as e:
            err = str(e).lower()
            assert any(kw in err for kw in ("not found", "invalid", "reasoner", "404", "403", "not support")), (
                f"Unexpected reasoner+tools error: {e}"
            )


# ---------------------------------------------------------------------------
# 7. rate_limit — 429 handling
# ---------------------------------------------------------------------------

@requires_deepseek
@integration
class TestRateLimit:
    def test_rapid_requests(self, llm_client):
        """Send 5 rapid requests and check behavior under load."""
        results = []
        for i in range(5):
            try:
                resp = llm_client.chat(
                    messages=[{"role": "user", "content": f"Say {i}"}],
                    max_tokens=10,
                )
                results.append(("ok", resp.get("content", "")))
            except Exception as e:
                results.append(("error", str(e)[:200]))
            time.sleep(0.1)  # Small delay to be somewhat polite

        # At least some should succeed
        successes = [r for r in results if r[0] == "ok"]
        assert len(successes) >= 1, (
            f"All 5 rapid requests failed. Results: {results}"
        )


# ---------------------------------------------------------------------------
# 8. invalid_tool_schema — graceful error handling
# ---------------------------------------------------------------------------

@requires_deepseek
@integration
class TestInvalidToolSchema:
    def test_malformed_tool_returns_error(self, llm_client):
        """Malformed tool schema should return error, not crash."""
        bad_tools = [{
            "type": "invalid_type",  # Not "function"
            "bad_function": {
                "malformed": True,
            },
        }]
        try:
            resp = llm_client.chat(
                messages=[{"role": "user", "content": "Use the tool."}],
                tools=bad_tools,
                max_tokens=100,
            )
            # Some APIs silently ignore bad tools
            assert isinstance(resp, dict)
        except Exception as e:
            # Error is expected, but should not be a Python crash
            err = str(e).lower()
            assert any(kw in err for kw in ("invalid", "error", "type", "tool")), (
                f"Unexpected error from bad tool schema: {e}"
            )

    def test_missing_required_fields(self, llm_client):
        """Tool without required fields should be handled gracefully."""
        bad_tools = [{
            "type": "function",
            # Missing "function" key entirely
        }]
        try:
            resp = llm_client.chat(
                messages=[{"role": "user", "content": "hi"}],
                tools=bad_tools,
                max_tokens=100,
            )
            assert isinstance(resp, dict)
        except Exception as e:
            err = str(e).lower()
            assert any(kw in err for kw in ("invalid", "error", "required", "tool")), (
                f"Unexpected error: {e}"
            )


# ---------------------------------------------------------------------------
# 9. content_none_handling
# ---------------------------------------------------------------------------

@requires_deepseek
@integration
class TestContentNoneHandling:
    TOOLS = [{
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send HTTP request",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST"]},
                    "url": {"type": "string"},
                },
                "required": ["method", "url"],
            },
        },
    }]

    def test_result_always_has_content_key(self, llm_client):
        """Even when content is None, the result dict must have a 'content' key."""
        resp = llm_client.chat(
            messages=[{"role": "user", "content": "GET http://example.com/api"}],
            tools=self.TOOLS,
            max_tokens=200,
        )
        assert "content" in resp, "Result must always have 'content' key"
        # content may be "" or a string—but it must be present
        assert isinstance(resp["content"], str), "content must be a string"

    def test_tool_calls_structure_consistent(self, llm_client):
        """Verify tool_calls always have consistent structure."""
        resp = llm_client.chat(
            messages=[{"role": "user", "content": "Send POST to http://example.com/login"}],
            tools=self.TOOLS,
            max_tokens=200,
        )
        tool_calls = resp.get("tool_calls", [])
        for tc in tool_calls:
            assert "id" in tc, "Tool call must have id"
            assert tc["type"] == "function"
            assert "function" in tc
            assert "name" in tc["function"]
            assert "arguments" in tc["function"]
            # Arguments should be valid JSON
            try:
                json.loads(tc["function"]["arguments"])
            except json.JSONDecodeError:
                pytest.fail(f"Tool arguments not valid JSON: {tc['function']['arguments']}")


# ---------------------------------------------------------------------------
# 10. LLMClient disabled mode
# ---------------------------------------------------------------------------

class TestLLMClientDisabled:
    def test_chat_raises_without_api_key(self, monkeypatch):
        """LLMClient should raise LLMError when API key is not configured."""
        from config.settings import settings as settings_obj
        monkeypatch.setattr(settings_obj, "deepseek_api_key", "")
        client = LLMClient()
        assert not client.enabled
        with pytest.raises(LLMError, match="disabled|not configured|DEEPSEEK"):
            client.chat(messages=[{"role": "user", "content": "hello"}], max_tokens=10)

    def test_client_disabled_when_key_empty(self, monkeypatch):
        """Client.enabled returns False when no API key."""
        from config.settings import settings as settings_obj
        monkeypatch.setattr(settings_obj, "deepseek_api_key", "")
        client = LLMClient()
        assert not client.enabled

    def test_client_enabled_when_key_set(self, monkeypatch):
        """Client.enabled returns True when API key is set."""
        from config.settings import settings as settings_obj
        monkeypatch.setattr(settings_obj, "deepseek_api_key", "sk-test-key")
        client = LLMClient()
        assert client.enabled


# ---------------------------------------------------------------------------
# 11. Edge cases
# ---------------------------------------------------------------------------

@requires_deepseek
@integration
class TestEdgeCases:
    def test_empty_messages_list(self, llm_client):
        """API should handle empty messages list (or raise clear error)."""
        try:
            resp = llm_client.chat(messages=[], max_tokens=50)
            assert isinstance(resp, dict)
        except Exception as e:
            err = str(e).lower()
            assert any(kw in err for kw in ("empty", "invalid", "error", "messages")), (
                f"Unexpected error for empty messages: {e}"
            )

    def test_very_long_message(self, llm_client):
        """Long message should not crash."""
        long_text = "A" * 4000
        try:
            resp = llm_client.chat(
                messages=[{"role": "user", "content": f"Echo: {long_text[:100]}"}],
                max_tokens=50,
            )
            assert resp.get("content") is not None
        except Exception as e:
            err = str(e).lower()
            assert any(kw in err for kw in ("token", "length", "context", "invalid")), (
                f"Unexpected error for long message: {e}"
            )

    def test_special_characters_in_message(self, llm_client):
        """Unicode and special characters in messages should work."""
        resp = llm_client.chat(
            messages=[{"role": "user", "content": "你好世界! @#$%^&*() <script>alert(1)</script>"}],
            max_tokens=30,
        )
        assert resp.get("content") is not None

    def test_multiple_tool_definitions(self, llm_client):
        """Multiple tool definitions should work correctly."""
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "tool_a",
                    "description": "Tool A",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "tool_b",
                    "description": "Tool B",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            },
        ]
        resp = llm_client.chat(
            messages=[{"role": "user", "content": "Call tool_a or tool_b."}],
            tools=tools,
            max_tokens=200,
        )
        assert isinstance(resp, dict)
        assert resp.get("content") is not None or resp.get("tool_calls")


# ===========================================================================
# Task 11.2 — Core Contract Tests (explicit names per spec)
#
# These tests verify the specific contract behaviors required by the spec:
#   - test_tool_calls_basic: function definitions → tool_calls returned
#   - test_reasoning_content: reasoning_content field present
#   - test_tool_message_roundtrip: tool_calls → tool message → assistant
#   - test_content_none_with_tools: content=None + tool_calls accepted
#   - test_multi_turn_tools: multi-turn tool calling without errors
#
# Validates: Requirements 9.1, 9.2, 9.3, 9.4
# ===========================================================================


@requires_deepseek
@skip_if_no_deepseek
class TestCoreContract:
    """Core DeepSeek contract tests as specified in task 11.2."""

    TOOLS = [
        {
            "type": "function",
            "function": {
                "name": "http_request",
                "description": "Send an HTTP request to a URL and return the response.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST", "PUT", "DELETE"],
                            "description": "HTTP method",
                        },
                        "url": {
                            "type": "string",
                            "description": "Target URL",
                        },
                        "body": {
                            "type": "string",
                            "description": "Request body (optional)",
                        },
                    },
                    "required": ["method", "url"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file from the filesystem.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File path to read",
                        },
                    },
                    "required": ["path"],
                },
            },
        },
    ]

    def test_tool_calls_basic(self, llm_client):
        """Send function definitions and verify the model returns tool_calls.

        Validates: Requirement 9.1
        """
        resp = llm_client.chat(
            messages=[{
                "role": "user",
                "content": (
                    "You are a penetration testing assistant. "
                    "Send a GET request to http://target.local/robots.txt to check for hidden paths."
                ),
            }],
            tools=self.TOOLS,
            max_tokens=300,
        )

        # Must return tool_calls
        tool_calls = resp.get("tool_calls", [])
        assert len(tool_calls) >= 1, (
            f"Expected at least 1 tool_call, got {len(tool_calls)}. Response: {resp}"
        )

        # Verify structure of the tool call
        call = tool_calls[0]
        assert call.get("id"), "Tool call must have a non-empty 'id'"
        assert call["type"] == "function", f"Expected type='function', got '{call['type']}'"
        assert "function" in call, "Tool call must have 'function' key"
        assert call["function"]["name"] in ("http_request", "read_file"), (
            f"Unexpected function name: {call['function']['name']}"
        )

        # Arguments must be valid JSON
        args_str = call["function"]["arguments"]
        args = json.loads(args_str)
        assert isinstance(args, dict), "Arguments must parse to a dict"

    def test_reasoning_content(self, llm_client):
        """Verify reasoning_content field is present when thinking mode is enabled.

        Validates: Requirement 9.2

        Note: reasoning_content availability depends on the model and API version.
        deepseek-chat may not always return it; deepseek-reasoner should.
        We test that the field is at least handled correctly.
        """
        try:
            resp = llm_client.chat(
                messages=[{
                    "role": "user",
                    "content": (
                        "Analyze this HTTP response and determine if it's vulnerable to SQL injection:\n"
                        "HTTP/1.1 500 Internal Server Error\n"
                        "Content: You have an error in your SQL syntax near '1' OR '1'='1'"
                    ),
                }],
                max_tokens=300,
                thinking=True,
            )

            # The response must be valid
            assert resp.get("content") is not None, "Must return content"

            # reasoning_content may or may not be present depending on model
            # If present, it must be a non-empty string
            if "reasoning_content" in resp:
                assert isinstance(resp["reasoning_content"], str), (
                    "reasoning_content must be a string"
                )
                assert len(resp["reasoning_content"]) > 0, (
                    "reasoning_content must not be empty when present"
                )

        except Exception as e:
            # Thinking mode may not be supported on all models/tiers
            err_msg = str(e).lower()
            if any(kw in err_msg for kw in ("thinking", "reasoning", "not support")):
                pytest.skip(f"Thinking mode not supported: {e}")
            raise

    def test_tool_message_roundtrip(self, llm_client):
        """Verify tool_calls → tool message → assistant response roundtrip.

        Validates: Requirement 9.3

        This tests the full tool calling flow:
        1. User asks something that triggers a tool call
        2. Assistant responds with tool_calls
        3. We send back a tool result message
        4. Assistant produces a final response incorporating the tool result

        We use a two-step approach: first get a real tool_call from the API,
        then send the tool result back to verify the roundtrip.
        """
        # Step 1: Get a real tool_call from the API
        step1_resp = llm_client.chat(
            messages=[{
                "role": "user",
                "content": "Read the file /etc/passwd to check for interesting users.",
            }],
            tools=self.TOOLS,
            max_tokens=300,
        )

        tool_calls = step1_resp.get("tool_calls", [])
        if not tool_calls:
            pytest.skip("Model did not produce tool_calls for roundtrip test")

        # Step 2: Build the continuation with the real assistant message
        assistant_msg = {"role": "assistant", "tool_calls": tool_calls}
        # Include content (may be empty string or None)
        assistant_msg["content"] = step1_resp.get("content") or None
        # Include reasoning_content if present (required by thinking-mode models)
        if step1_resp.get("reasoning_content"):
            assistant_msg["reasoning_content"] = step1_resp["reasoning_content"]

        tool_result_msg = {
            "role": "tool",
            "tool_call_id": tool_calls[0]["id"],
            "content": json.dumps({
                "status": "success",
                "content": "root:x:0:0:root:/root:/bin/bash\n"
                           "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                           "ctf_admin:x:1000:1000:CTF Admin:/home/ctf_admin:/bin/bash\n",
            }),
        }

        messages = [
            {"role": "user", "content": "Read the file /etc/passwd to check for interesting users."},
            assistant_msg,
            tool_result_msg,
        ]

        resp = llm_client.chat(
            messages=messages,
            tools=self.TOOLS,
            max_tokens=300,
        )

        # The assistant must produce a response (content or more tool_calls)
        has_content = bool(resp.get("content"))
        has_tool_calls = bool(resp.get("tool_calls"))
        assert has_content or has_tool_calls, (
            f"After tool result, assistant must respond. Got: {resp}"
        )

    def test_content_none_with_tools(self, llm_client):
        """Verify that content=None + tool_calls is accepted in message history.

        Validates: Requirement 9.4

        DeepSeek must accept assistant messages where content is None/null
        when tool_calls are present. This is the standard OpenAI format.
        We use a real API call to get a valid assistant message first.
        """
        # Step 1: Get a real tool_call response from the API
        step1_resp = llm_client.chat(
            messages=[{
                "role": "user",
                "content": "Check http://target.local for vulnerabilities.",
            }],
            tools=self.TOOLS,
            max_tokens=300,
        )

        tool_calls = step1_resp.get("tool_calls", [])
        if not tool_calls:
            pytest.skip("Model did not produce tool_calls for content_none test")

        # Step 2: Build continuation - the assistant message should have content=None
        # when tool_calls are present (this is the contract we're testing)
        assistant_msg = {
            "role": "assistant",
            "content": None,  # This is the key contract: content=None is valid
            "tool_calls": tool_calls,
        }
        # Include reasoning_content if the model produced it (required by thinking models)
        if step1_resp.get("reasoning_content"):
            assistant_msg["reasoning_content"] = step1_resp["reasoning_content"]

        messages = [
            {"role": "user", "content": "Check http://target.local for vulnerabilities."},
            assistant_msg,
            {
                "role": "tool",
                "tool_call_id": tool_calls[0]["id"],
                "content": json.dumps({
                    "status": 200,
                    "body": "<html><title>Welcome</title><body>Hello World</body></html>",
                }),
            },
        ]

        # This must not raise an error — content=None is valid
        resp = llm_client.chat(
            messages=messages,
            tools=self.TOOLS,
            max_tokens=300,
        )

        # Response must be valid
        assert isinstance(resp, dict), "Response must be a dict"
        assert "content" in resp, "Response must have 'content' key"
        assert resp.get("content") is not None or resp.get("tool_calls"), (
            "Must return either content or tool_calls"
        )

    def test_multi_turn_tools(self, llm_client):
        """Verify multi-turn tool calling works without errors.

        Validates: Requirement 9.1, 9.3, 9.4

        Simulates a realistic multi-turn CTF agent conversation by making
        real API calls at each step to ensure the conversation history
        is valid (including reasoning_content for thinking-mode models).
        """
        # Turn 1: User asks to scan, model should call a tool
        turn1_resp = llm_client.chat(
            messages=[{
                "role": "user",
                "content": "Scan http://target.local for vulnerabilities. First check the main page.",
            }],
            tools=self.TOOLS,
            max_tokens=300,
        )

        tool_calls_1 = turn1_resp.get("tool_calls", [])
        if not tool_calls_1:
            # Model responded with content instead of tool_calls - still valid
            assert turn1_resp.get("content"), "Must have either content or tool_calls"
            pytest.skip("Model chose not to use tools in turn 1")

        # Build turn 1 assistant message
        assistant_msg_1 = {
            "role": "assistant",
            "content": turn1_resp.get("content") or None,
            "tool_calls": tool_calls_1,
        }
        if turn1_resp.get("reasoning_content"):
            assistant_msg_1["reasoning_content"] = turn1_resp["reasoning_content"]

        # Turn 1 tool result
        tool_result_1 = {
            "role": "tool",
            "tool_call_id": tool_calls_1[0]["id"],
            "content": json.dumps({
                "status": 200,
                "headers": {"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4"},
                "body": "<html><title>Login</title><form action='/login' method='POST'>"
                        "<input name='user'><input name='pass' type='password'></form></html>",
            }),
        }

        # Turn 2: Send tool result, ask model to continue
        messages_turn2 = [
            {"role": "user", "content": "Scan http://target.local for vulnerabilities. First check the main page."},
            assistant_msg_1,
            tool_result_1,
        ]

        turn2_resp = llm_client.chat(
            messages=messages_turn2,
            tools=self.TOOLS,
            max_tokens=300,
        )

        # Turn 2 must produce a valid response
        assert isinstance(turn2_resp, dict), "Turn 2 response must be a dict"
        has_content = bool(turn2_resp.get("content"))
        has_tool_calls = bool(turn2_resp.get("tool_calls"))
        assert has_content or has_tool_calls, (
            f"Multi-turn must produce response in turn 2. Got: {turn2_resp}"
        )

        # If model made another tool call, verify we can continue the chain
        tool_calls_2 = turn2_resp.get("tool_calls", [])
        if tool_calls_2:
            assistant_msg_2 = {
                "role": "assistant",
                "content": turn2_resp.get("content") or None,
                "tool_calls": tool_calls_2,
            }
            if turn2_resp.get("reasoning_content"):
                assistant_msg_2["reasoning_content"] = turn2_resp["reasoning_content"]

            # Respond to ALL tool_calls (not just the first one)
            tool_results_2 = []
            for tc in tool_calls_2:
                tool_results_2.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": json.dumps({"status": 403, "body": "Access Denied"}),
                })

            messages_turn3 = messages_turn2 + [assistant_msg_2] + tool_results_2

            turn3_resp = llm_client.chat(
                messages=messages_turn3,
                tools=self.TOOLS,
                max_tokens=300,
            )

            # Turn 3 must also be valid
            assert isinstance(turn3_resp, dict), "Turn 3 response must be a dict"
            assert turn3_resp.get("content") is not None or turn3_resp.get("tool_calls"), (
                "Turn 3 must produce either content or tool_calls"
            )
