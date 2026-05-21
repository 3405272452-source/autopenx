"""Thin wrapper over the OpenAI SDK configured for DeepSeek."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from config.settings import settings


class LLMError(RuntimeError):
    pass


class LLMClient:
    """OpenAI-compatible chat completion client bound to DeepSeek V3 by default."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or settings.deepseek_api_key
        self.base_url = base_url or settings.deepseek_base_url
        self.model = model or settings.deepseek_model
        self._client = None

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        if not self.api_key:
            raise LLMError("LLM disabled: DEEPSEEK_API_KEY not configured")
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise LLMError("openai SDK not installed") from exc
        self._client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=180.0)
        return self._client

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        *,
        tool_choice: str = "auto",
        temperature: float = 0.2,
        max_tokens: int = 1200,
        thinking: bool = False,
        reasoning_effort: str = "high",
    ) -> Dict[str, Any]:
        """Return the raw assistant message dict (`content`, `tool_calls`).

        Args:
            messages: Chat messages list.
            tools: Optional tool definitions for function calling.
            tool_choice: Tool choice strategy ("auto", "none", "required").
            temperature: Sampling temperature (ignored in thinking mode).
            max_tokens: Max output tokens.
            thinking: Enable DeepSeek thinking/reasoning mode (CoT).
            reasoning_effort: Thinking effort level ("high" or "max").
        """
        client = self._ensure_client()
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
        }

        # Thinking mode configuration
        if thinking:
            kwargs["reasoning_effort"] = reasoning_effort
            kwargs["extra_body"] = {"thinking": {"type": "enabled"}}
            # temperature/top_p are ignored in thinking mode but don't cause errors
        else:
            kwargs["temperature"] = temperature

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice
        resp = client.chat.completions.create(**kwargs)
        msg = resp.choices[0].message
        tool_calls = []
        for tc in getattr(msg, "tool_calls", None) or []:
            tool_calls.append(
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
            )
        result: Dict[str, Any] = {
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": tool_calls,
            "usage": {
                "prompt_tokens": getattr(resp.usage, "prompt_tokens", 0),
                "completion_tokens": getattr(resp.usage, "completion_tokens", 0),
            }
            if getattr(resp, "usage", None)
            else {},
        }
        reasoning_content = getattr(msg, "reasoning_content", None)
        if reasoning_content:
            result["reasoning_content"] = reasoning_content
        return result
