"""Thin wrapper over the OpenAI SDK configured for DeepSeek."""
from __future__ import annotations

import os
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


# ---------------------------------------------------------------------------
# MultiModelClient — manages multiple LLM providers for parallel worker diversity
# ---------------------------------------------------------------------------


class MultiModelClient:
    """Manages multiple LLM providers for parallel worker diversity.

    Discovers available providers from environment variables and rotates
    workers across them. If only one provider (DeepSeek) is configured,
    all workers use the same model — identical to current behavior.
    """

    def __init__(self) -> None:
        self.providers: List[Dict[str, str]] = self._discover_providers()

    def _discover_providers(self) -> List[Dict[str, str]]:
        """Discover available LLM providers from environment."""
        providers: List[Dict[str, str]] = []

        # DeepSeek (primary)
        if settings.deepseek_api_key:
            providers.append({
                "name": "deepseek",
                "api_key": settings.deepseek_api_key,
                "base_url": settings.deepseek_base_url,
                "model": settings.deepseek_model,
            })

        # OpenAI (optional)
        openai_key = os.environ.get("OPENAI_API_KEY", "").strip()
        if openai_key:
            providers.append({
                "name": "openai",
                "api_key": openai_key,
                "base_url": os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").strip(),
                "model": os.environ.get("OPENAI_MODEL", "gpt-4o").strip(),
            })

        # Claude via OpenAI-compatible proxy (optional)
        claude_key = os.environ.get("CLAUDE_API_KEY", "").strip()
        if claude_key:
            providers.append({
                "name": "claude",
                "api_key": claude_key,
                "base_url": os.environ.get("CLAUDE_BASE_URL", "https://api.anthropic.com/v1").strip(),
                "model": os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-20250514").strip(),
            })

        return providers

    def get_client_for_worker(self, worker_index: int) -> LLMClient:
        """Get an LLM client for a specific worker, rotating through providers.

        Args:
            worker_index: Zero-based index of the parallel worker.

        Returns:
            LLMClient configured for the provider assigned to this worker.
            Falls back to default LLMClient if no providers are discovered.
        """
        if not self.providers:
            return LLMClient()  # Fallback to default
        provider = self.providers[worker_index % len(self.providers)]
        return LLMClient(
            api_key=provider["api_key"],
            base_url=provider["base_url"],
            model=provider["model"],
        )

    @property
    def provider_count(self) -> int:
        """Number of available LLM providers."""
        return len(self.providers)

    @property
    def provider_names(self) -> List[str]:
        """Names of all available providers."""
        return [p["name"] for p in self.providers]
