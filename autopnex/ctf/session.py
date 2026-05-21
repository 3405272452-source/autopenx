from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CTFStepRecord:
    iteration: int
    tool: str
    args: Dict[str, Any]
    result_preview: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iteration": self.iteration,
            "tool": self.tool,
            "args": self.args,
            "result_preview": self.result_preview,
        }


@dataclass
class CTFSessionState:
    target: str
    challenge_type: Optional[str]
    flag_format: str
    files: List[str] = field(default_factory=list)
    messages: List[Dict[str, Any]] = field(default_factory=list)
    steps: List[Dict[str, Any]] = field(default_factory=list)
    reasoning_chunks: List[str] = field(default_factory=list)

    def add_message(self, role: str, content: str, **extra: Any) -> None:
        payload: Dict[str, Any] = {"role": role, "content": content}
        payload.update(extra)
        self.messages.append(payload)

    def add_step(self, iteration: int, tool: str, args: Dict[str, Any], result_preview: str) -> None:
        self.steps.append(
            CTFStepRecord(
                iteration=iteration,
                tool=tool,
                args=args,
                result_preview=result_preview,
            ).to_dict()
        )

    def add_reasoning(self, text: str) -> None:
        if text:
            self.reasoning_chunks.append(text)

    def joined_reasoning(self) -> str:
        return "\n\n".join(self.reasoning_chunks)

    def build_result(
        self,
        *,
        success: bool,
        flag: Optional[str] = None,
        duration_ms: int = 0,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "success": success,
            "flag": flag,
            "reasoning": self.joined_reasoning(),
            "steps": self.steps,
            "iterations": len(self.steps),
            "duration_ms": duration_ms,
            "error": error,
        }
