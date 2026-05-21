from __future__ import annotations

from abc import ABC
from typing import Any, Dict, Optional


class CTFCapability(ABC):
    name: str = "generic"

    def applies_to(self, challenge_type: Optional[str]) -> bool:
        return challenge_type == self.name or (challenge_type is None and self.name == "generic")

    def suggest_tools(self) -> Dict[str, Any]:
        return {"recommended_tools": []}

    def run_preflight(self, agent: Any) -> None:
        return None

    def run_helpers(
        self,
        *,
        agent: Any,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        return None
