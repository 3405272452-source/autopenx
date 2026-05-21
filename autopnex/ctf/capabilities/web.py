from __future__ import annotations

from typing import Any, Dict, Optional

from .base import CTFCapability
from ..helpers.dispatcher import DeterministicHelperDispatcher
from ..preflight import run_static_preflight


class WebCTFCapability(CTFCapability):
    name = "web"

    def __init__(self, dispatcher: DeterministicHelperDispatcher) -> None:
        self._dispatcher = dispatcher

    def suggest_tools(self) -> Dict[str, Any]:
        return {
            "recommended_tools": [
                "http_request",
                "scan_flag",
                "ctf_knowledge_search",
                "ctf_tool_manager",
            ]
        }

    def run_preflight(self, agent: Any) -> None:
        run_static_preflight(agent)

    def run_helpers(
        self,
        *,
        agent: Any,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        return self._dispatcher.run(
            tool_name=tool_name,
            tool_args=tool_args,
            tool_result=tool_result,
            agent=agent,
        )
