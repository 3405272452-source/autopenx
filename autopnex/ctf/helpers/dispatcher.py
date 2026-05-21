from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .web import (
    try_cmdi_flag_from_tool_result,
    try_direnum_from_tool_result,
    try_idor_flag_from_tool_result,
    try_jwt_forge_flag_from_tool_result,
    try_known_php_pop_from_tool_result,
    try_lfi_flag_from_tool_result,
    try_nosqli_flag_from_tool_result,
    try_source_leak_chain_from_tool_result,
    try_sqli_flag_from_tool_result,
    try_ssrf_flag_from_tool_result,
    try_ssti_flag_from_tool_result,
    try_upload_flag_from_tool_result,
    try_xss_flag_from_tool_result,
    try_xxe_flag_from_tool_result,
)


class DeterministicHelperDispatcher:
    def __init__(self, helpers: Optional[List[Callable[..., Optional[Dict[str, Any]]]]] = None) -> None:
        self._helpers = helpers or [
            try_known_php_pop_from_tool_result,
            try_source_leak_chain_from_tool_result,
            try_ssti_flag_from_tool_result,
            try_lfi_flag_from_tool_result,
            try_sqli_flag_from_tool_result,
            try_cmdi_flag_from_tool_result,
            try_ssrf_flag_from_tool_result,
            try_idor_flag_from_tool_result,
            try_jwt_forge_flag_from_tool_result,
            try_upload_flag_from_tool_result,
            try_xxe_flag_from_tool_result,
            try_nosqli_flag_from_tool_result,
            try_xss_flag_from_tool_result,
            try_direnum_from_tool_result,
        ]

    def run(
        self,
        *,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_result: Dict[str, Any],
        agent: Any,
    ) -> Optional[Dict[str, Any]]:
        for helper in self._helpers:
            result = helper(
                agent=agent,
                tool_name=tool_name,
                tool_args=tool_args,
                tool_result=tool_result,
            )
            if result:
                return result
        return None
