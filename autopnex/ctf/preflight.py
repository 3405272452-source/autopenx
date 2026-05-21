"""CTF preflight static analysis injection.

Runs deterministic source-derived findings before LLM exploration.
"""
from __future__ import annotations

import json
import logging
from typing import Any

log = logging.getLogger("autopnex.ctf.preflight")


def run_static_preflight(agent: Any) -> None:
    """Inject deterministic source-derived findings before LLM exploration."""
    if "phar_pdo_chain" not in agent.enabled_tools or not _has_phar_pdo_chain_hint(agent):
        return

    args = {"flag_path": "/flag", "generate_payload": False}
    agent._emit("ctf_tool_start", iteration=0, tool="phar_pdo_chain", arguments=args)
    result = agent._execute_tool("phar_pdo_chain", args)
    agent._emit(
        "ctf_tool_finish",
        iteration=0,
        tool="phar_pdo_chain",
        arguments=args,
        result_preview=str(result)[:2000],
    )
    agent._state.add_step(0, "phar_pdo_chain", args, str(result)[:500])
    agent._messages.append(
        {
            "role": "user",
            "content": (
                "Deterministic source preflight detected a likely strange_php Phar+PDO chain. "
                "Tool result follows; use it as the primary attack path and do not spend turns rediscovering it:\n"
                + json.dumps(result, ensure_ascii=False, default=str)[:6000]
            ),
        }
    )

    if "ctf_mysql_helper" in agent.enabled_tools:
        helper_args = {"scenario": "strange_php", "flag_path": "/flag"}
        agent._emit("ctf_tool_start", iteration=0, tool="ctf_mysql_helper", arguments=helper_args)
        helper_result = agent._execute_tool("ctf_mysql_helper", helper_args)
        agent._emit(
            "ctf_tool_finish",
            iteration=0,
            tool="ctf_mysql_helper",
            arguments=helper_args,
            result_preview=str(helper_result)[:2000],
        )
        agent._state.add_step(0, "ctf_mysql_helper", helper_args, str(helper_result)[:500])
        agent._messages.append(
            {
                "role": "user",
                "content": (
                    "Because the Phar chain requires external MySQL, a deterministic helper plan was generated as well. "
                    "Treat this as the next concrete action after login/session establishment and do not waste turns rediscovering public-MySQL setup details:\n"
                    + json.dumps(helper_result, ensure_ascii=False, default=str)[:6000]
                ),
            }
        )

    if "ctf_tunnel_helper" in agent.enabled_tools:
        tunnel_args = {"local_port": 3306, "service": "mysql", "preferred_method": "auto"}
        agent._emit("ctf_tool_start", iteration=0, tool="ctf_tunnel_helper", arguments=tunnel_args)
        tunnel_result = agent._execute_tool("ctf_tunnel_helper", tunnel_args)
        agent._emit(
            "ctf_tool_finish",
            iteration=0,
            tool="ctf_tunnel_helper",
            arguments=tunnel_args,
            result_preview=str(tunnel_result)[:2000],
        )
        agent._state.add_step(0, "ctf_tunnel_helper", tunnel_args, str(tunnel_result)[:500])
        agent._messages.append(
            {
                "role": "user",
                "content": (
                    "Because local Docker may be unavailable, a deterministic non-Docker tunnel plan was generated too. "
                    "Use this if the MySQL helper service must be exposed from the local host or a VPS without Docker:\n"
                    + json.dumps(tunnel_result, ensure_ascii=False, default=str)[:6000]
                ),
            }
        )


def _has_phar_pdo_chain_hint(agent: Any) -> bool:
    kinds = {
        finding.kind
        for analysis in agent._source_analyses
        for finding in analysis.findings
    }
    return bool({"phar_trigger_candidate", "php_set_file_read_gadget"} <= kinds)
