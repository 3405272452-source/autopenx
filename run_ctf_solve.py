"""Run CTF agent against a target URL."""
import asyncio
import sys
import os
import json
import time

sys.path.insert(0, r"c:\Users\86181\Desktop\AutoPenX")
os.chdir(r"c:\Users\86181\Desktop\AutoPenX")

from dotenv import load_dotenv
load_dotenv()

from config.settings import settings
settings.reload()

from autopnex.ctf.react_agent import CTFReActAgent
from pathlib import Path

TARGET = "http://2835d91d-1e60-4662-8dd7-b82bd1db9e04.node5.buuoj.cn:81"


def progress_callback(event):
    """Print progress events."""
    ev_type = event.get("event", "")
    if ev_type == "ctf_iteration_start":
        print(f"\n--- Iteration {event.get('iteration')}/{event.get('max_iterations')} ---")
    elif ev_type == "ctf_tool_start":
        args_str = json.dumps(event.get("arguments", {}), ensure_ascii=False)[:150]
        print(f"  [TOOL] {event.get('tool')}({args_str})")
    elif ev_type == "ctf_tool_finish":
        preview = str(event.get("result_preview", ""))[:200]
        print(f"  [RESULT] {preview}")
    elif ev_type == "ctf_helper_triggered":
        print(f"  [HELPER] {event.get('helper')} @ {event.get('url', '')[:80]}")
    elif ev_type == "ctf_fuse_triggered":
        print(f"  [FUSE] {event.get('level')}: {event.get('reason', '')[:100]}")
    elif ev_type == "ctf_evidence_card":
        print(f"  [EVIDENCE] {event.get('summary', '')[:100]}")
    elif ev_type in ("ctf_error",):
        print(f"  [ERROR] {event.get('error_type', '')}: {event.get('tool', '')}")


async def solve():
    runtime = settings.snapshot()
    agent = CTFReActAgent(
        target=TARGET,
        challenge_type="web",
        flag_format=r"flag\{[^}]+\}",
        max_iterations=30,
        timeout=600,
        thinking=True,
        enabled_tools=[],
        runtime_config=runtime,
        progress_callback=progress_callback,
        knowledge_base_path=str(Path(r"c:\Users\86181\Desktop\AutoPenX") / "ctf_knowledge.json"),
        multi_agent=True,  # Hybrid: deterministic routes first, then LLM ReAct fallback
    )
    result = await agent.solve()
    return result


if __name__ == "__main__":
    start = time.time()
    result = asyncio.run(solve())
    elapsed = time.time() - start
    print("\n" + "=" * 60)
    print(f"Success: {result.get('success')}")
    print(f"Flag: {result.get('flag')}")
    print(f"Iterations: {result.get('iterations')}")
    print(f"Duration: {elapsed:.1f}s")
    print(f"Error: {result.get('error')}")
    if result.get("steps"):
        print(f"\nTotal steps: {len(result['steps'])}")
    if result.get("reasoning"):
        print(f"\nFinal reasoning: {result['reasoning'][:800]}")

