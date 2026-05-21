"""Debug script for benchmark challenges."""
from tests.benchmark.challenges import LFIReadEncoded
from autopnex.ctf.multi_agent import MultiAgentOrchestrator
import requests

target = LFIReadEncoded()
target.start()
print(f"Target: {target.url}")

sess = requests.Session()
orch = MultiAgentOrchestrator(
    target_url=target.url,
    flag_format=r"flag\{[^}]+\}",
    max_rounds=15,
    session=sess,
)
found, flag, log = orch.run_loop(max_rounds=15)
print(f"Found: {found}, Flag: {flag}")
print(f"Total log entries: {len(log)}")

for e in log:
    agent = e.get("agent", "?")
    decision = e.get("decision", {})
    route = decision.get("route", "?")
    result = e.get("result", {})
    result_str = str(result)[:150]
    print(f"  R{e['round']}: agent={agent} route={route} result={result_str}")

state = orch.blackboard.state_summary()
print(f"\nParams: {state.get('interesting_params', [])}")
print(f"Evidence: {state.get('top_evidence', [])}")
print(f"Flag candidates: {orch.blackboard.flag_candidates}")

target.stop()
