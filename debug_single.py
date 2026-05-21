"""Debug a single challenge target - minimal version."""
import logging, sys, json
logging.basicConfig(level=logging.WARNING, stream=sys.stdout)

from autopnex.ctf.multi_agent import MultiAgentOrchestrator
from tests.benchmark.challenges import (
    LFIReadDirect, LFIReadEncoded, SSTIReflectedJinja2,
    SQLiUnionBased, SQLiBooleanBlind, CMDiFilteredChars,
    JWTAlgNone, GraphQLIntrospection, WebSocketAuthBypass,
    XSSReflected, XSSStored,
)
import time

TARGETS = {
    "lfi_basic": LFIReadDirect,
    "lfi_filter": LFIReadEncoded,
    "ssti_jinja": SSTIReflectedJinja2,
    "sqli_union": SQLiUnionBased,
    "sqli_blind": SQLiBooleanBlind,
    "cmdi_filter": CMDiFilteredChars,
    "jwt_none": JWTAlgNone,
    "graphql_introspection": GraphQLIntrospection,
    "websocket_auth_bypass": WebSocketAuthBypass,
    "xss_reflected": XSSReflected,
    "xss_stored": XSSStored,
}

target_id = sys.argv[1] if len(sys.argv) > 1 else "ssti_jinja"
cls = TARGETS[target_id]
challenge = cls()
challenge.start()
time.sleep(0.5)
print(f"Target: {target_id} at {challenge.url}")
print(f"Expected flag: {challenge.flag}")

try:
    orch = MultiAgentOrchestrator(target_url=challenge.url, max_rounds=15)

    for round_num in range(1, 10):
        coord_decision = orch.coordinator.decide()
        scores = orch.coordinator._score_routes()
        print(f'--- Round {round_num} ---')
        print(f'Top 5 scores: {[(r,s) for r,s in scores[:5]]}')
        print(f'Coordinator: {coord_decision.route} -> {coord_decision.next_action.get("to","?")}')

        # Print evidence
        state = orch.blackboard.state_summary()
        for e in state.get("top_evidence", [])[:3]:
            print(f'  Evidence: route={e.get("route")} score={e.get("score")} obs={e.get("observation","")[:80]}')
        for p in state.get("interesting_params", []):
            print(f'  Param: {p["name"]} -> {p.get("suspected_routes", [])}')

        if coord_decision.next_action.get("action") == "stop":
            print("STOP")
            break

        target = coord_decision.next_action.get("to", "recon")
        if target == "recon":
            recon_decision = orch.recon.decide()
            result = orch.recon.execute(recon_decision)
            orch.coordinator.record_result(coord_decision.route, result.get("found_flag", False))
        elif target == "exploit":
            exploit_decision = orch.exploit.decide(suggested_route=coord_decision.route)
            print(f'Exploit route: {exploit_decision.route}')
            result = orch.exploit.execute(exploit_decision)
            rs = result.get("status", "?")
            flag = result.get("flag")
            print(f'Result: status={rs}, flag={flag}, stop={str(result.get("stop_reason",""))[:120]}')
            if result.get("status"):
                outcome = orch.coordinator.process_exploit_result(result)
                if outcome.get("stop"):
                    print(f'*** FLAG: {outcome["flag"]} ***')
                    break
        print()
finally:
    challenge.stop()
    try:
        challenge.cleanup()
    except Exception:
        pass
