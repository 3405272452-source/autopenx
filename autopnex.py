#!/usr/bin/env python3
"""AutoPenX CLI entry point.

Usage:
    python autopnex.py --target http://example.com
    python autopnex.py --target http://example.com --mock      # offline rule-based
    python autopnex.py --target http://example.com --out report.md
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from autopnex import tools as _tools  # noqa: F401  (side-effect: load all tools)
from autopnex.orchestrator import LLMOrchestrator
from autopnex.orchestrator.llm_client import LLMClient
from autopnex.policy import apply_scan_policy, create_approval
from autopnex.report import ReportGenerator
from autopnex.state_machine import PenTestStateMachine
from autopnex.tools._http import TargetScopeError, ensure_target_allowed
from config.settings import settings


BANNER = r"""
    _         _         ____            __  __
   / \  _   _| |_ ___  |  _ \ ___ _ __  \ \/ /
  / _ \| | | | __/ _ \ | |_) / _ \ '_ \  \  /
 / ___ \ |_| | || (_) ||  __/  __/ | | | /  \
/_/   \_\__,_|\__\___/ |_|   \___|_| |_|/_/\_\
     LLM-driven automated penetration testing
"""


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AutoPenX — LLM-driven automated penetration testing")
    p.add_argument("--target", "-t", default=None, help="Target URL or hostname (authorised only!)")
    p.add_argument("--list-tools", action="store_true", help="List all available tools and exit")
    p.add_argument("--version", "-V", action="store_true", help="Show version and exit")
    p.add_argument("--tools", default=None, help="Comma-separated tool names to run (default: all)")
    p.add_argument("--out", "-o", default=None, help="Output Markdown report path (default: reports/<ts>.md)")
    p.add_argument("--html", default=None, help="Optional HTML report path")
    p.add_argument("--mock", action="store_true", help="Force offline rule-based brain (no LLM API calls)")
    p.add_argument("--multi-agent", action="store_true", default=None, help="Use multi-agent collaboration (Coordinator+Recon+Exploit+Critic)")
    p.add_argument("--max-iter", type=int, default=None, help="Override max iterations per state")
    p.add_argument("--json", dest="json_path", default=None, help="Optional path to dump raw findings JSON")
    p.add_argument("--quiet", "-q", action="store_true", help="Reduce console output")
    p.add_argument("--yes", "-y", action="store_true", help="Skip authorisation prompt (CI mode)")
    p.add_argument("--scan-mode", choices=["passive", "active"], default=None, help="Execution policy for scanning actions.")
    p.add_argument(
        "--allow-external-tools",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Allow or deny external tools such as nmap/sqlmap for this run.",
    )
    p.add_argument(
        "--allow-local-targets",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Allow or deny localhost/private targets and SSRF internal probes for this run.",
    )
    p.add_argument(
        "--enable-exploit",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Allow or deny exploit-stage tools for this run.",
    )
    p.add_argument("--login-endpoint", default=None, help="Login endpoint path (e.g. /login.php)")
    p.add_argument("--login-creds", default=None, help="Credentials as user:pass,user:pass (e.g. admin:password)")
    p.add_argument("--login-user-field", default=None, help="Username form field name (default: username)")
    p.add_argument("--login-pass-field", default=None, help="Password form field name (default: password)")
    p.add_argument("--clean", "-c", action="store_true", help="One-click cleanup: remove all temp/artifacts in ctf_workspace/")
    p.add_argument("--clean-root", default="ctf_workspace", help="Root directory for --clean scan (default: ctf_workspace)")
    p.add_argument("--clean-dry-run", action="store_true", help="Dry-run mode for --clean: show what would be deleted")
    return p.parse_args()


def _print_progress(event: dict, *, quiet: bool) -> None:
    if quiet:
        return
    ev = event.get("event")
    state = event.get("state")
    if ev == "start":
        print(f"[start] mode={event.get('mode')} target={event.get('target')}")
    elif ev == "state_enter":
        print(f"\n=== {state} ===")
    elif ev == "react_step":
        tool = event.get("tool")
        action = event.get("action")
        iteration = event.get("iteration")
        summary = event.get("tool_summary") or event.get("reasoning") or ""
        if tool:
            print(f"  [{state}#{iteration}] -> {tool}{event.get('arguments') or ''}")
            print(f"    = {summary[:160]}")
        else:
            print(f"  [{state}#{iteration}] {action}: {summary[:160]}")
    elif ev == "login_attempt":
        print(f"[login] attempting auto-login to {event.get('endpoint', '?')}")
    elif ev == "login_success":
        print(f"[login] success: {event.get('message', '')}")
    elif ev == "login_failed":
        print(f"[login] failed: {event.get('message', '')}")
    elif ev == "done":
        print("\n[done] pipeline finished")


def main() -> int:
    args = _parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    print(BANNER)

    if args.version:
        print("AutoPenX v0.2 (Shannon-enhanced)")
        return 0

    # One-click cleanup mode
    if args.clean:
        from autopnex.ctf.workspace_cleaner import one_click_cleanup
        dry = args.clean_dry_run
        root = args.clean_root
        mode = "DRY-RUN" if dry else "LIVE"
        print(f"[clean] Scanning {root} ({mode})...")
        result = one_click_cleanup(root, dry_run=dry)
        if result.get("error"):
            print(f"[clean] Error: {result['error']}")
            return 3
        removed = result.get("removed", [])
        failed = result.get("failed", [])
        count = result.get("count", 0)
        print(f"[clean] {mode}: {count} files/dirs would be removed" if dry else f"[clean] Removed {count} files/directories")
        for item in removed:
            print(f"  {'[DRY]' if dry else '[DEL]'} {item}")
        for item in failed:
            print(f"  [FAIL] {item}")
        print(f"[clean] Done. {count} items {'found' if dry else 'removed'}.")
        return 0

    if args.list_tools:
        from autopnex.tools.base import ToolRegistry
        from autopnex.tools import load_all
        tools = ToolRegistry.all()
        print(f"\n{'工具名':<25} {'分类':<12} {'描述'}")
        print("-" * 90)
        for t in sorted(tools, key=lambda x: getattr(x, 'name', '')):
            name = getattr(t, 'name', '?')
            cat = getattr(t, 'category', '?')
            desc = (getattr(t, 'description', '') or '')[:50]
            print(f"  {name:<23} {cat:<12} {desc}")
        print(f"\n共 {len(tools)} 个工具")
        return 0

    if not args.target:
        p = _parse_args.__wrapped__ if hasattr(_parse_args, '__wrapped__') else None
        print("错误: --target 是必需参数（除非使用 --list-tools 或 --version）")
        return 2

    print("⚠️  仅限在获得明确授权的目标上使用 AutoPenX。任何未授权测试均违反法律。")
    if not args.yes:
        confirm = input(f"已获授权对 {args.target} 进行测试？ [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print("已取消。")
            return 2

    base_runtime = settings.snapshot()
    approval_token = None
    requested_scopes = ["passive"]
    requested_scan_mode = args.scan_mode or base_runtime.scan_mode
    if requested_scan_mode == "active" or args.allow_external_tools:
        requested_scopes.append("active_scan")
    if args.enable_exploit:
        requested_scopes.append("exploit")
    if len(requested_scopes) > 1:
        approval_token = create_approval(args.target, requested_scopes, base_runtime.approval_ttl_seconds).token
    runtime = apply_scan_policy(
        base_runtime,
        target=args.target,
        scan_mode=requested_scan_mode,
        allow_external_tools=args.allow_external_tools,
        allow_local_targets=args.allow_local_targets,
        exploit_enabled=args.enable_exploit,
        approval_token=approval_token,
    )
    # Apply login overrides from CLI
    login_overrides = {}
    if args.login_endpoint:
        login_overrides["login_endpoint"] = args.login_endpoint
    if args.login_creds:
        login_overrides["login_credentials"] = args.login_creds
    if args.login_user_field:
        login_overrides["login_username_field"] = args.login_user_field
    if args.login_pass_field:
        login_overrides["login_password_field"] = args.login_pass_field
    if login_overrides:
        runtime = settings.snapshot(**login_overrides)
        # Re-apply policy on top
        runtime = apply_scan_policy(
            runtime,
            target=args.target,
            scan_mode=requested_scan_mode,
            allow_external_tools=args.allow_external_tools,
            allow_local_targets=args.allow_local_targets,
            exploit_enabled=args.enable_exploit,
            approval_token=approval_token,
        )
    try:
        ensure_target_allowed(args.target, runtime_config=runtime)
    except TargetScopeError as exc:
        print(f"目标被策略拒绝：{exc}")
        return 2

    # Multi-agent feature flag (frozen dataclass → replace)
    if args.multi_agent:
        runtime = replace(runtime, multi_agent_enabled=True)

    client = LLMClient(
        api_key=runtime.deepseek_api_key,
        base_url=runtime.deepseek_base_url,
        model=runtime.deepseek_model,
    )
    orchestrator = LLMOrchestrator(mock=args.mock, client=client, runtime_config=runtime)
    mode = orchestrator.mode
    print(
        "LLM mode: "
        f"{mode}   policy(scan_mode={runtime.scan_mode}, exploit={runtime.exploit_enabled}, "
        f"external_tools={runtime.allow_external_tools}, local_targets={runtime.allow_local_targets}, "
        f"multi_agent={runtime.multi_agent_enabled})"
    )

    fsm = PenTestStateMachine(
        target=args.target,
        orchestrator=orchestrator,
        max_iter_per_state=args.max_iter,
        progress_callback=lambda e: _print_progress(e, quiet=args.quiet),
    )
    findings = fsm.run()

    # Multi-agent mode (optional, feature flag)
    if runtime.multi_agent_enabled:
        print("\n=== Multi-Agent Mode ===")
        from autopnex.ctf.multi_agent import MultiAgentOrchestrator
        from autopnex.state_machine.findings import Finding
        ma_orch = MultiAgentOrchestrator(
            target_url=args.target,
            flag_format=r"[A-Za-z0-9_]+\{[^}]+\}",
            max_rounds=args.max_iter or 15,
        )
        found, flag, action_log = ma_orch.run_loop(max_rounds=args.max_iter or 15)
        if found:
            print(f"[multi-agent] Flag found: {flag}")
            findings.add_finding(Finding(
                title="Multi-Agent Flag Discovery",
                url=args.target,
                severity="HIGH",
                description=f"Multi-Agent collaboration found flag: {flag}",
            ))
        else:
            print(f"[multi-agent] No flag found (rounds={len(action_log)})")
        print(f"[multi-agent] Action log: {len(action_log)} entries")

    # Output paths
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_md = Path(args.out) if args.out else Path("reports") / f"{ts}.md"
    out_html = Path(args.html) if args.html else out_md.with_suffix(".html")
    generator = ReportGenerator(client, mode=mode)
    md_path, html_path = generator.save(findings, out_md, out_html)
    print(f"\n[report] markdown: {md_path}")
    if html_path:
        print(f"[report] html:     {html_path}")

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(findings.to_dict(), ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        print(f"[report] json:     {args.json_path}")

    # Summary to console
    print("\n=== Summary ===")
    print(f"target: {findings.target}")
    print(f"open ports: {len(findings.open_ports)}, subdomains: {len(findings.subdomains)}")
    print(f"paths: {len(findings.discovered_paths)}, params: {len(findings.parameters)}")
    print(f"findings: {len(findings.findings)}")
    for f in findings.sorted_findings()[:10]:
        print(f"  [{f.severity}] {f.title} @ {f.url or '-'} ({f.parameter or '-'})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
