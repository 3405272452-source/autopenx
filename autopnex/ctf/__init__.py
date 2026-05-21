"""CTF Flag 自动捕获系统 — AI 辅助 CTF 解题引擎。"""
from __future__ import annotations

from .ida_mcp_client import IDAMCPClient, IDAConfig, IDAResult
from .models import (
    AttackPlan,
    AttackStep,
    ChallengeInput,
    ChallengeProfile,
    ChallengeType,
    CTFProgress,
    CTFResult,
    FlagCandidate,
    StepResult,
)
from .offline_solver import OfflineSolver

# PHP Attack Chain modules (Phase 1-6)
from .source_leak_scanner import SourceLeakScanner, LeakResult
from .php_audit_engine import (
    PHPAuditEngine,
    PHPVulnerability,
    VulnType,
    Severity,
    PHPAuditReport,
    audit_php_source,
    audit_php_text,
)
from .php_deser_framework import (
    POPChain,
    POPChainSelector,
    PayloadGenerator,
    build_phar,
    quick_pop_payload,
)
from .upload_exploit import UploadExploit, auto_upload_exploit
from .webshell_manager import WebshellManager
from .attack_chain_orchestrator import (
    AttackChainOrchestrator,
    AttackChainResult,
    ChainState,
    run_php_attack_chain,
)
from .workspace_cleaner import WorkspaceCleaner, one_click_cleanup

# M1: PromptCompiler + WebStateBlackboard + RouteCards + RouteStateMachines
from .web_state_blackboard import (
    WebStateBlackboard,
    EndpointRecord,
    FormRecord,
    ParamRecord,
    EvidenceCard,
    AttemptRecord,
    CandidateFlag,
    RouteStatus,
    EvidenceStrength,
)
from .prompt_compiler import PromptCompiler, TokenBudget, build_task_context, compress_history, summarize_html
from .route_cards import RouteCard, ROUTE_CARDS, get_route_card, get_routes_for_evidence
from .source_audit_agent import SourceAuditAgent, AuditResult, SinkInfo, SourceInfo, DataFlow
from .route_state_machine import (
    RouteStateMachine,
    SourceLeakMachine,
    LFIMachine,
    SSTIMachine,
    SQLiMachine,
    CMDiMachine,
    JWTMachine,
    UploadMachine,
    PHPPopMachine,
    SSRFMachine,
    IDORMachine,
    XSSMachine,
    GraphQLMachine,
    WebSocketMachine,
    create_machine,
    run_route,
    RouteResult,
    MACHINE_REGISTRY,
)

__all__ = [
    # Models
    "AttackPlan",
    "AttackStep",
    "ChallengeInput",
    "ChallengeProfile",
    "ChallengeType",
    "CTFProgress",
    "CTFResult",
    "FlagCandidate",
    "IDAConfig",
    "IDAMCPClient",
    "IDAResult",
    "OfflineSolver",
    "StepResult",
    # Source Leak
    "SourceLeakScanner",
    "LeakResult",
    # PHP Audit
    "PHPAuditEngine",
    "PHPVulnerability",
    "VulnType",
    "Severity",
    "PHPAuditReport",
    "audit_php_source",
    "audit_php_text",
    # Deser Framework
    "POPChain",
    "POPChainSelector",
    "PayloadGenerator",
    "build_phar",
    "quick_pop_payload",
    # Upload Exploit
    "UploadExploit",
    "auto_upload_exploit",
    # Webshell
    "WebshellManager",
    # Attack Chain
    "AttackChainOrchestrator",
    "AttackChainResult",
    "ChainState",
    "run_php_attack_chain",
    # Workspace Cleaner
    "WorkspaceCleaner",
    "one_click_cleanup",
    # M1: WebStateBlackboard
    "WebStateBlackboard",
    "EndpointRecord",
    "FormRecord",
    "ParamRecord",
    "EvidenceStrength",
    "RouteStatus",
    # M1: PromptCompiler
    "PromptCompiler",
    "TokenBudget",
    "build_task_context",
    "compress_history",
    # M1: RouteCards
    "RouteCard",
    "ROUTE_CARDS",
    "get_route_card",
    "get_routes_for_evidence",
    # SourceAuditAgent
    "SourceAuditAgent",
    "AuditResult",
    "SinkInfo",
    "SourceInfo",
    "DataFlow",
    # M1: RouteStateMachines
    "RouteStateMachine",
    "SourceLeakMachine",
    "LFIMachine",
    "SSTIMachine",
    "SQLiMachine",
    "CMDiMachine",
    "JWTMachine",
    "UploadMachine",
    "PHPPopMachine",
    "SSRFMachine",
    "IDORMachine",
    "XSSMachine",
    "GraphQLMachine",
    "WebSocketMachine",
    "create_machine",
    "run_route",
    "RouteResult",
    "MACHINE_REGISTRY",
]
