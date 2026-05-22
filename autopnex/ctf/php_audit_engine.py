"""PHP source code audit engine for CTF challenges.

Performs static analysis on PHP source: dangerous function detection,
lightweight data flow tracking, vulnerability classification, and
exploit hint generation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .source_analyzer import SourceAnalysis, SourceFinding


# ---------------------------------------------------------------------------
# Enums & Constants
# ---------------------------------------------------------------------------

class VulnType(Enum):
    DESER_RCE = "deser_rce"
    FILE_INCLUDE = "file_include"
    CMD_INJECT = "cmd_inject"
    CODE_EXEC = "code_exec"
    ARBITRARY_FILE_READ = "arbitrary_file_read"
    ARBITRARY_FILE_WRITE = "arbitrary_file_write"
    ARBITRARY_FILE_DELETE = "arbitrary_file_delete"
    FILE_UPLOAD = "file_upload"
    SSRF = "ssrf"
    SQL_INJECT = "sql_inject"
    VARIABLE_COVER = "variable_cover"
    WEAK_COMPARE = "weak_compare"
    PHAR_TRIGGER = "phar_trigger"
    XXE = "xxe"
    NOSQL_INJECT = "nosql_inject"
    PATH_TRAVERSAL = "path_traversal"
    INFO_LEAK = "info_leak"
    OTHER = "other"


class Severity(Enum):
    CRITICAL = "C"     # Direct RCE / flag read
    HIGH = "H"         # Likely exploitable
    MEDIUM = "M"       # Possibly exploitable with conditions
    LOW = "L"          # Informational / hardening issue
    INFO = "I"         # Not a vulnerability itself


# Dangerous sink patterns: (VulnType, regex_or_keyword, is_regex, exploit_suggestions)
DANGEROUS_SINKS: List[Tuple[VulnType, str, bool, str]] = [
    # Deserialization
    (VulnType.DESER_RCE, r"\bunserialize\s*\(", True,
     "User-controlled data passed to unserialize(). Build a POP chain to get RCE."),
    (VulnType.DESER_RCE, r"\bunserialize\s*\(\s*base64_decode\s*\(", True,
     "base64-decoded unserialize input — construct POP chain, base64-encode payload."),
    (VulnType.DESER_RCE, r"\bwddx_deserialize\s*\(", True,
     "WDDX deserialization may be exploitable if user input reaches it."),

    # File inclusion
    (VulnType.FILE_INCLUDE, r"\binclude\s*\(.*\$", True,
     "LFI via include() with user-controlled path. Try php://filter, data://, /proc/self/environ."),
    (VulnType.FILE_INCLUDE, r"\brequire\s*\(.*\$", True,
     "LFI via require(). Same vectors as include()."),
    (VulnType.FILE_INCLUDE, r"\binclude_once\s*\(.*\$", True,
     "LFI via include_once(). Same vectors as include()."),
    (VulnType.FILE_INCLUDE, r"\brequire_once\s*\(.*\$", True,
     "LFI via require_once(). Same vectors as include()."),
    (VulnType.PHAR_TRIGGER, r"\bfile_exists\s*\(.*\$", True,
     "phar:// deserialization via file_exists(). Upload a .phar file then trigger with phar://path."),
    (VulnType.PHAR_TRIGGER, r"\bis_file\s*\(.*\$", True,
     "phar:// deserialization via is_file()."),
    (VulnType.PHAR_TRIGGER, r"\bis_dir\s*\(.*\$", True,
     "phar:// deserialization via is_dir()."),
    (VulnType.PHAR_TRIGGER, r"\bgetimagesize\s*\(.*\$", True,
     "phar:// deserialization via getimagesize(). Upload a phar file disguised as an image."),

    # Command injection
    (VulnType.CMD_INJECT, r"\bsystem\s*\(.*\$", True,
     "Command injection via system(). Try pipes, semicolons, backticks."),
    (VulnType.CMD_INJECT, r"\bexec\s*\(.*\$", True,
     "Command injection via exec(). Use 2nd parameter for output capture."),
    (VulnType.CMD_INJECT, r"\bshell_exec\s*\(.*\$", True,
     "Command injection via shell_exec(). Wraps in shell, try backticks or pipes."),
    (VulnType.CMD_INJECT, r"\bpassthru\s*\(.*\$", True,
     "Command injection via passthru(). Same vectors as system()."),
    (VulnType.CMD_INJECT, r"\bpopen\s*\(.*\$", True,
     "Command injection via popen(). Process handle, may need 2-stage."),
    (VulnType.CMD_INJECT, r"\bproc_open\s*\(.*\$", True,
     "Command injection via proc_open(). Complex API but exploitable."),

    # Code execution
    (VulnType.CODE_EXEC, r"\beval\s*\(.*\$", True,
     "eval() with user-controlled data. Inject arbitrary PHP code."),
    (VulnType.CODE_EXEC, r"\bassert\s*\(.*\$", True,
     "assert() with user-controlled data (pre-PHP 8). Inject arbitrary PHP code."),
    (VulnType.CODE_EXEC, r"\bpreg_replace\s*\(.*/e", True,
     "/e modifier in preg_replace() (PHP < 7.0). Code execution via pattern matching."),
    (VulnType.CODE_EXEC, r"\bcreate_function\s*\(.*\$", True,
     "create_function() with user input. Internal eval() — inject to escape."),
    (VulnType.CODE_EXEC, r"\bcall_user_func\s*\(.*\$", True,
     "call_user_func() with user-controlled callback. Call any function."),
    (VulnType.CODE_EXEC, r"\bcall_user_func_array\s*\(.*\$", True,
     "call_user_func_array() with user-controlled callback. Similar to call_user_func."),

    # File read
    (VulnType.ARBITRARY_FILE_READ, r"\bfile_get_contents\s*\(.*\$", True,
     "Arbitrary file read via file_get_contents(). Try /flag, /etc/passwd, php://filter."),
    (VulnType.ARBITRARY_FILE_READ, r"\breadfile\s*\(.*\$", True,
     "Arbitrary file read via readfile(). Outputs directly, try /flag."),
    (VulnType.ARBITRARY_FILE_READ, r"\bfread\s*\(fopen\s*\(.*\$", True,
     "Arbitrary file read via fopen/fread with user path."),
    (VulnType.ARBITRARY_FILE_READ, r"\bfgets\s*\(fopen\s*\(.*\$", True,
     "Arbitrary file read via fopen/fgets with user path."),
    (VulnType.SSRF, r"\bcurl_exec\s*\(.*\$", True,
     "SSRF via curl_exec() with user-controlled URL. Try file:///flag, gopher://."),
    (VulnType.SSRF, r"\bcurl_setopt\s*\(.*CURLOPT_URL", True,
     "SSRF via curl_setopt() with user-controlled CURLOPT_URL."),

    # File write
    (VulnType.ARBITRARY_FILE_WRITE, r"\bfile_put_contents\s*\(.*\$", True,
     "Arbitrary file write. Write a PHP webshell to a web-accessible path."),
    (VulnType.ARBITRARY_FILE_WRITE, r"\bfwrite\s*\(fopen\s*\(.*\$", True,
     "Arbitrary file write via fopen/fwrite. Same as file_put_contents."),
    (VulnType.FILE_UPLOAD, r"\bmove_uploaded_file\s*\(", True,
     "File upload via move_uploaded_file(). Check extension/mime validation strength."),
    (VulnType.FILE_UPLOAD, r"\bcopy\s*\(\s*\$_(FILES|GET|POST)", True,
     "File upload/copy from user-controlled source."),

    # File delete
    (VulnType.ARBITRARY_FILE_DELETE, r"\bunlink\s*\(.*\$", True,
     "Arbitrary file deletion. Can trigger phar:// via unlink or remove config/lock files."),
    (VulnType.ARBITRARY_FILE_DELETE, r"\brmdir\s*\(.*\$", True,
     "Directory deletion with user input."),

    # SQL injection
    (VulnType.SQL_INJECT, r"SELECT.*\.\s*\$_(GET|POST|REQUEST)", True,
     "Potential SQL injection: GET/POST directly interpolated into SQL query."),
    (VulnType.SQL_INJECT, r"INSERT.*\.\s*\$_(GET|POST|REQUEST)", True,
     "Potential SQL injection in INSERT statement."),
    (VulnType.SQL_INJECT, r"UPDATE.*\.\s*\$_(GET|POST|REQUEST)", True,
     "Potential SQL injection in UPDATE statement."),
    (VulnType.SQL_INJECT, r"DELETE.*\.\s*\$_(GET|POST|REQUEST)", True,
     "Potential SQL injection in DELETE statement."),
    (VulnType.SQL_INJECT, r"\bmysql_query\s*\(.*\$", True,
     "mysql_query() with user input. Deprecated, no prepared statements."),
    (VulnType.SQL_INJECT, r"\bmysqli_query\s*\(.*\$_(GET|POST|REQUEST)", True,
     "mysqli_query() with user input directly in query string."),
    (VulnType.SQL_INJECT, r"\bmssql_query\s*\(.*\$", True,
     "mssql_query() with user input."),
    (VulnType.SQL_INJECT, r"\bpg_query\s*\(.*\$", True,
     "pg_query() with user input."),
    (VulnType.SQL_INJECT, r"\bsqlite_query\s*\(.*\$", True,
     "sqlite_query() with user input."),

    # Variable coverage
    (VulnType.VARIABLE_COVER, r"\bextract\s*\(\s*\$_(GET|POST|REQUEST)", True,
     "extract() on user input can override existing variables and bypass auth."),
    (VulnType.VARIABLE_COVER, r"\bparse_str\s*\(.*\$_(GET|POST|REQUEST)", True,
     "parse_str() on user input can create/override variables."),
    (VulnType.VARIABLE_COVER, r"\bimport_request_variables\s*\(", True,
     "import_request_variables() imports GET/POST/COOKIE as globals. Highly dangerous."),

    # Weak comparison
    (VulnType.WEAK_COMPARE, r"\$\w+\s*==\s*\$_(GET|POST|COOKIE)", True,
     "Loose comparison (==) with user input. Type juggling may bypass checks."),
    (VulnType.WEAK_COMPARE, r"strcmp\s*\(.*\$_(GET|POST|COOKIE)", True,
     "strcmp() NULL bypass: input as array() causes NULL return which == 0."),
    (VulnType.WEAK_COMPARE, r"sha1\s*\(.*\s*==\s*\$_(GET|POST|COOKIE)", True,
     "sha1() array bypass: input as array() makes sha1 return NULL."),
    (VulnType.WEAK_COMPARE, r"md5\s*\(.*\s*==\s*\$_(GET|POST|COOKIE)", True,
     "md5() array bypass or magic hash collision (0eXXXXX == 0eXXXXX)."),

    # NoSQL injection
    (VulnType.NOSQL_INJECT, r"new\s+MongoDB\\Client", True,
     "MongoDB connection. Check for NoSQL injection if user input reaches queries."),
    (VulnType.NOSQL_INJECT, r"\$collection->find\s*\(.*\$_(GET|POST)", True,
     "MongoDB find() with user input — possible NoSQL injection."),
    (VulnType.NOSQL_INJECT, r"\$collection->findOne\s*\(.*\$_(GET|POST)", True,
     "MongoDB findOne() with user input."),
    (VulnType.NOSQL_INJECT, r"new\s+Predis\\Client", True,
     "Redis/Predis connection. Potential for SSRF/command injection."),

    # XXE
    (VulnType.XXE, r"simplexml_load_string\s*\(.*\$", True,
     "XXE via simplexml_load_string() — default enables external entities."),
    (VulnType.XXE, r"simplexml_load_file\s*\(.*\$", True,
     "XXE via simplexml_load_file() — reads XML from user-controlled file."),
    (VulnType.XXE, r"DOMDocument::loadXML\s*\(.*\$", True,
     "XXE via DOMDocument::loadXML(). Must check if LIBXML_NOENT is set."),
    (VulnType.XXE, r"new\s+DOMDocument\s*\(\s*\)", True,
     "DOMDocument instantiation. Check if external entities are loaded."),
    (VulnType.XXE, r"xml_parse\s*\(.*\$", True,
     "XXE via xml_parse(). Check parser options."),

    # Path traversal
    (VulnType.PATH_TRAVERSAL, r"basename\s*\(.*\$_(GET|POST)", True,
     "basename() has known bypass (multibyte, null byte)."),
    (VulnType.PATH_TRAVERSAL, r"realpath\s*\(.*\$_(GET|POST)", True,
     "realpath() resolves symlinks but doesn't prevent directory traversal."),

    # Info leak
    (VulnType.INFO_LEAK, r"var_dump\s*\(.*\$_(GET|POST)", True,
     "Debug var_dump() on user input — info leak."),
    (VulnType.INFO_LEAK, r"print_r\s*\(.*\$_(GET|POST)", True,
     "Debug print_r() on user input — info leak."),
    (VulnType.INFO_LEAK, r"echo.*\$_(GET|POST)", True,
     "User input echoed back. Check for XSS or info leak."),
]


# Php ext patterns to extract: ($_GET['xxx'] style)
_SUPERGLOBAL_KEY_RE = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]",
    re.I,
)

# Variable assignment tracking
_VAR_ASSIGN_RE = re.compile(
    r"(\$\w+)\s*=\s*(\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\s*\[[^\]]+\])",
    re.I,
)

# Tainted variable usage tracking
_TAINTED_VAR_RE = re.compile(r"(\$\w+)\s*=\s*\$(\w+)\s*\[", re.I)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PHPVulnerability:
    vuln_type: VulnType
    severity: Severity
    file: str
    line: int
    source: str      # User input parameter name
    sink: str        # Dangerous function
    detail: str      # Code snippet
    exploit_hint: str
    chain_potential: str = ""  # e.g. "deser->rce", "upload->include"
    cwe_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_type": self.vuln_type.value,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "source": self.source,
            "sink": self.sink,
            "detail": self.detail[:200],
            "exploit_hint": self.exploit_hint,
            "chain_potential": self.chain_potential,
            "cwe_id": self.cwe_id,
        }


@dataclass
class PHPAuditReport:
    files_analyzed: int
    total_lines: int
    vulnerabilities: List[PHPVulnerability] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    framework: str = ""
    php_version_guess: str = ""

    def by_severity(self, min_sev: Severity = Severity.MEDIUM) -> List[PHPVulnerability]:
        """Filter vulnerabilities by minimum severity level."""
        sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        return [v for v in self.vulnerabilities if sev_order[v.severity] <= sev_order[min_sev]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_analyzed": self.files_analyzed,
            "total_lines": self.total_lines,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "warnings": self.warnings,
            "framework": self.framework,
            "php_version_guess": self.php_version_guess,
        }

    def to_prompt_context(self, max_vulns: int = 30) -> str:
        lines = [
            f"PHP Audit: {self.files_analyzed} files, {self.total_lines} lines",
            f"Framework: {self.framework or 'unknown'}",
            f"Vulnerabilities found: {len(self.vulnerabilities)}",
        ]
        if self.php_version_guess:
            lines.append(f"PHP version guess: {self.php_version_guess}")
        for v in self.vulnerabilities[:max_vulns]:
            lines.append(
                f"  [{v.severity.value}] {v.vuln_type.value} @ {v.file}:{v.line} "
                f"source={v.source} sink={v.sink} -> {v.exploit_hint}"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# PHPAuditEngine
# ---------------------------------------------------------------------------

class PHPAuditEngine:
    """Static analysis engine for PHP source code in CTF context."""

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def audit(self, source: SourceAnalysis) -> PHPAuditReport:
        """Run full audit on a SourceAnalysis result."""
        vulns: List[PHPVulnerability] = []
        total_lines = 0

        for file_entry in source.files:
            path = file_entry.get("path", "")
            size = file_entry.get("size", 0)
            if not path or size == 0:
                continue

        # Process source findings
        for finding in source.findings:
            v = self._classify_finding(finding)
            if v:
                vulns.append(v)

        # Check for taint flows from parameters to sinks
        params_set = {(p["file"], p["name"]) for p in source.parameters}
        for finding in source.findings:
            if finding.kind in ("unserialize", "file_read", "command_exec", "dynamic_call",
                                 "file_write", "file_delete", "path_probe"):
                for pfile, pname in params_set:
                    if pfile == finding.file:
                        v = self._check_taint_flow(finding, pname)
                        if v and v not in vulns:
                            vulns.append(v)

        # Check for chain potential
        chain_vulns = self._analyze_chains(vulns)
        vulns = chain_vulns

        return PHPAuditReport(
            files_analyzed=len(source.files),
            total_lines=total_lines or len(source.findings) * 10,
            vulnerabilities=vulns,
            warnings=source.errors[:20],
        )

    def audit_text(self, filename: str, text: str) -> List[PHPVulnerability]:
        """Audit raw PHP source text, returning vulnerabilities found."""
        vulns: List[PHPVulnerability] = []
        lines = text.splitlines()

        for line_no, line in enumerate(lines, 1):
            compact = line.strip()
            if not compact:
                continue
            for vuln_type, pattern, is_regex, hint in DANGEROUS_SINKS:
                if is_regex:
                    if re.search(pattern, compact, re.I):
                        vulns.append(PHPVulnerability(
                            vuln_type=vuln_type,
                            severity=self._type_to_severity(vuln_type),
                            file=filename,
                            line=line_no,
                            source="user_input",
                            sink=compact[:120],
                            detail=compact[:200],
                            exploit_hint=hint,
                        ))
                else:
                    if pattern.lower() in compact.lower():
                        vulns.append(PHPVulnerability(
                            vuln_type=vuln_type,
                            severity=self._type_to_severity(vuln_type),
                            file=filename,
                            line=line_no,
                            source="user_input",
                            sink=compact[:120],
                            detail=compact[:200],
                            exploit_hint=hint,
                        ))

        return vulns

    def detect_class_hierarchy(self, source: SourceAnalysis) -> Dict[str, List[str]]:
        """Extract class hierarchy from source for POP chain building."""
        hierarchy: Dict[str, List[str]] = {}
        for cls in source.classes:
            name = cls.get("name", "")
            methods = cls.get("methods", [])
            hierarchy[name] = methods
        return hierarchy

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _classify_finding(self, finding: SourceFinding) -> Optional[PHPVulnerability]:
        """Map a SourceFinding to a PHPVulnerability."""
        kind_to_vuln: Dict[str, tuple] = {
            "unserialize": (VulnType.DESER_RCE, Severity.HIGH,
                           "Unserialize on user input — build POP chain for RCE"),
            "command_exec": (VulnType.CMD_INJECT, Severity.CRITICAL,
                            "Command execution with user input"),
            "dynamic_call": (VulnType.CODE_EXEC, Severity.CRITICAL,
                            "Dynamic call (eval/call_user_func) with user input"),
            "file_read": (VulnType.ARBITRARY_FILE_READ, Severity.HIGH,
                         "File read from user-controllable path"),
            "file_write": (VulnType.ARBITRARY_FILE_WRITE, Severity.CRITICAL,
                          "File write from user-controllable path — write webshell"),
            "file_delete": (VulnType.ARBITRARY_FILE_DELETE, Severity.MEDIUM,
                           "File deletion — may trigger phar:// or remove locks"),
            "path_probe": (VulnType.PHAR_TRIGGER, Severity.HIGH,
                          "Path probe on user input — phar:// deser trigger candidate"),
            "phar_trigger_candidate": (VulnType.PHAR_TRIGGER, Severity.HIGH,
                                      "Phar deserialization trigger chain"),
            "php_set_file_read_gadget": (VulnType.DESER_RCE, Severity.HIGH,
                                        "Potential POP chain gadget: __set reads file"),
            "pdo_fetch_class_candidate": (VulnType.DESER_RCE, Severity.HIGH,
                                         "PDO FETCH_CLASS gadget — object injection from DB rows"),
            "pdo_connection_options": (VulnType.DESER_RCE, Severity.MEDIUM,
                                      "PDO connection options may be controllable"),
            "base64": (VulnType.INFO_LEAK, Severity.INFO,
                      "Base64 encode/decode — check for flags or payload encoding"),
            "session": (VulnType.OTHER, Severity.LOW,
                       "Session handling — check for session deser/upload"),
            "superglobal": (VulnType.INFO_LEAK, Severity.INFO,
                           "Superglobal access — data source"),
            "php_magic_method": (VulnType.DESER_RCE, Severity.MEDIUM,
                                "Magic method found — potential POP chain gadget"),
        }

        if finding.kind in kind_to_vuln:
            vt, sev, hint = kind_to_vuln[finding.kind]
            return PHPVulnerability(
                vuln_type=vt,
                severity=sev,
                file=finding.file,
                line=finding.line,
                source="user_input",
                sink=finding.detail[:120],
                detail=finding.detail[:200],
                exploit_hint=hint,
            )

        return None

    def _check_taint_flow(self, finding: SourceFinding, source_param: str) -> Optional[PHPVulnerability]:
        """Check if there's a taint flow from source_param to the finding's sink."""
        # Simple heuristic: if the source param name appears near the dangerous function
        # This is not a full data flow analysis, but CTF-oriented heuristics
        lines_around = finding.detail.lower()
        if source_param.lower() in lines_around:
            kind_map = {
                "unserialize": (VulnType.DESER_RCE, Severity.HIGH),
                "command_exec": (VulnType.CMD_INJECT, Severity.CRITICAL),
                "dynamic_call": (VulnType.CODE_EXEC, Severity.CRITICAL),
                "file_read": (VulnType.ARBITRARY_FILE_READ, Severity.HIGH),
                "file_write": (VulnType.ARBITRARY_FILE_WRITE, Severity.CRITICAL),
                "file_delete": (VulnType.ARBITRARY_FILE_DELETE, Severity.MEDIUM),
                "path_probe": (VulnType.PHAR_TRIGGER, Severity.HIGH),
            }
            if finding.kind in kind_map:
                vt, sev = kind_map[finding.kind]
                return PHPVulnerability(
                    vuln_type=vt,
                    severity=sev,
                    file=finding.file,
                    line=finding.line,
                    source=source_param,
                    sink=finding.detail[:120],
                    detail=finding.detail[:200],
                    exploit_hint=f"Direct taint flow: param '{source_param}' reaches {finding.kind}.",
                )
        return None

    def _analyze_chains(self, vulns: List[PHPVulnerability]) -> List[PHPVulnerability]:
        """Analyze vulnerabilities for chaining potential."""
        deser_vulns = [v for v in vulns if v.vuln_type == VulnType.DESER_RCE]
        upload_vulns = [v for v in vulns if v.vuln_type == VulnType.FILE_UPLOAD]
        include_vulns = [v for v in vulns if v.vuln_type == VulnType.FILE_INCLUDE]
        write_vulns = [v for v in vulns if v.vuln_type == VulnType.ARBITRARY_FILE_WRITE]
        phar_vulns = [v for v in vulns if v.vuln_type == VulnType.PHAR_TRIGGER]

        # Chain: upload + include = upload shell, then include it
        if upload_vulns and include_vulns:
            for v in upload_vulns:
                v.chain_potential = "upload->include: upload shell, then include it for RCE"

        # Chain: upload + phar trigger = upload phar, trigger deser
        if upload_vulns and phar_vulns:
            for v in upload_vulns:
                if not v.chain_potential:
                    v.chain_potential = "upload->phar_deser: upload phar file, trigger via phar://"

        # Chain: write + include
        if write_vulns and include_vulns:
            for v in write_vulns:
                v.chain_potential = "write->include: write webshell to known path, then include it"

        # Chain: deser + cmd exec (POP chain reaches system/exec)
        if deser_vulns:
            for v in deser_vulns:
                v.chain_potential = "deser->cmd: find POP chain gadget that reaches system()/exec()"

        return vulns

    @staticmethod
    def _type_to_severity(vuln_type: VulnType) -> Severity:
        mapping: Dict[VulnType, Severity] = {
            VulnType.CMD_INJECT: Severity.CRITICAL,
            VulnType.CODE_EXEC: Severity.CRITICAL,
            VulnType.ARBITRARY_FILE_WRITE: Severity.CRITICAL,
            VulnType.ARBITRARY_FILE_READ: Severity.HIGH,
            VulnType.DESER_RCE: Severity.HIGH,
            VulnType.FILE_INCLUDE: Severity.HIGH,
            VulnType.SQL_INJECT: Severity.HIGH,
            VulnType.SSRF: Severity.HIGH,
            VulnType.FILE_UPLOAD: Severity.MEDIUM,
            VulnType.PHAR_TRIGGER: Severity.HIGH,
            VulnType.VARIABLE_COVER: Severity.HIGH,
            VulnType.ARBITRARY_FILE_DELETE: Severity.MEDIUM,
            VulnType.WEAK_COMPARE: Severity.MEDIUM,
            VulnType.NOSQL_INJECT: Severity.HIGH,
            VulnType.XXE: Severity.HIGH,
            VulnType.PATH_TRAVERSAL: Severity.MEDIUM,
            VulnType.INFO_LEAK: Severity.LOW,
            VulnType.OTHER: Severity.INFO,
        }
        return mapping.get(vuln_type, Severity.MEDIUM)


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def audit_php_source(source: SourceAnalysis) -> PHPAuditReport:
    """Quick audit from a SourceAnalysis."""
    engine = PHPAuditEngine()
    return engine.audit(source)


def audit_php_text(filename: str, text: str) -> List[PHPVulnerability]:
    """Quick audit from raw PHP text."""
    engine = PHPAuditEngine()
    return engine.audit_text(filename, text)
