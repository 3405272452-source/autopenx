"""Tests for PHP audit engine."""
import pytest
from autopnex.ctf.php_audit_engine import (
    PHPAuditEngine,
    PHPVulnerability,
    VulnType,
    Severity,
    PHPAuditReport,
    audit_php_text,
    audit_php_source,
)


class TestPHPAuditEngine:
    """Test PHP static analysis engine."""

    def test_detect_command_injection(self):
        vulns = audit_php_text("test.php", '<?php system($_GET["cmd"]); ?>')
        cmd_vulns = [v for v in vulns if v.vuln_type == VulnType.CMD_INJECT]
        assert len(cmd_vulns) > 0
        assert cmd_vulns[0].severity == Severity.CRITICAL

    def test_detect_deserialization(self):
        vulns = audit_php_text("test.php", '<?php unserialize($_POST["data"]); ?>')
        deser = [v for v in vulns if v.vuln_type == VulnType.DESER_RCE]
        assert len(deser) > 0

    def test_detect_file_inclusion(self):
        vulns = audit_php_text("test.php", '<?php include($_GET["page"] . ".php"); ?>')
        lfi = [v for v in vulns if v.vuln_type == VulnType.FILE_INCLUDE]
        assert len(lfi) > 0

    def test_detect_eval(self):
        vulns = audit_php_text("test.php", '<?php eval($_POST["code"]); ?>')
        code_exec = [v for v in vulns if v.vuln_type == VulnType.CODE_EXEC]
        assert len(code_exec) > 0
        assert code_exec[0].severity == Severity.CRITICAL

    def test_detect_arbitrary_file_read(self):
        vulns = audit_php_text("test.php", '<?php echo file_get_contents($_GET["file"]); ?>')
        afr = [v for v in vulns if v.vuln_type == VulnType.ARBITRARY_FILE_READ]
        assert len(afr) > 0

    def test_detect_arbitrary_file_write(self):
        vulns = audit_php_text("test.php", '<?php file_put_contents($_GET["path"], $_POST["content"]); ?>')
        afw = [v for v in vulns if v.vuln_type == VulnType.ARBITRARY_FILE_WRITE]
        assert len(afw) > 0

    def test_detect_sql_injection(self):
        vulns = audit_php_text("test.php", '<?php mysql_query("SELECT * FROM users WHERE id=" . $_GET["id"]); ?>')
        sqli = [v for v in vulns if v.vuln_type == VulnType.SQL_INJECT]
        assert len(sqli) > 0

    def test_detect_phar_trigger(self):
        vulns = audit_php_text("test.php", '<?php file_exists($_GET["path"]); unlink($_GET["path"]); ?>')
        phar = [v for v in vulns if v.vuln_type == VulnType.PHAR_TRIGGER]
        assert len(phar) > 0

    def test_detect_variable_coverage(self):
        vulns = audit_php_text("test.php", '<?php extract($_GET); ?>')
        vc = [v for v in vulns if v.vuln_type == VulnType.VARIABLE_COVER]
        assert len(vc) > 0

    def test_detect_weak_comparison(self):
        vulns = audit_php_text("test.php", '<?php if ($input == $_GET["password"]) { echo "admin"; } ?>')
        # Should catch the == comparison with user input
        assert len(vulns) > 0

    def test_safe_code_no_vulns(self):
        vulns = audit_php_text("safe.php", '<?php echo "Hello World"; ?>')
        critical = [v for v in vulns if v.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical) == 0  # Safe code should not produce critical/high vulns

    def test_class_hierarchy_detection(self):
        from autopnex.ctf.source_analyzer import SourceAnalysis, SourceFinding
        analysis = SourceAnalysis(
            root_file="test.zip",
            classes=[{"file": "a.php", "name": "Begin", "methods": ["__destruct", "getName"]}],
        )
        engine = PHPAuditEngine()
        hierarchy = engine.detect_class_hierarchy(analysis)
        assert "Begin" in hierarchy
        assert "__destruct" in hierarchy["Begin"]


class TestPHPVulnerability:
    def test_to_dict(self):
        v = PHPVulnerability(
            vuln_type=VulnType.CMD_INJECT,
            severity=Severity.CRITICAL,
            file="test.php",
            line=10,
            source="cmd",
            sink='system($_GET["cmd"])',
            detail='system($_GET["cmd"]);',
            exploit_hint="Try command injection",
            chain_potential="direct->rce",
            cwe_id="CWE-78",
        )
        d = v.to_dict()
        assert d["vuln_type"] == "cmd_inject"
        assert d["severity"] == "C"
        assert d["file"] == "test.php"
        assert d["line"] == 10


class TestPHPAuditReport:
    def test_by_severity_filter(self):
        vulns = [
            PHPVulnerability(VulnType.CMD_INJECT, Severity.CRITICAL, "a.php", 1, "", "", "", ""),
            PHPVulnerability(VulnType.FILE_INCLUDE, Severity.HIGH, "b.php", 2, "", "", "", ""),
            PHPVulnerability(VulnType.INFO_LEAK, Severity.INFO, "c.php", 3, "", "", "", ""),
        ]
        report = PHPAuditReport(files_analyzed=3, total_lines=100, vulnerabilities=vulns)
        high_only = report.by_severity(Severity.HIGH)
        assert len(high_only) == 2  # CRITICAL + HIGH

    def test_to_prompt_context(self):
        vulns = [
            PHPVulnerability(VulnType.CMD_INJECT, Severity.CRITICAL, "a.php", 1, "cmd", "system()", "sys", "hint"),
        ]
        report = PHPAuditReport(files_analyzed=1, total_lines=10, vulnerabilities=vulns, framework="ThinkPHP")
        ctx = report.to_prompt_context()
        assert "ThinkPHP" in ctx
        assert "cmd_inject" in ctx
