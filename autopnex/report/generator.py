"""Render StateFindings into Markdown + HTML reports.

The executive summary is produced by the LLM if available; otherwise we fall
back to a deterministic template-based summary so the pipeline still works.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import markdown as md
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..orchestrator.llm_client import LLMClient, LLMError
from ..state_machine.findings import StateFindings
from ..knowledge_base.vuln_patterns import SEVERITY_REMEDIATION
from ..knowledge_base.cwe_mapping import OWASP_TOP10_2021, auto_correlate


TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    def __init__(self, llm_client: Optional[LLMClient] = None, *, mode: str = "llm"):
        self.mode = mode
        self.llm = llm_client
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(disabled_extensions=("md", "j2")),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    # ------------------------------------------------------------------
    def render(self, findings: StateFindings) -> tuple[str, str]:
        """Return (markdown, html)."""
        summary = self._executive_summary(findings)

        # Auto-correlate CWE/OWASP for findings missing them
        for f in findings.findings:
            if not f.cwe_id and f.category:
                cwe = auto_correlate(f.category)
                if cwe.get("cwe_id") and not f.cwe_id:
                    f.cwe_id = cwe["cwe_id"]
                if cwe.get("owasp_category") and not f.owasp_category:
                    f.owasp_category = cwe["owasp_category"]
                if cwe.get("cvss_score") is not None and f.cvss_score is None:
                    f.cvss_score = cwe["cvss_score"]
                if cwe.get("cvss_vector") and not f.cvss_vector:
                    f.cvss_vector = cwe["cvss_vector"]

        # Build OWASP compliance summary from findings
        owasp_summary: dict[str, int] = {}
        for f in findings.findings:
            owasp = f.owasp_category
            if not owasp and f.category:
                cwe = auto_correlate(f.category)
                owasp = cwe.get("owasp_category")
            if owasp:
                owasp_summary[owasp] = owasp_summary.get(owasp, 0) + 1

        template = self.env.get_template("report.md.j2")
        markdown_text = template.render(
            findings=findings,
            mode=self.mode,
            executive_summary=summary,
            severity_sla=SEVERITY_REMEDIATION,
            owasp_summary=owasp_summary,
            owasp_descriptions=OWASP_TOP10_2021,
        )
        html_body = md.markdown(
            markdown_text,
            extensions=["tables", "fenced_code", "toc", "sane_lists"],
        )
        html = _HTML_SHELL.replace("{{body}}", html_body).replace(
            "{{title}}", f"AutoPenX Report — {findings.target}"
        )
        return markdown_text, html

    def save(self, findings: StateFindings, md_path: Path, html_path: Optional[Path] = None) -> tuple[Path, Optional[Path]]:
        md_text, html_text = self.render(findings)
        md_path = Path(md_path)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(md_text, encoding="utf-8")
        final_html: Optional[Path] = None
        if html_path is not None:
            html_path = Path(html_path)
            html_path.parent.mkdir(parents=True, exist_ok=True)
            html_path.write_text(html_text, encoding="utf-8")
            final_html = html_path
        return md_path, final_html

    # ------------------------------------------------------------------
    def _executive_summary(self, findings: StateFindings) -> str:
        # Always compute a deterministic baseline summary first.
        baseline = _baseline_summary(findings)
        if not self.llm or not self.llm.enabled:
            return baseline
        try:
            prompt = (
                "You are writing the executive summary of a penetration test report.\n"
                "Produce 3-6 concise sentences in Chinese summarising the target posture, "
                "key findings (by severity) and the most urgent remediation advice.\n\n"
                f"Target: {findings.target}\n"
                f"Open ports: {len(findings.open_ports)}; technologies: {findings.technologies};\n"
                f"Findings: {[f.to_dict() for f in findings.sorted_findings()[:20]]}\n"
            )
            resp = self.llm.chat(
                [
                    {"role": "system", "content": "You are a professional pentest report writer."},
                    {"role": "user", "content": prompt},
                ],
                tools=None,
                temperature=0.3,
                max_tokens=600,
            )
            content = (resp.get("content") or "").strip()
            return content or baseline
        except LLMError:
            return baseline
        except Exception:  # noqa: BLE001
            return baseline


def _baseline_summary(findings: StateFindings) -> str:
    counts: dict[str, int] = {}
    for f in findings.findings:
        counts[f.severity.upper()] = counts.get(f.severity.upper(), 0) + 1
    by_sev = ", ".join(f"{sev}: {n}" for sev, n in sorted(counts.items(), key=lambda x: -["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index(x[0]) if x[0] in ["INFO","LOW","MEDIUM","HIGH","CRITICAL"] else 0)) or "无明显漏洞"
    tech = ", ".join(findings.technologies[:8]) or "未知"
    return (
        f"AutoPenX 在目标 `{findings.target}` 上共执行了 {len(findings.tool_invocations)} 次工具调用，"
        f"识别到 {len(findings.open_ports)} 个开放端口、{len(findings.subdomains)} 个子域名，"
        f"识别到的技术栈包括：{tech}。"
        f"本次测试共记录 {len(findings.findings)} 项发现（{by_sev}），"
        "建议优先处理 HIGH/CRITICAL 级别漏洞，并补齐缺失的安全响应头与敏感文件泄露问题。"
    )


_HTML_SHELL = """<!doctype html>
<html lang=\"zh-CN\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{{title}}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif; max-width: 960px; margin: 0 auto; padding: 32px; color: #1f2937; background: #f9fafb; }
    h1, h2, h3, h4 { color: #0f172a; }
    h1 { border-bottom: 2px solid #0ea5e9; padding-bottom: 8px; }
    h2 { border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; margin-top: 32px; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0; background: #fff; }
    th, td { border: 1px solid #e2e8f0; padding: 6px 10px; font-size: 14px; text-align: left; vertical-align: top; }
    th { background: #f1f5f9; }
    code { background: #f1f5f9; padding: 1px 6px; border-radius: 4px; font-size: 13px; }
    pre { background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; }
    pre code { background: transparent; color: inherit; padding: 0; }
    blockquote { border-left: 4px solid #f59e0b; background: #fffbeb; padding: 8px 12px; color: #92400e; }
    .severity-CRITICAL, .severity-HIGH { color: #b91c1c; font-weight: 700; }
    .severity-MEDIUM { color: #b45309; font-weight: 700; }
    .severity-LOW { color: #047857; }
  </style>
</head>
<body>
{{body}}
</body>
</html>
"""
