"""Playwright-based browser automation for SPA testing, XSS detection, and DOM analysis.

Inspired by Shannon's shannon-browser tool. Enables testing of JavaScript-heavy
applications (React, Angular, Vue) that cannot be tested with simple HTTP requests.
"""
from __future__ import annotations

import asyncio
import textwrap
from typing import Any, Dict

from ..base import BaseTool, ToolResult, register


@register
class BrowserTestTool(BaseTool):
    category = "browser"

    @property
    def name(self) -> str:
        return "browser_test"

    @property
    def description(self) -> str:
        return (
            "Playwright browser automation for testing JavaScript SPAs (React, Angular, Vue). "
            "Execute custom Playwright scripts for XSS detection, DOM analysis, "
            "cookie/localStorage inspection, form interaction, and navigation testing. "
            "The script has access to 'page' (Playwright Page) and 'context' objects."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to test.",
                },
                "script": {
                    "type": "string",
                    "description": (
                        "Python Playwright script to execute. Has access to 'page' (Playwright Page), "
                        "'context' (BrowserContext), and 'browser' objects. Use print() for output.\n"
                        "Example:\n"
                        "await page.goto(target)\n"
                        "title = await page.title()\n"
                        "print(f'Title: {title}')"
                    ),
                },
                "timeout": {
                    "type": "number",
                    "description": "Timeout in milliseconds (default: 30000).",
                },
            },
            "required": ["target", "script"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = kwargs.get("target", "")
        script = kwargs.get("script", "")
        timeout = kwargs.get("timeout", 30000)

        if not target or not script:
            return ToolResult(False, self.name, "target and script required", error="missing_args")

        try:
            result = asyncio.run(self._execute_browser(target, script, timeout))
            return result
        except RuntimeError:
            # If there's already a running event loop, use nest_asyncio
            import nest_asyncio
            nest_asyncio.apply()
            result = asyncio.run(self._execute_browser(target, script, timeout))
            return result
        except ImportError:
            return ToolResult(
                False, self.name,
                "playwright not installed. Run: pip install playwright && playwright install chromium",
                error="missing_dependency",
            )
        except Exception as exc:
            return ToolResult(False, self.name, f"Browser test failed: {exc}", error=str(exc))

    async def _execute_browser(self, target: str, script: str, timeout: int) -> ToolResult:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return ToolResult(
                False, self.name,
                "playwright not installed. Run: pip install playwright && playwright install chromium",
                error="missing_dependency",
            )

        output_lines = []
        error_lines = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            try:
                # Wrap user script in async function with output capture
                wrapped_script = self._build_script(target, script)

                # Execute with timeout
                exec_result = await asyncio.wait_for(
                    self._run_script(page, context, browser, wrapped_script, output_lines, error_lines),
                    timeout=timeout / 1000,
                )

                success = not bool(error_lines)
                summary = f"Browser test on {target}: {len(output_lines)} output lines"
                if error_lines:
                    summary += f", {len(error_lines)} errors"

                return ToolResult(
                    success=success,
                    tool=self.name,
                    summary=summary,
                    raw_output="\n".join(output_lines),
                    parsed_data={
                        "target": target,
                        "output": output_lines,
                        "errors": error_lines,
                        "output_count": len(output_lines),
                    },
                    error="\n".join(error_lines) if error_lines else None,
                )
            except asyncio.TimeoutError:
                return ToolResult(
                    False, self.name,
                    f"Browser test timed out after {timeout}ms",
                    error="timeout",
                    raw_output="\n".join(output_lines),
                )
            except Exception as exc:
                return ToolResult(
                    False, self.name,
                    f"Browser test error: {exc}",
                    error=str(exc),
                    raw_output="\n".join(output_lines),
                )
            finally:
                await browser.close()

    async def _run_script(self, page, context, browser, script: str, output_lines, error_lines):
        """Execute the user script with page/context/browser in scope."""
        # Capture print output
        import io
        import sys

        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()
        try:
            exec_globals = {
                "page": page,
                "context": context,
                "browser": browser,
                "target": None,  # Set by script preamble
                "asyncio": asyncio,
            }
            exec_locals = {}
            compiled = compile(script, "<browser_test>", "exec")

            # The script uses top-level await which won't work in exec.
            # Instead, wrap in an async function and run it.
            async def _run():
                local_vars = {
                    "page": page,
                    "context": context,
                    "browser": browser,
                }
                func_code = (
                    "async def __browser_test_func__(page, context, browser):\n"
                    + self._indent_script(script, 4)
                )
                exec(compile(func_code, "<browser_test>", "exec"), local_vars)
                await local_vars["__browser_test_func__"](page, context, browser)

            await _run()
        except Exception as exc:
            error_lines.append(str(exc))
        finally:
            sys.stdout = old_stdout
            captured_output = captured.getvalue()
            if captured_output:
                output_lines.extend(line for line in captured_output.split("\n") if line.strip())

    def _build_script(self, target: str, user_script: str) -> str:
        """Build the complete script with target variable injected."""
        return f'target = "{target}"\n{user_script}'

    def _indent_script(self, script: str, spaces: int) -> str:
        """Indent user script while preserving relative indentation."""
        lines = script.split("\n")
        non_empty = [l for l in lines if l.strip()]
        if not non_empty:
            return ""
        min_indent = min(len(l) - len(l.lstrip()) for l in non_empty)
        indent = " " * spaces
        return "\n".join(
            indent + l[min_indent:] if l.strip() else ""
            for l in lines
        )
