"""Browser login helper - opens visible browser for manual login, captures session cookies.

Flow:
1. Launch Playwright Chromium in HEADED mode (visible window)
2. Navigate to the target login URL
3. Display instructions to the user
4. Wait until the user completes login (detect URL change or cookie change)
5. Capture all cookies from the browser context
6. Close browser and return cookies
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..base import BaseTool, ToolResult, register


async def browser_login(target_url: str, wait_timeout: int = 300) -> dict:
    """Open a headed browser for manual login and capture session cookies.

    Args:
        target_url: The login page URL to navigate to.
        wait_timeout: Maximum seconds to wait for user to complete login (default 300).

    Returns:
        dict with keys: success, cookies, session_cookie, all_headers
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "success": False,
            "cookies": [],
            "session_cookie": "",
            "all_headers": {},
            "error": (
                "Playwright is not installed. "
                "Run: pip install playwright && playwright install chromium"
            ),
        }

    initial_url = target_url
    initial_path = urlparse(target_url).path

    print(f"\n{'='*60}")
    print("🌐 浏览器登录助手 (Browser Login Helper)")
    print(f"{'='*60}")
    print(f"目标: {target_url}")
    print("请在弹出的浏览器窗口中手动完成登录。")
    print("登录完成后浏览器将自动关闭并捕获 Cookie。")
    print(f"超时时间: {wait_timeout} 秒")
    print(f"{'='*60}\n")

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=False,
                args=["--disable-blink-features=AutomationControlled"],
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
            )
            page = await context.new_page()

            # Navigate to target
            await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)

            # Capture initial cookies for comparison
            initial_cookies = await context.cookies()
            initial_cookie_names = {c["name"] for c in initial_cookies}

            # Poll for login detection
            elapsed = 0
            poll_interval = 2  # seconds
            login_detected = False

            while elapsed < wait_timeout:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

                # Check if browser/page was closed by user
                try:
                    current_url = page.url
                except Exception:
                    # Page or browser closed by user
                    login_detected = True
                    break

                # Signal 1: URL changed away from login page
                current_path = urlparse(current_url).path
                if current_path != initial_path and current_url != initial_url:
                    # URL changed - likely redirected after login
                    login_detected = True
                    break

                # Signal 2: New cookies appeared (session cookies set)
                current_cookies = await context.cookies()
                current_cookie_names = {c["name"] for c in current_cookies}
                new_cookies = current_cookie_names - initial_cookie_names
                if new_cookies:
                    # New cookies appeared - login likely completed
                    # Wait a moment for any additional cookies/redirects
                    await asyncio.sleep(1)
                    login_detected = True
                    break

            # Capture final cookies
            try:
                all_cookies = await context.cookies()
            except Exception:
                all_cookies = []

            # Close browser
            try:
                await browser.close()
            except Exception:
                pass

            if not all_cookies:
                return {
                    "success": False,
                    "cookies": [],
                    "session_cookie": "",
                    "all_headers": {},
                    "error": "No cookies captured. Login may not have completed.",
                }

            # Find session cookie (common session cookie names)
            session_cookie_names = [
                "sessionid", "session", "PHPSESSID", "JSESSIONID",
                "connect.sid", "sid", "token", "auth_token",
                "access_token", "_session", "sess", "laravel_session",
            ]
            session_cookie = ""
            for cookie in all_cookies:
                if cookie["name"].lower() in [n.lower() for n in session_cookie_names]:
                    session_cookie = f"{cookie['name']}={cookie['value']}"
                    break

            # If no known session cookie found, use the newest/largest cookie
            if not session_cookie and all_cookies:
                # Pick the cookie with the longest value (likely the session token)
                longest = max(all_cookies, key=lambda c: len(c.get("value", "")))
                session_cookie = f"{longest['name']}={longest['value']}"

            # Build headers
            cookie_header = cookies_to_header(all_cookies)
            all_headers = {"Cookie": cookie_header}

            return {
                "success": True,
                "cookies": all_cookies,
                "session_cookie": session_cookie,
                "all_headers": all_headers,
                "cookie_count": len(all_cookies),
                "login_detected": login_detected,
                "elapsed_seconds": elapsed,
            }

    except Exception as exc:
        return {
            "success": False,
            "cookies": [],
            "session_cookie": "",
            "all_headers": {},
            "error": f"Browser login failed: {exc}",
        }


def cookies_to_header(cookies: List[dict]) -> str:
    """Convert a list of cookie dicts to a Cookie header string.

    Args:
        cookies: List of cookie dicts (as returned by Playwright context.cookies()).

    Returns:
        Cookie header string in format: "name=value; name2=value2"
    """
    if not cookies:
        return ""
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies)


@register
class BrowserLoginTool(BaseTool):
    """Tool that opens a visible browser for manual login and captures cookies."""

    category = "browser"

    @property
    def name(self) -> str:
        return "browser_login"

    @property
    def description(self) -> str:
        return (
            "Opens a visible Chromium browser window for manual login. "
            "The user logs in interactively, and the tool captures all session cookies "
            "for use in subsequent automated requests. Detects login completion via "
            "URL change or new cookie appearance."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target login page URL.",
                },
                "wait_timeout": {
                    "type": "number",
                    "description": "Maximum seconds to wait for login (default: 300).",
                },
            },
            "required": ["target"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        target = kwargs.get("target", "")
        wait_timeout = int(kwargs.get("wait_timeout", 300))

        if not target:
            return ToolResult(
                False, self.name, "target URL is required", error="missing_args"
            )

        try:
            result = asyncio.run(browser_login(target, wait_timeout))
        except RuntimeError:
            # If there's already a running event loop, use nest_asyncio
            try:
                import nest_asyncio
                nest_asyncio.apply()
                result = asyncio.run(browser_login(target, wait_timeout))
            except ImportError:
                # Try with get_event_loop
                loop = asyncio.get_event_loop()
                result = loop.run_until_complete(browser_login(target, wait_timeout))

        if result.get("success"):
            cookie_count = result.get("cookie_count", len(result.get("cookies", [])))
            return ToolResult(
                success=True,
                tool=self.name,
                summary=f"Login captured successfully. {cookie_count} cookies obtained.",
                raw_output=result.get("session_cookie", ""),
                parsed_data=result,
            )
        else:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=f"Login failed: {result.get('error', 'unknown')}",
                error=result.get("error", "unknown"),
                parsed_data=result,
            )
