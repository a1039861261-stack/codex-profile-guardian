"""Cloud-only switch-dialog acceptance; all data and failures are synthetic."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
    raise SystemExit("This acceptance runs only on the GitHub-hosted Windows runner.")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from playwright.sync_api import expect, sync_playwright
from backend.guardian import APP_VERSION, GuardianPublicError
from backend.server import start_server
from tests.test_guardian import GuardianServiceTests


def verify(browser, width, height):
    fixture = GuardianServiceTests()
    fixture.setUp()
    server = context = None
    try:
        profile = fixture.service.create_api_profile(
            "关闭验证账号", "https://api.example.invalid/v1", "fixture-key", "gpt-5",
        )
        before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in fixture.codex.rglob("*") if p.is_file()}
        server = start_server(fixture.service, ROOT / "dist", "127.0.0.1", 0)
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        context = browser.new_context(viewport={"width": 1440, "height": 960})
        external = []
        def local_only(route):
            if route.request.url.startswith(origin + "/"):
                route.continue_()
            else:
                external.append(route.request.url.split("?", 1)[0])
                route.abort()
        context.route("**/*", local_only)
        page = context.new_page()
        page.set_default_timeout(30000)
        errors = []
        console_issues = []
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        def console_message(message):
            if message.type in ("warning", "error"):
                if message.type == "error" and "Failed to load resource" in message.text and "409" in message.text:
                    return
                console_issues.append(message.type)
        page.on("console", console_message)
        with patch.object(fixture.service, "update_status", return_value={
            "state": "up_to_date", "current_version": APP_VERSION, "latest_version": APP_VERSION,
        }):
            page.goto(origin, wait_until="networkidle")
            page.get_by_role("button", name="设置", exact=True).click()
            expect(page.get_by_text("直接强制退出 Codex，无需等待正常关闭；有进行中任务时停止切换", exact=True)).to_be_visible()
            page.get_by_role("button", name="账号", exact=True).click()
            page.set_viewport_size({"width": width, "height": height})
            page.locator(".profile-card").filter(has_text=profile["name"]).get_by_role("button", name="安全切换", exact=True).click()
            dialog = page.get_by_role("dialog", name="切换到 关闭验证账号？", exact=True)
            expect(dialog).to_be_visible()
            expect(dialog).to_contain_text("将直接强制结束 Codex 后台进程")
            expect(dialog).not_to_contain_text("先正常关闭")
            expect(dialog).not_to_contain_text("30 秒")
            expect(dialog.get_by_role("button", name="安全切换", exact=True)).to_be_enabled()
            geometry = dialog.evaluate("""element => {
                const r = element.getBoundingClientRect();
                return {left:r.left,right:r.right,bottom:r.bottom,
                        pageWidth:document.documentElement.scrollWidth};
            }""")
            assert geometry["left"] >= -1 and geometry["right"] <= width + 1, geometry
            assert geometry["bottom"] <= height + 1 and geometry["pageWidth"] <= width + 1, geometry
            screenshots = ROOT / "output" / "playwright"
            screenshots.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(screenshots / f"codex-close-confirm-{width}.png"))
            report = {"reason": "force_exit_timeout", "force_attempted": True, "forced_count": 1}
            failure = GuardianPublicError(
                "codex_close_incomplete", fixture.service._codex_close_failure_message(report),
                details={"close": report}, retryable=True,
            )
            with patch.object(fixture.service, "_ensure_codex_closed", side_effect=failure):
                with page.expect_response(lambda r: r.url.endswith("/switch") and r.request.method == "POST") as submitted:
                    dialog.get_by_role("button", name="安全切换", exact=True).click()
                assert submitted.value.status == 409
                expect(page.locator(".toast")).to_contain_text("已尝试结束后台进程")
                expect(page.locator(".toast")).to_contain_text("未开始修改账号或聊天文件")
                expect(dialog).to_be_visible()
                expect(dialog.get_by_role("button", name="安全切换", exact=True)).to_be_enabled()
                page.screenshot(path=str(screenshots / f"codex-close-blocked-{width}.png"))
            dialog.get_by_role("button", name="取消", exact=True).click()
            expect(page.get_by_role("dialog")).to_have_count(0)
        after = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in fixture.codex.rglob("*") if p.is_file()}
        assert before == after
        assert not errors and not console_issues and not external
        return {"viewport": f"{width}x{height}", "direct_force_disclosed": True, "grace_period": False,
                "failed_close_http": 409, "account_and_history_unchanged": True,
                "retry_and_cancel_available": True, "javascript_errors": 0,
                "unexpected_console_issues": 0, "horizontal_overflow": False,
                "navigation_uses_desktop": width < 680}
    finally:
        if context:
            context.close()
        if server:
            server.shutdown()
            server.server_close()
        fixture.tearDown()


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    try:
        for width, height in ((1440, 960), (390, 844)):
            print(json.dumps({"codex_close_ui": verify(browser, width, height),
                              "private_data_used": False}, ensure_ascii=False), flush=True)
    finally:
        browser.close()
