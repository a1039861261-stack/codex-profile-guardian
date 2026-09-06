"""Cloud-only browser acceptance of official Codex trigger compatibility."""
from __future__ import annotations

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
from backend.server import start_server
from tests.test_history_trigger_compatibility import HistoryTriggerCompatibilityTests


def verify(browser, width: int, height: int) -> dict:
    fixture = HistoryTriggerCompatibilityTests()
    fixture.setUp()
    server = None
    context = None
    try:
        fixture.manual_request()
        before_database = fixture.snapshot()
        before_files = fixture.non_database_hashes()
        server = start_server(fixture.service, ROOT / "dist", "127.0.0.1", 0)
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        context = browser.new_context(viewport={
            "width": 1440 if width < 680 else width,
            "height": 960 if width < 680 else height,
        })
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
        page.on("console", lambda message: console_issues.append(message.type)
                if message.type in ("warning", "error") else None)
        with patch.object(
            fixture.service, "update_status",
            return_value={"state": "up_to_date", "current_version": "1.10.7", "latest_version": "1.10.7"},
        ):
            page.goto(origin, wait_until="networkidle")
            page.get_by_role("button", name="聊天保护", exact=True).click()
            expect(page.get_by_role("button", name="选择保留副本", exact=True)).to_be_enabled()
            if width < 680:
                page.set_viewport_size({"width": width, "height": height})
            page.get_by_role("button", name="选择保留副本", exact=True).click()
            page.locator(".conflict-copy-option").filter(has_text="归档目录").locator('input[type="radio"]').check()
            submit = page.get_by_role("button", name="确认冷备并处理", exact=True)
            expect(submit).to_be_enabled()
            with page.expect_response(
                lambda response: response.url.endswith("/api/protection/conflicts/isolate")
                and response.request.method == "POST"
            ) as submitted:
                submit.click()
            response = submitted.value
            assert response.status == 200, response.status
            result = response.json()["data"]
            assert result["resolved"] == 1 and result["quarantined_files"] == 1
            fixture.assert_success_preserved(before_database, result, changed=True)
            assert fixture.non_database_hashes() == {
                path: digest for path, digest in before_files.items()
                if path != fixture.active_path.relative_to(fixture.codex).as_posix()
            }
            toast = page.locator(".toast")
            expect(toast).to_contain_text("已完成全量冷备")
            expect(toast).to_contain_text("所有原始副本均可恢复")
            expect(page.get_by_role("button", name="确认冷备并处理", exact=True)).to_have_count(0)
            geometry = toast.evaluate("""element => {
                const r = element.getBoundingClientRect();
                const text = element.querySelector('strong');
                return {
                    left: r.left, right: r.right, bottom: r.bottom,
                    textWidth: text.clientWidth, textScrollWidth: text.scrollWidth,
                    pageWidth: document.documentElement.scrollWidth
                };
            }""")
            assert geometry["left"] >= -1 and geometry["right"] <= width + 1, geometry
            assert geometry["bottom"] <= height + 1, geometry
            assert geometry["textScrollWidth"] <= geometry["textWidth"] + 1, geometry
            assert geometry["pageWidth"] <= width + 1, geometry
            screenshots = ROOT / "output" / "playwright"
            screenshots.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(screenshots / f"conflict-official-triggers-{width}.png"))
            page.locator(".toast button").click()
            if width < 680:
                page.set_viewport_size({"width": 1440, "height": 960})
            page.get_by_role("button", name="日志", exact=True).click()
            if width < 680:
                page.set_viewport_size({"width": width, "height": height})
            expect(page.get_by_text("已按明确选择保留聊天副本，并隔离 1 个正文分支副本", exact=False)).to_be_visible()
            assert page.evaluate("document.documentElement.scrollWidth") <= width + 1
            page.screenshot(path=str(screenshots / f"conflict-official-triggers-log-{width}.png"))
        assert not errors, errors
        assert not console_issues, console_issues
        assert not external, "Unexpected external browser requests"
        trigger_count = sum(row[0] == "trigger" and row[2] == "threads" for row in before_database["schema"])
        assert trigger_count == 5
        return {
            "viewport": f"{width}x{height}", "http_status": response.status,
            "official_triggers_retained": trigger_count,
            "database_rows_repointed": result["database_rows_repointed"],
            "timestamps_provider_other_columns_unchanged": True,
            "index_and_retained_files_unchanged": True,
            "cold_backup_verified": True, "original_copies_recoverable": True,
            "success_visible_in_toast_and_log": True,
            "javascript_errors": len(errors), "unexpected_console_issues": len(console_issues),
            "horizontal_overflow": False, "navigation_uses_desktop": width < 680,
        }
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
        results = []
        for width, height in ((1440, 960), (390, 844)):
            result = verify(browser, width, height)
            results.append(result)
            print(json.dumps({"completed_viewport": result}, ensure_ascii=False), flush=True)
    finally:
        browser.close()
print(json.dumps({"history_official_trigger_ui": results, "private_data_used": False}, ensure_ascii=False))
