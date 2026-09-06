"""Cloud-only real-browser acceptance using synthetic conflict fixtures."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
    raise SystemExit("This acceptance runs only on the GitHub-hosted Windows runner.")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from playwright.sync_api import expect, sync_playwright
from backend.server import start_server
from tests.test_history_conflict_diagnostics import HistoryConflictDiagnosticsTests


def verify(browser, width: int, height: int) -> dict:
    fixture = HistoryConflictDiagnosticsTests()
    fixture.setUp()
    server = None
    context = None
    try:
        with sqlite3.connect(fixture.codex / "state_5.sqlite") as db:
            db.execute(
                "UPDATE threads SET rollout_path=? WHERE id=?",
                (str(fixture.codex / "sessions" / "missing-fixture.jsonl"), fixture.active_id),
            )
        db.close()
        fixture.add_trigger()
        before = fixture.protected_hashes()
        server = start_server(fixture.service, ROOT / "dist", "127.0.0.1", 0)
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        context = browser.new_context(viewport={"width": width, "height": height})
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
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        with patch.object(
            fixture.service, "update_status",
            return_value={"state": "up_to_date", "current_version": "1.10.5", "latest_version": "1.10.5"},
        ):
            page.goto(origin, wait_until="networkidle")
            page.get_by_role("button", name="聊天保护", exact=True).click()
            page.get_by_role("button", name="选择保留副本", exact=True).click()
            # Choose explicitly, matching the stale-database-path customer flow.
            page.locator('input[type="radio"]').first.check()
            submit = page.get_by_role("button", name="确认冷备并处理", exact=True)
            expect(submit).to_be_enabled()
            with page.expect_response(
                lambda response: response.url.endswith("/api/protection/conflicts/isolate")
                and response.request.method == "POST"
            ) as submitted:
                submit.click()
            response = submitted.value
            assert response.status == 409, response.status
            failure = response.json()["error"]
            assert failure["code"] == "history_conflict_database_triggers_present"
            assert failure["details"]["cold_backup_complete"] is True
            assert failure["details"]["history_writes_started"] is False
            toast = page.locator(".toast")
            expect(toast).to_contain_text("threads 触发器")
            expect(toast).to_contain_text("完整冷备已完成并保留")
            expect(toast).not_to_contain_text("请求未完成")
            geometry = toast.evaluate("""element => {
                const r = element.getBoundingClientRect();
                const text = element.querySelector('strong');
                return {
                    left: r.left, right: r.right, bottom: r.bottom,
                    viewportWidth: innerWidth, viewportHeight: innerHeight,
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
            page.screenshot(path=str(screenshots / f"conflict-diagnostic-{width}.png"))
            # Dismiss only the notification and modal, never retry repair.
            page.locator(".toast button").click()
            page.get_by_role("button", name="取消", exact=True).click()
            page.get_by_role("button", name="操作日志", exact=True).click()
            expect(page.get_by_text("history_conflict_database_triggers_present", exact=False)).to_be_visible()
            expect(page.get_by_text(failure["details"]["diagnostic_id"], exact=False)).to_be_visible()
            page.screenshot(path=str(screenshots / f"conflict-diagnostic-log-{width}.png"))
        assert not errors, errors
        assert not external, "Unexpected external browser requests"
        assert fixture.protected_hashes() == before, "Synthetic protected history changed"
        return {
            "viewport": f"{width}x{height}", "http_status": response.status,
            "code": failure["code"], "cold_backup_complete": True,
            "history_unchanged": True, "error_visible_in_toast_and_log": True,
            "javascript_errors": len(errors), "horizontal_overflow": False,
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
        results = [verify(browser, 1440, 960), verify(browser, 390, 844)]
    finally:
        browser.close()
print(json.dumps({"history_conflict_ui": results, "private_data_used": False}, ensure_ascii=False))
