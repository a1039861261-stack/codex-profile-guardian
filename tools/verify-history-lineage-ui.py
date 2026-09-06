"""Cloud-only browser acceptance: paginated lineage preserved and missing sources blocked."""
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
from tests.test_history_lineage import PaginatedHistoryTests


def verify(browser, width, height):
    fixture = PaginatedHistoryTests()
    fixture.setUp()
    server = context = None
    try:
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
        console = []
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        page.on("console", lambda message: console.append(message.type)
                if message.type in ("warning", "error") else None)
        with patch.object(fixture.service, "update_status", return_value={
            "state": "up_to_date", "current_version": "1.10.8", "latest_version": "1.10.8",
        }):
            before = fixture.hashes()
            page.goto(origin, wait_until="networkidle")
            page.get_by_role("button", name="聊天保护", exact=True).click()
            page.set_viewport_size({"width": width, "height": height})
            expect(page.get_by_role("heading", name="分页历史依赖检查通过", exact=True)).to_be_visible()
            expect(page.get_by_text("已保留 2 个关联历史文件", exact=False)).to_be_visible()
            expect(page.get_by_role("button", name="全量冷备并隔离", exact=True)).to_have_count(0)
            expect(page.get_by_role("button", name="选择保留副本", exact=True)).to_have_count(0)
            assert fixture.hashes() == before
            saved_source = fixture.original.read_bytes()
            fixture.original.unlink()
            missing_before = fixture.hashes()
            page.get_by_role("button", name="刷新检测", exact=True).click()
            expect(page.get_by_role("heading", name="聊天历史依赖异常，已停止切换", exact=True)).to_be_visible()
            expect(page.get_by_text("1 个源历史缺失", exact=True)).to_be_visible()
            expect(page.get_by_role("button", name="打开隔离库", exact=True)).to_be_enabled()
            response = context.request.post(
                origin + "/api/protection/conflicts/isolate", data={"confirmed": True}, headers={"Origin": origin},
            )
            assert response.status == 409, response.status
            assert response.json()["error"]["code"] == "history_lineage_invalid", response.json()
            assert fixture.hashes() == missing_before
            assert page.evaluate("document.documentElement.scrollWidth") <= width + 1
            screenshots = ROOT / "output" / "playwright"
            screenshots.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(screenshots / f"history-lineage-missing-{width}.png"))
            fixture.original.write_bytes(saved_source)
            page.get_by_role("button", name="刷新检测", exact=True).click()
            expect(page.get_by_role("heading", name="分页历史依赖检查通过", exact=True)).to_be_visible()
            assert fixture.hashes() == before
            assert not errors and not console and not external
            return {
                "viewport": f"{width}x{height}", "immutable_rollouts_preserved": True,
                "missing_source_visible": True, "blocked_http_status": response.status,
                "original_source_restore_rechecked": True, "private_data_used": False,
                "javascript_errors": len(errors), "unexpected_console_issues": len(console),
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
        results = [verify(browser, width, height) for width, height in ((1440, 960), (390, 844))]
        print(json.dumps({"history_lineage_ui": results, "private_data_used": False}, ensure_ascii=False), flush=True)
    finally:
        browser.close()
