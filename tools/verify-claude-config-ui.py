"""Cloud-only Claude configuration acceptance; no real credentials or upstream calls."""
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
from backend.claude_desktop import ClaudeDesktopIntegration
from backend.guardian import APP_VERSION
from backend.server import start_server
from tests.test_guardian import GuardianServiceTests


def verify(browser, width, height):
    fixture = GuardianServiceTests()
    fixture.setUp()
    server = context = None
    try:
        fixture.service.claude_desktop = ClaudeDesktopIntegration(
            local_appdata=fixture.data / "synthetic-local-appdata",
            data_dir=fixture.data / "synthetic-claude",
            cc_switch_home=fixture.data / "unused-cc",
            protect=lambda value: b"fixture:" + value,
            unprotect=lambda value: value.removeprefix(b"fixture:"),
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
        console = []
        page.on("pageerror", lambda error: errors.append(type(error).__name__))
        page.on("console", lambda message: console.append(message.type)
                if message.type in ("warning", "error") else None)
        with patch.object(fixture.service, "update_status", return_value={
            "state": "up_to_date", "current_version": APP_VERSION, "latest_version": APP_VERSION,
        }):
            page.goto(origin, wait_until="networkidle")
            page.get_by_role("tab", name="Claude", exact=True).click()
            page.set_viewport_size({"width": width, "height": height})
            page.get_by_role("button", name="添加供应商", exact=True).click()
            dialog = page.get_by_role("dialog", name="添加 Claude 供应商", exact=True)
            expect(dialog).to_contain_text("末尾的 /v1 会自动去除")
            dialog.get_by_label("供应商名称", exact=True).fill("Claude fixture")
            dialog.locator("label").filter(has_text="Anthropic 接口地址").locator("input").fill("https://anthropic.example.invalid/v1")
            dialog.get_by_label("API Key", exact=True).fill("synthetic-claude-key")
            dialog.get_by_role("button", name="保存", exact=True).click()
            expect(dialog).to_have_count(0)
            card = page.locator(".claude-provider-card").filter(has_text="Claude fixture")
            expect(card.locator("code")).to_have_text("https://anthropic.example.invalid")
            card.get_by_role("button", name="启用", exact=True).click()
            apply_dialog = page.get_by_role("dialog", name="启用 Claude fixture？", exact=True)
            apply_dialog.get_by_role("button", name="确认启用", exact=True).click()
            restart = page.get_by_role("dialog", name="重启 Claude Desktop？", exact=True)
            expect(restart).to_be_visible()
            restart.get_by_role("button", name="取消", exact=True).click()
            expect(page.locator(".claude-summary")).to_contain_text("配置已启用 · 接口待验证")
            expect(page.locator(".claude-summary")).not_to_contain_text("连接正常")
            expect(page.locator(".claude-summary")).not_to_contain_text("无需处理")
            expect(card.get_by_role("button", name="重新应用", exact=True)).to_be_enabled()
            expect(page.get_by_text("未手动指定模型。Claude Desktop 需要从供应商读取模型列表；若列表为空，请检查接口地址与密钥。", exact=True)).to_be_visible()
            status = fixture.service.claude_desktop_status()
            assert not status["connection_verified"] and not status["model_discovery_verified"]
            deployed = json.loads(fixture.service.claude_desktop.profile_path.read_text(encoding="utf-8"))
            assert deployed["inferenceGatewayBaseUrl"] + "/v1/models" == "https://anthropic.example.invalid/v1/models"
            assert len(list(fixture.service.claude_desktop.backups_dir.glob("*.dpapi"))) == 1
            card.get_by_role("button", name="编辑", exact=True).click()
            edit_dialog = page.get_by_role("dialog", name="编辑 Claude fixture", exact=True)
            edit_dialog.locator("label").filter(has_text="Anthropic 接口地址").locator("input").fill("https://anthropic.example.invalid/gateway/v1")
            edit_dialog.get_by_role("button", name="保存", exact=True).click()
            expect(edit_dialog).to_have_count(0)
            expect(page.locator(".toast")).to_contain_text("请重新应用并重启 Claude Desktop")
            assert json.loads(fixture.service.claude_desktop.profile_path.read_text(encoding="utf-8")) == deployed
            card.get_by_role("button", name="重新应用", exact=True).click()
            page.get_by_role("dialog", name="启用 Claude fixture？", exact=True).get_by_role("button", name="确认启用", exact=True).click()
            restart = page.get_by_role("dialog", name="重启 Claude Desktop？", exact=True)
            expect(restart).to_be_visible()
            restart.get_by_role("button", name="取消", exact=True).click()
            reapplied = json.loads(fixture.service.claude_desktop.profile_path.read_text(encoding="utf-8"))
            assert reapplied["inferenceGatewayBaseUrl"] == "https://anthropic.example.invalid/gateway"
            assert reapplied["inferenceGatewayApiKey"] == deployed["inferenceGatewayApiKey"]
            assert len(list(fixture.service.claude_desktop.backups_dir.glob("*.dpapi"))) == 2
            assert page.evaluate("document.documentElement.scrollWidth") <= width + 1
            screenshots = ROOT / "output" / "playwright"
            screenshots.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(screenshots / f"claude-config-unverified-{width}.png"))
        after = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in fixture.codex.rglob("*") if p.is_file()}
        assert before == after
        assert not errors and not console and not external
        return {"viewport": f"{width}x{height}", "api_root_normalized": True,
                "unverified_status_visible": True, "reapply_available": True,
                "protected_rollback_created": True, "edit_reapply_verified": True, "codex_files_unchanged": True,
                "javascript_errors": 0, "console_issues": 0, "horizontal_overflow": False}
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
            print(json.dumps({"claude_config_ui": verify(browser, width, height),
                              "private_data_used": False}, ensure_ascii=False), flush=True)
    finally:
        browser.close()
