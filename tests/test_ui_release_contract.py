from pathlib import Path
import re
import unittest


class UIReleaseContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project = Path(__file__).resolve().parents[1]

    def test_main_document_uses_product_title(self) -> None:
        document = (self.project / "index.html").read_text(encoding="utf-8")
        self.assertIn("<title>Codex Profile Guardian</title>", document)
        self.assertNotIn("<title>Prototype</title>", document)

    def test_mobile_main_actions_keep_44_pixel_touch_target(self) -> None:
        stylesheet = (self.project / "src" / "styles.css").read_text(encoding="utf-8")
        mobile = stylesheet.split("@media (max-width: 680px)", 2)[2]
        self.assertIn(
            ".app-shell.is-gray .main-area .button { min-height: 44px; }",
            mobile,
        )
        self.assertIn(
            ".app-shell.is-gray .top-refresh { width: 44px; height: 44px; }",
            mobile,
        )

        failover = (self.project / "src" / "failover" / "failover.css").read_text(
            encoding="utf-8"
        )
        failover_mobile = failover.split("@media (max-width: 760px)", 1)[1]
        self.assertIn(
            ".fo-icon-button, .fo-swap-button { width: 44px; height: 44px; }",
            failover_mobile,
        )

    def test_gray_theme_keeps_buttons_and_current_cards_distinct(self) -> None:
        stylesheet = (self.project / "src" / "styles.css").read_text(encoding="utf-8")
        self.assertIn(
            ".app-shell.is-gray .button { color: #25282d; border-color: #c5cad1; background: #ffffff;",
            stylesheet,
        )
        self.assertIn(
            ".app-shell.is-gray .button-primary { color: #ffffff; border-color: #245da9; background: #2f6fc9; }",
            stylesheet,
        )
        self.assertIn(
            ".app-shell.is-gray .button-primary:disabled { color: #737982; border-color: #cfd4da; background: #e7e9ec; opacity: 1; }",
            stylesheet,
        )
        self.assertIn(".app-shell.is-gray .quick-profile.is-current {", stylesheet)
        self.assertIn("border-color: #2563eb;", stylesheet)
        self.assertIn("background: #e5efff;", stylesheet)
        self.assertIn("opacity: 1;", stylesheet)

    def test_current_quota_ui_uses_weekly_and_reset_cards_only(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        self.assertNotIn("five_hour", application)
        self.assertIn('<QuotaMeter label="每周" windowData={weekly} />', application)
        self.assertIn("<ResetCardBalance data={resetCards} />", application)
        self.assertIn("window.setInterval(syncVisibleQuota, 60_000)", application)

    def test_account_cards_hide_current_delete_and_pad_quota_content(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        stylesheet = (self.project / "src" / "styles.css").read_text(encoding="utf-8")
        profile_card = application.split("function ProfileCard(", 1)[1].split(
            "function Overview(", 1
        )[0]
        self.assertIn("!profile.current && (", profile_card)
        self.assertIn(
            'className="icon-button danger" onClick={() => onDelete(profile)} disabled={busy}',
            profile_card,
        )
        self.assertIn(
            ".profile-card .quota-summary-card { padding: 11px 12px; }",
            stylesheet,
        )

    def test_home_is_quota_only_and_renders_every_official_account(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        stylesheet = (self.project / "src" / "styles.css").read_text(encoding="utf-8")
        overview = application.split("function Overview(", 1)[1].split(
            "function Accounts(", 1
        )[0]
        self.assertIn('{ id: "overview", label: "主页"', application)
        self.assertIn('overview: ["主页", "查看全部官方账号额度与同步状态"]', application)
        self.assertIn('profile.type === "official"', overview)
        self.assertIn("officialProfiles.map((profile)", overview)
        self.assertIn('<OfficialQuota profile={profile} showPlan={false} />', overview)
        self.assertIn("同步全部额度", overview)
        self.assertNotIn("快速切换", overview)
        self.assertNotIn("统一会话库", overview)
        self.assertNotIn("<StatCard", overview)
        self.assertNotIn("<HealthStrip", overview)
        self.assertIn("grid-template-columns: repeat(2, minmax(0, 1fr));", stylesheet)

    def test_official_account_modal_uses_isolated_chatgpt_oauth(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        self.assertIn('api("/api/profiles/official/oauth"', application)
        self.assertIn("使用 ChatGPT OAuth 绑定", application)
        self.assertIn("不会改变 Codex 当前账号、配置或聊天记录", application)
        self.assertIn("手动检查更新", application)

    def test_verified_background_update_prompts_once_per_app_session(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        self.assertIn('const update = await api("/api/update")', application)
        self.assertIn("window.setInterval(syncUpdateStatus, 5_000)", application)
        self.assertIn('update?.state !== "downloaded"', application)
        self.assertIn("updatePromptedVersion.current === version", application)
        self.assertIn('setConfirmAction({ type: "update-install", version, automatic: true })', application)

    def test_uncertain_recent_turn_state_blocks_switch_with_a_visible_reason(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        self.assertIn("conflicts?.active_turns?.uncertain_count || 0", application)
        self.assertIn("无法确认最近任务是否已经结束", application)
        self.assertIn("无法安全确认最近任务是否结束；Guardian 未关闭 Codex，也未修改任何文件。", application)

    def test_interrupted_turn_markers_are_visible_without_claiming_they_are_running(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        self.assertIn("conflicts?.active_turns?.interrupted_count || 0", application)
        self.assertIn("未发现正在运行的任务", application)
        self.assertIn("未收尾标记已归类为中断记录，不再阻止切换", application)
        self.assertIn("无法确认 Codex 后台进程状态", application)
        self.assertIn("后台 app-server 或 CLI 写入进程仍可能继续任务", application)

    def test_missing_rollout_switch_result_is_a_visible_warning(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        self.assertIn("result.migration?.missing_rollout_file_count || 0", application)
        self.assertIn("条会话仅剩 SQLite 元数据，未重建已缺失的聊天文件", application)
        self.assertIn('verification?.verified && !missingRollouts ? "success" : "warning"', application)

    def test_auto_close_describes_real_graceful_wait_without_residual_kill_promise(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        self.assertIn("自动请求正常退出并等待最多 30 秒；不会强制结束进程", application)
        self.assertNotIn("超时后只清理 Codex 自身的残留进程", application)

    def test_history_conflicts_support_explicit_recoverable_copy_selection(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        stylesheet = (self.project / "src" / "styles.css").read_text(encoding="utf-8")
        self.assertIn("conflicts?.can_resolve", application)
        self.assertIn("选择保留副本", application)
        self.assertIn("manualConflicts.map((conflict, conflictIndex)", application)
        self.assertIn("report_revision: report?.report_revision", application)
        self.assertIn("keep_copy_ref: selections[item.conflict_ref]", application)
        self.assertIn("不要手动删除聊天", application)
        self.assertIn('conflictBlockedLabel = !turnStateSafe', application)
        self.assertIn('"等待任务结束"', application)
        self.assertIn("所有原始副本均可恢复", application)
        self.assertIn(".conflict-copy-option.is-selected", stylesheet)
        self.assertIn(".conflict-copy-options { grid-template-columns: 1fr; }", stylesheet)

    def test_product_styles_keep_an_eleven_pixel_font_floor(self) -> None:
        pattern = re.compile(r"font(?:-size)?\s*:[^;]*(?<!\d)(?:8|9|10)px")
        for stylesheet_path in (self.project / "src").rglob("*.css"):
            stylesheet = stylesheet_path.read_text(encoding="utf-8")
            self.assertIsNone(pattern.search(stylesheet), stylesheet_path.as_posix())


if __name__ == "__main__":
    unittest.main()
