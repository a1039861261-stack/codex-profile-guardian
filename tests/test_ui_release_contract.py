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
            ".app-shell.is-gray .button-primary:disabled { color: #ffffff; border-color: #3f5f8f; background: #4b6f9f; opacity: 1; }",
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

    def test_overview_quota_cards_are_unframed_aligned_and_manual(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        stylesheet = (self.project / "src" / "styles.css").read_text(encoding="utf-8")
        self.assertIn('<section className="overview-quota-panel">', application)
        self.assertNotIn('<section className="content-panel overview-quota-panel">', application)
        self.assertIn("grid-template-columns: repeat(3, minmax(0, 1fr));", stylesheet)
        self.assertIn("手动同步额度", application)
        self.assertIn("手动检查更新", application)

    def test_verified_background_update_prompts_once_per_app_session(self) -> None:
        application = (self.project / "src" / "App.jsx").read_text(encoding="utf-8")
        self.assertIn('const update = await api("/api/update")', application)
        self.assertIn("window.setInterval(syncUpdateStatus, 5_000)", application)
        self.assertIn('update?.state !== "downloaded"', application)
        self.assertIn("updatePromptedVersion.current === version", application)
        self.assertIn('setConfirmAction({ type: "update-install", version, automatic: true })', application)

    def test_product_styles_keep_an_eleven_pixel_font_floor(self) -> None:
        pattern = re.compile(r"font(?:-size)?\s*:[^;]*(?<!\d)(?:8|9|10)px")
        for stylesheet_path in (self.project / "src").rglob("*.css"):
            stylesheet = stylesheet_path.read_text(encoding="utf-8")
            self.assertIsNone(pattern.search(stylesheet), stylesheet_path.as_posix())


if __name__ == "__main__":
    unittest.main()
