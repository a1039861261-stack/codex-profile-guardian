from pathlib import Path
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
            ".app-shell.is-gray .button:disabled,\n.app-shell.is-gray .icon-button:disabled { color: #5b616a; opacity: .68; }",
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


if __name__ == "__main__":
    unittest.main()
