# Prototype Instructions

Run the local server yourself and open the preview in the in-app browser. Do not give the user server-start instructions when you can run it.

Before making substantial visual changes, use the Product Design plugin's `get-context` skill when the visual source is unclear or no longer matches the current goal. When the user gives durable prototype-specific design feedback, preferences, or decisions, record them in `AGENTS.md`.

When implementing from a selected generated mock, treat that image as the source of truth for layout, component anatomy, density, spacing, color, typography, visible content, and hierarchy.

## Confirmed product direction

- Windows Chinese desktop utility for managing Codex and Claude Desktop from one control surface.
- Codex keeps the existing official-account, API-profile, shared-history and failover responsibilities. Guardian independently owns Claude Desktop provider metadata and DPAPI secrets, writes only its dedicated 3P profile, and supports an explicit one-time CC Switch import without retaining CC Switch as a runtime dependency.
- Legacy Guardian screens may continue using the supplied Cockpit Tools reference. The API failover control surface follows the user's updated direction: gray-white surfaces, restrained borders, compact spacing, and semantic color limited to status and focus.
- The entire product now uses one palette: gray-white surfaces and black/gray typography/structure. Blue is the only action, selection, focus, healthy/current accent; yellow is the only warning, offline, error, destructive, or action-required accent. Do not reintroduce green, red, cyan, purple, gradients, or dark navy surfaces.
- Buttons must keep clearly readable text against every background, including disabled and modal states. Selected/current task or account cards must be immediately distinguishable from unselected cards through a stronger blue border, tinted surface, and structural accent; do not rely on a subtle shade change alone.
- When automatic updates are enabled, opening the app must automatically observe the background update check. After a newer installer has been downloaded and SHA-256 verified, proactively open the existing install-confirmation modal once per version per app session. Installation still requires the user's explicit click and must never run silently.
- Keep the API failover first viewport deliberately sparse: one conclusion, current carrier, primary status, required action, and the P1/P2 routes. Engineering diagnostics belong in collapsed details.
- Keep Codex and Claude as separate platform workspaces. Codex primary navigation remains Home, Accounts, Chat Protection, API Failover, Backups, Logs, Settings; Claude starts with one sparse connection-status page.
- Codex Home is a quota-only dashboard. It must show every saved official account and its plan, weekly quota, reset-card balance, current/stale state, and latest refresh time. Do not put quick switching, session-library explanations, account/session statistics, or chat-protection summaries back on Home.
- Adding an official account should default to the official ChatGPT OAuth flow in an isolated one-time `CODEX_HOME`. It must not require changing the active Codex login first, must not ask for a password, and must not modify the user's active Codex home, configuration, or conversations.
- Full functionality is required. Profile secrets must be DPAPI-encrypted, every switch must create a rollback backup, thread provider metadata must be reconciled without changing archived flags, and failures must roll back automatically.
- Claude daily status and provider operations must not read CC Switch. A confirmed one-time import may read only the current provider needed for migration; only native Anthropic Messages API providers are accepted, and Claude Desktop restart must not terminate Claude Code CLI.
