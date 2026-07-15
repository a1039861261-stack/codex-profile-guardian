# Design QA

## Reference material

- `qa/source-cockpit-overview.png`
- `qa/source-cockpit-accounts.png`
- `qa/source-cockpit-settings.png`

## Implementation captures

- `qa/implementation-overview.png`
- `qa/implementation-accounts.png`
- `qa/implementation-protection.png`

## Legacy v1.2 test matrix

- Desktop viewport: 1440 × 900
- Compact viewport: 800 × 900
- State: three saved profiles, third-party API active, chat protection healthy, backups available
- Browser console: no errors or warnings

## Full-view comparison

The implementation preserves the useful Cockpit Tools visual language: deep navy workspace, fixed left navigation, blue active states, restrained card borders, and green/amber status semantics. It intentionally removes the unrelated multi-platform dashboard and exposes only Codex account switching, chat protection, backups, logs, and settings.

## Focused-region comparison

- Account cards keep the reference hierarchy of profile name, type badge, connection details, status, and direct actions.
- Chat protection replaces Cockpit's generic network-service settings with explicit conversation index, archive-state, backup, repair, and integrity indicators.
- The compact viewport keeps navigation and all critical actions usable without overlapping or clipped controls.

## Findings and patches

- Replaced remote web fonts with local Windows fonts so the packaged application renders consistently offline.
- Kept the active profile action disabled to prevent accidental repeat switching.
- Preserved visible archive and backup health signals on the overview instead of hiding them in settings.
- No remaining P0, P1, or P2 visual defects were found in the legacy v1.2 baseline.

## v1.1 credential-state patch

- Added a compact credential health row to official account cards using the existing green/amber/red semantic system.
- Added “更新登录” only on the current official account, with a confirmation modal that explains automatic Codex shutdown, same-account validation, backup creation, and chat preservation.
- Rechecked the account view at the standard browser viewport; the three-card layout remains aligned and no action overlaps or text overflow were found.
- Browser console remained free of errors and warnings.

## v1.2 SSH settings patch

- Added one settings section using the existing panel, toggle, spacing, blue accent, and typography components.
- The copy explicitly states the SSH host count, backup behavior, and the Windows-only configuration exclusions.
- Verified the settings viewport with no horizontal overflow, clipped controls, console errors, or warnings.
- Account cards now report whether their encrypted settings snapshot exists.

legacy v1.2 baseline result: passed

## G6 v0 failover preview

Status: passed as a fixture-only gray-white preview; G6 itself remains in progress.

### Confirmed direction

- User feedback replaced the original dense navy dashboard with a gray-white operational surface.
- The first viewport now answers only: current conclusion, active route, primary status, required action, and P1/P2 state.
- Breaker enums, model/base URL/key suffix/revision, event history, runtime diagnostics, and reliability boundaries are collapsed by default.
- Blue is reserved for focus/selection. Green, amber, and red appear only on compact semantic status elements.

### Captures

- `qa/g6-v0-1440x900.png`
- `qa/g6-v0-1920x1080.png`
- `qa/g6-v0-410x900.png`

Each PNG preserves the exact logical CSS viewport size: `1440×900`, `1920×1080`, and `410×900`.

### Responsive and interaction matrix

- Desktop `1440×900`: document `scrollWidth=clientWidth=1440`; the complete status, facts, P1/P2 routes, and collapsed “更多信息” control fit in the first viewport.
- Wide desktop `1920×1080`: document `scrollWidth=clientWidth=1920`; the `1120px` content canvas stays centered and bounded.
- Mobile `410×900`: document `scrollWidth=clientWidth=395` after the native scrollbar; the current navigation target, grouped scenario select, conclusion, and three key facts are visible before route details.
- Scenario switching: healthy, degraded, action required, both routes failed, loading, empty, and error each update the URL, native selected option, and page content consistently.
- Navigation: desktop keeps the full product context; mobile shows only the current `API 容灾` destination instead of seven unlabeled icons.
- Disabled states: unavailable real operations remain disabled and reference the visible synthetic-preview notice with `aria-describedby`.
- Keyboard and disclosure: the active navigation target shows the `2px` blue focus ring; both route details and the advanced panel use native `details/summary` controls with at least `44px` mobile targets.
- State semantics: loading/empty use `role=status`; error uses `role=alert`; no loading, empty, or error state overflows horizontally.
- Console: a newly loaded preview tab has zero errors and zero warnings; only Vite debug and React development info messages remain.
- Motion: `prefers-reduced-motion` removes nonessential animation and transition duration.
- Build: Vite `6.4.2` transforms `4,574` modules and emits `dist/failover-preview.html`, `14.87 kB` preview CSS, and `39.50 kB` preview JS successfully.

G6 v0 visual result: passed. This does not cover fixture/production management APIs, live Gateway state, provider transactions, installation, or release.

## G6 fixture management integration

Status: passed for the offline fixture management gate; production Gateway control, real provider activation, installation, NAS, packaging, and release remain out of scope.

### Same-origin flow

- Started Guardian with a fresh temporary `CODEX_HOME` and data directory; no real Guardian profile, DPAPI secret, provider, or chat state was read.
- Used the packaged `dist` page and the real Guardian management HTTP API to create two synthetic API profiles, create a failover group, and publish it to the fixture Gateway controller.
- The final page showed `主线路运行正常`, `P1 · P1 离线主线`, P1 `正在使用`, P2 `健康可用`, and `无需操作`.
- HttpOnly session bootstrap, loopback Host validation, same-origin Origin validation, credentialed dev CORS, revision CAS, structured errors, CRUD, publish, retest, and delete are covered by `tests/test_guardian_management_http.py`.
- Browser console errors/warnings: `0`.

### Responsive verification

- Desktop `1440×900`: `scrollWidth=1440`, `scrollHeight=900`; status, facts, both routes, and collapsed advanced details fit in the first viewport.
- Wide desktop `1920×1080`: `scrollWidth=1920`, content canvas `1120px`, no horizontal overflow.
- Mobile `410×900`: browser content `scrollWidth=395` with the native scrollbar, both route cards `363px`; only the active `API 容灾` navigation item remains visible and no horizontal overflow occurs.
- Shared action buttons preserve explicit form `type="submit"`; this fixes the browser-found regression where the create form did not submit and the modal action fell through to the legacy page.

### Verification

- Focused G6 suite: `43/43` passed.
- Full Python suite: `309/309` passed in `159.281s`.
- Vite `6.4.2`: `4,580` modules transformed successfully.
- `pip check`, `compileall`, `git diff --check`, G1 `56/56` snapshot verification, and scoped secret scan passed; scan hits were limited to known synthetic fixture Authorization strings.

G6 fixture management visual and interaction result: passed.
