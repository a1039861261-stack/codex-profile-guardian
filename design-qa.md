# Design QA — v1.9.1

- Source visual truth:
  - `_tmp/design-qa/source-quota-layout.png`
  - `_tmp/design-qa/source-disabled-button.png`
- Browser-rendered implementation:
  - `_tmp/design-qa/design-qa-desktop.png`
  - `_tmp/design-qa/design-qa-mobile.png`
  - `_tmp/design-qa/design-qa-settings-mobile.png`
- Combined comparison evidence: `_tmp/design-qa/design-qa-comparison.png`
- Desktop viewport: `1440 x 900` CSS px, device scale factor approximately `1`.
- Mobile viewport: `390 x 844` CSS px, device scale factor approximately `1`; full-page capture is `374 x 1734` px after scrollbar exclusion.
- Desktop browser screenshot: `1251 x 900` px because the Codex in-app browser reserves its own side surface; layout metrics were separately read from the page at the full `1440 x 900` CSS viewport.
- State: isolated fake account/quota fixture; no real credentials or real Codex chat data.

## Full-view comparison evidence

- The old quota screenshot showed one outer white frame around the three summary rectangles. The implementation removes that wrapper surface and keeps only the three cards.
- At `1440 x 900`, the three desktop quota cards measured the same height (`101.28125px`) and were laid out in three columns with equal widths (`359.33334px`) and `12px` gaps.
- At `390 x 844`, the quota cards switch to one column and the document has no horizontal overflow (`scrollWidth=375`, `innerWidth=390`).
- The selected/current account card now uses a strong blue border, blue-tinted surface, left structural accent, and visible `当前` badge.
- The previous disabled blue action used low-contrast gray text. The current disabled primary action retains white text on a deeper blue surface; the mobile settings capture shows the complete state.

## Focused-region comparison evidence

- `_tmp/design-qa/design-qa-comparison.png` puts the two user-provided problem screenshots and the corresponding implementation regions into one comparison image.
- The page also has a global `11px` font floor; important UI text remains at `12–16px` or larger.
- No visible raster or brand asset was replaced. Existing Phosphor icons and the Guardian product mark remain unchanged.

## Interaction checks

- `手动同步额度`: clicked successfully; the UI displayed `官方额度已手动同步`.
- `手动检查更新`: clicked successfully; the update card changed from `尚未检查` to the safe repository-unavailable state in the private-repository fixture.
- Navigation between Overview and Settings worked at desktop width.
- Automatic update toggle is on in the fixture and copy states that checks run after launch and every 30 minutes.
- Browser console warnings/errors: `0` on desktop and mobile verification passes.

## Required fidelity surfaces

- Fonts and typography: Windows Chinese UI stack preserved; minimum size increased to `11px`; no clipped headings or unreadable disabled labels found.
- Spacing and layout rhythm: desktop quota cards are equal-height and horizontally aligned; mobile cards stack cleanly; no horizontal overflow.
- Colors and visual tokens: gray-white surfaces remain consistent; blue is used for actions, selection and healthy/current state; disabled primary contrast is materially improved.
- Image quality and asset fidelity: no new raster assets were required for this UI-only change; existing logo/icon assets remain sharp.
- Copy and content: manual quota sync, manual update check, automatic update explanation, and `单一本机聊天库` wording are present and readable.

## Findings

- No actionable P0/P1/P2 findings remain.

## Comparison history

1. Earlier findings from the supplied screenshots:
   - P1: disabled blue action text had insufficient contrast.
   - P2: quota cards were wrapped in an unnecessary outer frame and their grouping/alignment felt visually uneven.
   - P2: smallest product text was too small.
2. Fixes made:
   - Disabled primary buttons now retain white text on a deeper blue background.
   - Removed the quota wrapper surface and aligned three equal-height desktop cards.
   - Added responsive single-column mobile behavior and raised the font floor to `11px`.
3. Post-fix evidence:
   - Desktop and mobile browser captures listed above.
   - Exact DOM measurements for equal-height cards and overflow checks.
   - Zero browser console warnings/errors.

## Follow-up polish

- P3 only: the long fixture path in the `统一会话库` explanation wraps heavily on narrow screens; the installed product path is shorter, so this does not block the release.

final result: passed
