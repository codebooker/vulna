# Accessibility

Vulna's dashboard aims to be usable with a keyboard and a screen reader. This
document records the accessibility approach and a keyboard-only review of the core
flows (Phase 22).

## Approach

- **Landmarks & structure** — each panel is a `<section>`/`<article>` with an
  `aria-label`, and content uses real headings (`h2`/`h3`/`h4`) in order.
- **Controls** — actions are native `<button>` elements; the global search box has
  a visually-hidden `<label>` and `type="search"`; expandable technical detail uses
  native `<details>`/`<summary>`. Errors use `role="alert"`.
- **Focus** — interactive elements are reachable and operable by keyboard in DOM
  order; no click-only handlers on non-interactive elements.
- **Contrast** — text and status colors are chosen against the panel/background
  variables for legibility in the default dark theme.
- **Responsive** — the home dashboard, findings review, and status panels use
  responsive grids that reflow for tablets and phones.

## Keyboard-only review (core flows)

Reviewed with keyboard only (Tab / Shift+Tab / Enter / Space / Escape):

| Flow | Result |
|---|---|
| Sign in | Fields and submit reachable and operable; errors announced. |
| Home dashboard: read next action + top issue | Headings and content reachable; next action is the first content after the heading. |
| Findings: open a finding, expand raw evidence | List rows are buttons; `<details>` toggles with Enter/Space. |
| One-click workflows (mark fixed & verify, false positive, assign) | Buttons focusable and operable; disabled state respected while busy. |
| Global search | Input focusable; results list is navigable; blur closes the panel. |
| Emergency stop (remote Scout) | CLI command; documented in deployment guide. |

## Automated checks

Component tests render key views and assert accessible names/roles (e.g. buttons
found by role/name, `role="alert"` for errors). Broader automated accessibility
assertions (axe-style) are a tracked follow-up.
