---
name: Laneway Console
description: A dark, topology-first operating surface for private-network administration.
colors:
  canvas: "#080e15"
  chrome-deep: "#050a0f"
  sidebar: "#060b11"
  surface: "#0e1722"
  surface-raised: "#14202d"
  surface-hover: "#19283a"
  border: "#223142"
  border-strong: "#354a62"
  text: "#edf4ff"
  text-muted: "#9dafc3"
  text-faint: "#8396aa"
  primary: "#2f7df6"
  primary-hover: "#4b90fa"
  primary-soft: "rgba(47, 125, 246, .15)"
  focus: "#82b7ff"
  positive: "#55d6b0"
  positive-soft: "rgba(85, 214, 176, .12)"
  warning: "#f3b85c"
  warning-soft: "rgba(243, 184, 92, .13)"
  danger: "#ff7e86"
  danger-soft: "rgba(255, 126, 134, .12)"
  danger-action: "#bf4553"
  on-primary: "#f7fbff"
typography:
  display:
    fontFamily: "Manrope Variable, system-ui, sans-serif"
    fontSize: "clamp(3.3rem, 6.5vw, 5.8rem)"
    fontWeight: 550
    lineHeight: 0.95
    letterSpacing: "-.04em"
  headline:
    fontFamily: "Manrope Variable, system-ui, sans-serif"
    fontSize: "clamp(1.8rem, 3.2vw, 2.35rem)"
    fontWeight: 550
    lineHeight: 1.08
    letterSpacing: "-.025em"
  title:
    fontFamily: "Manrope Variable, system-ui, sans-serif"
    fontSize: "clamp(1.04rem, 1.5vw, 1.22rem)"
    fontWeight: 550
    lineHeight: 1.3
    letterSpacing: "-.025em"
  body:
    fontFamily: "Manrope Variable, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Manrope Variable, system-ui, sans-serif"
    fontSize: ".72rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: ".08em"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace"
    fontSize: ".92em"
    fontWeight: 400
    lineHeight: 1.55
rounded:
  compact: "5px"
  small: "6px"
  control: "7px"
  default: "8px"
  panel: "9px"
  large: "10px"
  auth-stage: "14px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "14px"
  lg: "18px"
  xl: "24px"
  page-gutter: "clamp(20px, 3vw, 38px)"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    rounded: "{rounded.control}"
    padding: "8px 14px"
    height: "40px"
  button-secondary:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "8px 14px"
    height: "40px"
  button-danger:
    backgroundColor: "{colors.danger-action}"
    textColor: "#ffffff"
    rounded: "{rounded.control}"
    padding: "8px 14px"
    height: "40px"
  field:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "9px 11px"
    height: "42px"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.panel}"
    padding: "18px"
  filter-chip:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.text-muted}"
    rounded: "{rounded.pill}"
    padding: "7px 29px 7px 10px"
    height: "38px"
---

# Design System: Laneway Console

## Overview

**Creative North Star: "The Authenticated Operations Room"**

Laneway implements the approved NetBird-weighted hybrid direction (seed `cc80fe45`): a serious, dark administrative workspace that favors task grouping, contextual inspection, and visible network paths. NetBird's topology-first explanations, grouped navigation, segmented filters, and master-detail workspaces carry the most weight; Twingate contributes restraint, explicit actions, readable density, and calm operational copy. The result must remain recognizably Laneway rather than reproducing either reference product.

The interface is built from blue-black planes, fine slate seams, compact controls, and sparse semantic color. Data remains dense but never anonymous: an inventory row is commonly paired with a selected-record inspector, and configuration is paired with an effective-path or impact preview. Topology diagrams, status language, audit attribution, and confirmation copy make system behavior and consequences visible.

**Key Characteristics:**

- Dark-only operating-room atmosphere with crisp tonal layering and minimal decoration.
- Grouped, task-oriented navigation with persistent context and clear active state.
- Topology and effective-path explanations before low-level protocol detail.
- Dense inventories with filters, result counts, selection, and adjacent inspectors.
- Review-first forms and explicit, attributable safety gates for consequential changes.
- Synthetic and live-controller states are labeled honestly and never visually conflated.

## Colors

The palette uses cold blue-black neutrals as the field, electric blue for intent, mint for verified health, amber for attention, and coral-red for denial or destructive risk. The frontmatter is the normative color source.

### Primary

- **Laneway Blue:** Primary actions, active navigation seams, selected choice borders, topology endpoints, and interactive emphasis. Use the hover token for pointer hover and the softer wash for selection or icon tiles.
- **Ice Focus:** Keyboard focus rings, linked values, and selected-record accents. It is deliberately brighter than the action blue so focus is unambiguous.

### Secondary

- **Verified Mint:** Connected, healthy, redeemed, approved, and successful outcomes; also the direct-path end of topology gradients.
- **Review Amber:** Pending approval, relay fallback, expiring credentials, demo state, and impact warnings.
- **Guardrail Coral:** Deny, offline, failed, revoked, validation error, and destructive-action semantics.

### Neutral

- **Canvas / Deep Chrome / Sidebar:** The three lowest planes establish page, inset, and persistent-navigation depth.
- **Surface / Raised / Hover:** Panels, selected records, and transient hover response. Raised is a state or hierarchy cue, not a generic card fill.
- **Slate Seams:** Default borders divide tables and panels; the stronger seam marks interactive fields and elevated boundaries.
- **Text / Muted / Faint:** Primary content, explanatory copy, and tertiary metadata. Faint text is never used for essential actions or status on its own.

**The Sparse Signal Rule.** Semantic color is evidence, not decoration. Blue marks agency, mint confirms health, amber requests attention, and coral marks harm or failure; always pair status color with text or an icon.

**The Dark-Only Rule.** The administrator console is designed for its blue-black environment. Do not introduce a light page, white card, or pale dashboard region as an alternate default.

## Typography

**Display and Body Font:** Manrope Variable with `system-ui` fallback.
**Technical Font:** The platform monospace stack for identifiers and protocol values.

Manrope gives the console a modern, calm voice without making the interface feel editorial or consumer-oriented. Headings are medium weight, tightly tracked, and balanced; body and control copy stays regular to semibold. Numeric tables use tabular figures where comparison matters.

### Hierarchy

- **Display:** Reserved for the sign-in statement. It is oversized, very tightly tracked, and never used inside the application shell.
- **Headline:** Page titles use the responsive headline role with a maximum measure of roughly 24 characters.
- **Title:** Panel and section headings use the title role; compact inspector and table headings may reduce to about `.95rem–1rem` while preserving medium weight.
- **Body:** Explanatory copy uses a maximum line length of 72 characters and muted color. Dense tables and metadata commonly reduce to `.68rem–.84rem`.
- **Label:** Navigation groups, panel kickers, table headers, and inspector labels use compact uppercase text with deliberate tracking. Do not uppercase sentences or action labels.
- **Mono:** Node, route, token, event, CIDR, overlay address, selector, and command values use monospace with ligatures disabled and safe wrapping or truncation.

**The Human-First Rule.** Lead with a recognizable name or outcome; place IDs, prefixes, and protocol data as secondary technical evidence.

## Layout

Desktop uses a fixed `224px` navigation rail and a fluid application frame. The `62px` command bar is sticky and contains breadcrumbs, command search, refresh, environment mode, and operator identity. A narrow notice directly below it distinguishes synthetic, live, and controller-error states. Page content uses fluid horizontal gutters and a generous bottom reserve above the system-status footer.

Global navigation is grouped exactly as follows:

- **Control:** Overview, Nodes, Users.
- **Connectivity:** Routes, Infrastructure.
- **Governance:** Access, Security, Audit.

Inventory pages commonly use a four-cell health strip, then segmented filters and a search/filter toolbar, then a `minmax(0, 1fr) / 290–300px` workspace. The selected inspector stays sticky below the command bar. Forms and approval screens use a main authoring or impact panel plus a narrow, sticky review/actions column. Detail pages use an identity rail beside stacked operational sections. The overview and infrastructure pages lead with topology and a narrower service-impact queue.

Spacing follows a compact 4/8px foundation with repeated working gaps around `14–18px`, panel padding around `18–23px`, and page-level separation around `24–38px`. Borders and alignment carry most grouping; avoid nesting many disconnected cards.

### Responsive behavior

- **At 1120px and below:** Generic detail and form layouts become one column; most inspectors stop being sticky. Topology/work-queue and inventory/inspector workspaces collapse at their page-specific `1100–1180px` breakpoints.
- **At 860px and below:** The sidebar becomes a `66px` icon rail, navigation labels and group headings hide, command search hides, and operator identity condenses.
- **At 680px and below:** The rail becomes a fixed, blurred bottom launcher with all eight destinations in a four-column, two-row grid. The wordmark and environment block leave navigation; breadcrumbs, refresh, and the environment badge remain in the top bar. Pages use `14px` side padding and `142px` bottom padding so content clears the launcher.
- **Mobile actions:** Page headers stack and their primary actions fill the available width. Button rows distribute actions evenly where appropriate.
- **Mobile data:** Table headers disappear and each row becomes a bordered record with visible field labels. Purpose-built compact tables may retain only their three most important columns. Inspectors follow the inventory rather than opening as overlays.
- **Mobile topology:** Horizontal flows rotate into source-to-destination vertical order. Four-up health strips become two-up and then one-up; form field pairs, metadata pairs, and path facts become a single column.
- **Mobile footer:** Preserve the primary system state while progressively hiding auto-refresh, epoch, and timestamp metadata.

**The Context-Preservation Rule.** Prefer an adjacent inspector or stacked continuation over a modal when examining a record. Selection should never erase the inventory that established context.

## Elevation & Depth

The system is flat by default. Depth comes from tonal planes, one-pixel borders, inset active seams, and occasional sticky positioning. Ordinary panels and controls do not float. Shadows are reserved for the sign-in stage/panel and topology nodes, where spatial separation is part of the meaning.

### Shadow vocabulary

- **Authentication stage:** A broad `0 28px 90px rgb(0 0 0 / 35%)` shadow separates the sign-in environment from the page background.
- **Authentication panel:** A quieter `0 20px 60px rgb(0 0 0 / 24%)` shadow brings the credential form forward.
- **Topology node:** A compact `0 14px 34px rgb(0 0 0 / 28%)` shadow distinguishes network actors from the diagram field.
- **Selected record:** Use an inset `2px` focus-colored seam plus the raised surface; do not use a drop shadow.

Topology path dots animate linearly over three seconds to communicate live flow. Ordinary state transitions use a short `160ms ease-out`. Respect `prefers-reduced-motion` by reducing transitions and animations to effectively instantaneous, single-iteration behavior.

**The Flat-by-Default Rule.** If a border and tonal change can establish hierarchy, do not add a shadow.

## Shapes

Laneway uses compact, gently squared geometry. Interactive controls sit around `7–8px`; containers around `8–10px`; the authentication stage alone reaches `14px`. One-pixel slate borders are structural and remain visible against every dark plane.

Full pills are reserved for filters, status/action chips, compact counters, avatars, and circular topology/status markers. They are not the default button or panel shape. The Laneway mark is three narrow rising bars skewed upward; Lucide line icons remain compact, normally `14–19px`, and reinforce labels rather than replacing them on desktop.

Dashed borders identify one-time credential/code containers and empty-state illustrations. Circular forms are used sparingly for status dots, queue counts, decision icons, and path actors.

**The Controlled-Radius Rule.** Keep operational surfaces compact; do not introduce oversized rounded cards, pill buttons, or bubbly consumer-app silhouettes.

## Components

### Application shell and navigation

- The desktop rail is persistent, grouped, and ends with the active network environment plus a labeled health indicator.
- Active navigation uses the raised surface, primary text, and a `2px` blue leading seam. Hover changes color and adds only a very subtle light wash.
- Pending work may appear as a labeled amber count on the relevant destination.
- Breadcrumbs preserve hierarchy in the sticky command bar. Command search is centered at desktop widths; refresh, mode, operator, and optional sign-out occupy the right side.
- The bottom launcher keeps the same information architecture and visible labels. Its selected item uses the raised surface; never substitute an unlabeled icon-only tab bar.

### Page headers, metrics, and panels

- A `PageHeader` pairs one outcome-oriented title and short description with one dominant upper-right action. Multiple actions are allowed only when they represent distinct peer tasks, as on Infrastructure.
- Health strips are a single joined surface divided by seams, not a row of floating KPI cards. Each metric combines a value with a short operational label; icons and semantic color are supporting cues.
- Panels use the surface plane, a one-pixel border, and compact header/body separation. Kicker labels identify inspector or system context.

### Buttons and controls

- Primary buttons use Laneway Blue, semibold text, `40px` minimum height, and compact corners. Hover brightens; active presses down by `1px`.
- Secondary buttons use the raised plane and strong border. Quiet buttons are transparent with a default seam. Danger buttons use a darker red action fill, not the brighter status coral.
- Fields use the canvas plane, strong border, `42px` minimum height, and visible labels. Hover strengthens the border; focus uses Ice Focus plus a soft three-pixel blue halo.
- Disabled controls stay structurally visible at reduced opacity. Unsupported capabilities, such as SSO in the current product, remain visibly disabled with explanatory copy.
- Choice cards show label and consequence; selected choices use the soft blue plane and a blue border. Checkbox acknowledgements use the same semantic action color.

### Filters, inventories, and inspectors

- Segmented controls sit inside one compact dark track. The selected segment uses raised fill; some inventories add a thin blue lower seam.
- Search and chip-shaped selects form one query band. Updates are local and preserve a visible result count.
- Desktop inventory tables use compact rows, subdued headers, tabular figures, hover tint, and a raised selected row with a leading focus seam.
- Entity cells pair a small icon tile with a human name and secondary ID. Status always combines a dot with text.
- The selected-record inspector shows identity, status, key facts, effective path or impact, and an explicit open action. Details, audit, and security workspaces reuse the master-detail pattern.

### Topology and effective paths

- Topology is a functional explanation, not decorative network art. It must distinguish control-plane coordination from the authenticated data path and identify direct versus relay behavior.
- Nodes appear as labeled, bordered actors connected by blue-to-mint paths. A faint technical grid is permitted only inside the overview topology field.
- Compact effective-path blocks use directional order, readable actor labels, and text describing authorization or fallback. At mobile widths, preserve order vertically.

### Forms, review, tokens, and destructive actions

- Forms pair authoring with a live review/impact panel whenever the change affects enrollment, forwarding, capabilities, or access.
- Route creation ends in a distinct approval screen. Approval requires reviewing the effective path, acknowledging the change, and typing the exact destination; rejection records a reason.
- Access rules preview the exact selector and destination, and detail pages support sample-packet evaluation with an ordered trace.
- One-time tokens are shown once in a dashed technical container with immediate copy feedback, clipboard-failure recovery, a command, and numbered next steps.
- Destructive actions use a dedicated, centered confirmation panel or inspector action area. Explain downstream impact, require the exact entity name or affected value, and keep the destructive button disabled until valid.

### Status, callouts, empty, and audit states

- `Status` always combines text with a dot; color never carries meaning alone.
- Neutral callouts use deep chrome. Warning, danger, and effective-result callouts use the corresponding soft semantic plane, border, text, and explicit heading.
- Empty states use a dashed icon container, direct explanation, and at most one recovery action.
- Audit rows show time, icon, action, actor/target, and short event ID. Selection opens recorded fields, effective result, attribution, and copy/open actions without leaving the stream.
- Every interactive element retains a visible keyboard focus ring. Copy actions announce success in their label and preserve a manual fallback.

## Do's and Don'ts

### Do:

- **Do** lead overviews with operational health, topology, effective paths, and attention queues rather than generic analytics.
- **Do** keep primary actions explicit, scarce, and anchored to the page header or consequence panel.
- **Do** preserve inventory context through adjacent inspectors, selected-row seams, and breadcrumb continuity.
- **Do** explain what a route, rule, credential, capability, or revocation changes before the user commits it.
- **Do** use human-readable names first and technical identifiers as secondary evidence.
- **Do** maintain WCAG 2.2 AA contrast, complete keyboard operation, textual status labels, and reduced-motion behavior.
- **Do** label synthetic data, live-controller state, unsupported functionality, and clipboard or controller errors honestly.

### Don't:

- **Don't** imply that the controller carries user traffic; diagrams and copy must keep it outside the packet path.
- **Don't** imply persistent email people directories, identity-provider sync, groups, tenant roles, or enabled SSO until the backend supports them.
- **Don't** turn the console into a wide top-nav product site, a generic card dashboard, or a light-mode SaaS template.
- **Don't** decorate with semantic color, gradients, glow, or shadows outside their documented operational roles.
- **Don't** hide destructive or access-broadening consequences behind ambiguous labels, instant actions, or color alone.
- **Don't** force horizontal scrolling for critical fields at common laptop or mobile widths.
- **Don't** wrap the administrator console as a desktop client. A future Tauri client is a separate endpoint surface for connection state, profiles, exit-node selection, tray controls, updates, and diagnostics; it may share tokens and components, not information architecture.
