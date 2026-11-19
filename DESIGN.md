# Console design

The admin console supports light and dark themes. Use the tokens in
[the console stylesheet](web/src/styles.css) and reuse components from
[the UI library](web/src/components/ui.tsx). Check both themes when changing a
color or control. The [desktop client](docs/desktop-client.md) has its own
navigation and manages the local node, rather than the controller.

## Navigation and records

- Put the main action in the page header. Group related views under one
  navigation item, such as Users and Teams under People.
- Keep filters and result counts near the data. Show current records by
  default; give administrators a way to inspect inactive records.
- Lead with names instead of IDs. Display IP addresses, CIDRs, and IDs in
  monospace. Wrap long values in detail views so they remain readable.
- Keep the selected item's details in view when its list scrolls. Stack the
  list and details on narrow screens. Preserve access to the full value when
  a table shortens it.

## Copy and controls

- Name the action and its target. Use "Revoke node" instead of "Confirm."
  Explain who gains or loses access before saving a rule.
- Show a credential or enrollment command only when it is available. Offer
  copy and manual selection. Never store a one-time secret in browser storage.
- Pair status color with a label. Report enrollment and connection status
  separately. Label demo data, unknown locations, and unverified paths.
- Keep focus visible, label icon buttons, support keyboard use, and respect
  reduced-motion preferences.

## Network diagrams

The controller coordinates connections. It does not forward user packets.
Distinguish direct connections from relay traffic, and do not draw an active
path without an observation.
