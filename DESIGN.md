# Console design

The admin console and desktop client share [light and dark theme tokens](web/src/design-tokens.css),
Inter for interface text, and JetBrains Mono for technical values. Use a
neutral sidebar, a single divider between rows, and a subtle fill for
selection. Reserve color for focus, the Laneway mark, and meaningful status.

Build console controls from the [shared React components](web/src/components/ui.tsx).
These use UI SDK for buttons, form fields, and search inputs. Keep navigation
links and tables semantic. The [desktop client](docs/desktop-client.md)
manages the local node and has its own navigation.

## Navigation and records

- Put the main action in the page header. Group related views under one
  navigation item, such as Users and Teams under People.
- Keep filters and result counts near the data. Show current records by
  default; give administrators a way to inspect inactive records.
- Lead with names instead of IDs. Display IP addresses, CIDRs, and IDs in
  monospace. Wrap long values in detail views so they remain readable.
- Place a resource type or alias on a second line. Keep full traffic policies
  readable at narrow widths.
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
