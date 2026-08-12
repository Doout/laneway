# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

The administrator console is a React and TypeScript single-page application built with Vite and emitted as a static bundle suitable for serving beside the controller. Server state uses TanStack Query, form boundaries use React Hook Form and Zod, and accessible custom components carry the approved Laneway visual system.

Laneway should also have a later desktop client, but it is a separate end-user surface rather than a wrapper around the administrator console. That client should use Tauri 2 with the shared React design system and communicate with the local Laneway daemon for profile, connection, exit-node, tray, update, and diagnostic workflows. The administrator console remains web-first.

## Users

The primary users are infrastructure, network, security, and IT administrators who would otherwise evaluate products such as Twingate or NetBird. They need to enroll machines and people, publish private routes, control who can use those routes, and understand administrative changes without working directly in the controller CLI.

## Product Purpose

Laneway connects clients to Linux hosts and private networks through an encrypted IP overlay. The admin console should make the controller's operational workflows legible and safe: add nodes, issue user access, create and inspect routes, manage access rules, and investigate audit events.

## Positioning

Laneway carries ordinary IP traffic without an application proxy, prefers authenticated direct QUIC paths, and falls back through an authenticated relay while keeping the controller out of the packet path.

## Operating Context

Administrators currently operate Laneway through the `laneway control` and `laneway controller` commands. Durable nodes, Connectors, exit nodes, and remembered or ephemeral user enrollments share one controller-owned inventory. Routes can target private IPs or prefixes through a Connector, use NAT or routed mode, carry metrics and lifetimes, and can be restricted to an enrolled user through an ACL rule.

## Capabilities and Constraints

- The existing controller can create and list networks; issue enrollment tokens; list, revoke, and set capabilities on nodes; register and manage relays; advertise, assign, approve, withdraw, and list routes; create, delete, and list ACL rules; list certificates; and list audit events.
- The Compose control-plane workflow can issue user login tokens, create single-use node or Connector invitations, add a route through a Connector, and show deployment status.
- The current data model records user access as remembered or ephemeral node enrollments, not as a persistent email-based people directory. Email invitations, identity-provider sync, groups, and tenant roles would require confirmed backend expansion and must not be presented as shipping capabilities.
- The first design scope is an administrator-facing web console. It must preserve the controller's fail-closed security model and avoid implying that the controller carries user traffic.

## Brand Commitments

The product name is Laneway. The console should meet the usability and craft bar of Twingate and NetBird while retaining Laneway's own product model and terminology.

The visual target is now deliberately between NetBird and Twingate, with NetBird carrying more weight in the UX. Laneway should use a task-oriented grouped sidebar, contextual breadcrumbs, chip-based filters, topology-first access explanations, in-place enrollment steps, and detail drawers or split workspaces where they preserve context. It should retain Twingate's restraint, readable density, explicit primary actions, and serious operational tone. The result must feel like Laneway rather than a re-skinned copy of either product.

The approved theme remains a dark operating-room environment. Surfaces may separate more clearly than the original graphite build, but light mode, generic card dashboards, and wide horizontal product navigation are not the default direction.

The execution path is comp-led: the complete page set must be rendered and approved before application UI implementation begins.

The render review set contains 24 screens: controller sign in; overview; node inventory, creation, token, detail, capability editing, and revocation; user enrollment inventory, issuance, token, and detail; route inventory, creation, approval, and detail; ACL inventory, editing, and evaluation detail; infrastructure overview, network detail, and relay registration/detail; tokens and certificates; and audit events with event detail.

## Evidence on Hand

- `README.md` documents the quick-start workflow and product promise.
- `spec/architecture.md` defines the controller, relay, endpoint, CLI, direct-path preference, relay fallback, and fail-closed behavior.
- `go/cmd/laneway/cli.go`, `controller.go`, and `controller_overview.go` expose the current administrator workflows and record shapes.
- The controller stores networks, nodes, routes, ACL rules, relays, enrollment tokens, certificates, and audit events.
- No logo artwork, persistent user-directory model, customer claims, commercial metrics, or production dashboard data is present. Page renders use clearly synthetic example records and must not invent market claims.

## Product Principles

- Show effective access and forwarding paths, not abstract configuration alone.
- Keep every destructive or access-broadening action explicit, reviewable, and attributable.
- Use the controller's real terminology and capabilities; surface product gaps instead of disguising them.
- Make routine enrollment and routing fast while keeping advanced protocol detail available on demand.
- Treat operational state and auditability as first-class product content.

## Accessibility & Inclusion

The web console should meet WCAG 2.2 AA, remain fully keyboard-operable, never depend on color alone for status, and support dense operational data without forcing horizontal scrolling at common laptop widths.
