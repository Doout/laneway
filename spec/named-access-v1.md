# Named access selectors v1

## Scope

Named access selectors let an administrator grant a network-scoped access
subject a stable Resource and Service pair. They compile to the same node ID,
prefix, protocol, and destination-port selectors used by raw ACL rules. They do
not introduce an application proxy or a second dataplane policy language.

The existing `access_users` and `access_teams` records remain network-scoped
policy subjects. They are not global people, identity-provider accounts, or
administrator principals. A future durable person model can link those records
without redefining their identity or ownership semantics.

## Resources

A Resource has an immutable ID, network, name, target, and creation time. Its
enabled state may change.

- A Node Resource names exactly one active Node in the same Network. It grants
  only that Node's active overlay host addresses; it never grants Exit use.
- A prefix Resource names a canonical, non-default prefix and is pinned to
  exactly one approved subnet Route in the same Network. The selected prefix,
  Route prefix, and Route Node are captured together. The selected prefix MUST
  be contained by that Route. The captured Route Node is the dataplane next
  hop; compilation fails closed if the Route ID ever resolves to a different
  Node or prefix.

Resource names are unique within one Network. Renaming or silently retargeting
a Resource is not supported in v1. Administrators create a new Resource when
the identity or routing target changes. Route identity, Connector, advertised
prefix, mode, metric, and validity are immutable; approval and withdrawal remain
lifecycle state transitions.

## Services

A Service has an immutable ID, network, name, protocol, port selection, and
creation time. Its enabled state may change. Protocol is one of `any`, `tcp`,
`udp`, `icmp`, or `icmpv6`.

Only TCP and UDP Services may contain destination-port ranges. Ranges are
bounded to 1 through 65535, sorted by first port, and merged when they overlap
or are adjacent. TCP and UDP Services MUST contain at least one range; selecting
every destination port requires the explicit range 1 through 65535.
Non-TCP/UDP Services MUST omit ranges. Port rows are staged only inside the
Service creation transaction and then sealed against insertion, update, or
deletion.

## Grants and compilation

A named Resource grant binds one network-scoped User or Team to one Resource
and one Service in the same Network. The tuple is unique per subject. Grants
are immutable and are removed explicitly.

For a User-bound Node, the controller expands direct and Team-derived grants
in grant-ID order. Each named grant produces one priority-zero accept rule with:

- every active Node owned by the User as the source Node set;
- the Resource's current authorized Node and prefix as the destination;
- the Service protocol and canonical destination-port ranges; and
- the grant ID as the policy rule ID.

The existing managed-user terminal deny remains after all managed accept
rules. Raw ACL rules remain interoperable but cannot broaden access past that
managed boundary.

Compilation MUST omit a named grant when its Resource or Service is disabled,
its Node is revoked or expired, or its pinned Route is withdrawn, expired,
changed away from an approved subnet Route, or no longer has an active Node.
The controller MUST NOT fall back to another Route or infer a replacement
Connector. Corrupt selector state makes snapshot construction fail rather than
broadening the selector.

## Lifecycle and audit

Creating or enabling/disabling a Resource or Service, and creating or deleting
a named Resource grant, increments the Network configuration epoch when state
changes. Every state change records the authenticated administrator actor and
the affected durable object in the audit log.

Backups at this schema version include all named-access tables and their exact
SQLite tables, indexes, checks, foreign keys, and triggers. Restore rejects
missing or weakened named-access authorization schema.
