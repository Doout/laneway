# Node locations

Networks → Map shows approximate node locations, grouped when pins overlap.
Select a node to inspect its location, configured routes, or set a manual site.
Revoked and expired ephemeral nodes are excluded. Nodes without a location stay
in the list; they are never assigned an invented coordinate.

## Enable automatic lookup

Provision a DB-IP City Lite, GeoLite2 City or GeoIP2 City `.mmdb` database on the controller
and set the following in its TOML configuration:

```toml
[controller]
location_database = "/etc/laneway/GeoLite2-City.mmdb"
```

For containers, mount the file read-only at that path. Obtain and update it through
[MaxMind's database distribution](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
under the operator's account and license. This repository does not bundle or
download the database or store a MaxMind license key. Replace the file atomically
and restart the controller to load an update; never rewrite a mapped file in place.
Missing, invalid, or non-City databases disable enrichment without stopping the
controller. Manual locations work without a database.

### Free alternative without an account

[DB-IP City Lite](https://db-ip.com/db/download/ip-to-city-lite) provides a monthly
MMDB download without a MaxMind account. Download the MMDB gzip file for the
desired month from the official page, verify its published checksum, decompress
it, and point `location_database` to the resulting file. Keep it outside the image
and mount it read-only. Replace it atomically and restart to apply a new month.
This dataset is CC BY 4.0; the map displays the required DB-IP attribution link
when that database is configured. It has reduced coverage and accuracy, and
does not supply an accuracy radius. No node IP is sent to DB-IP during lookups.

The controller uses the socket source address of authenticated configuration
polls and status reports. It ignores client-provided IPs and forwarded headers.
Private, loopback, link-local, CGNAT, and reserved addresses remain unknown.
The node-facing listener must be reached directly for useful IP attribution;
public reverse proxies can otherwise locate the proxy, not the node. Keep lookup
disabled for such deployments and use manual locations. No client update is
needed for ordinary configuration polling.

## Privacy and interpretation

- Lookups run locally. The bundled Natural Earth basemap needs no external tiles.
- Only the latest approximate coordinates, label, accuracy radius, observed public
  IP and timestamp are stored. IP/location history is not stored by this feature.
- Authenticated HTTPS and QUIC configuration polls act as heartbeats, including
  unchanged-configuration responses. An active identity is online for six minutes
  after its last report (the supported poll interval is at most five minutes).
  No heartbeat means unknown, not enrolled-and-online. Manual edits never refresh
  presence. The Nodes view refreshes connection state every 15 seconds without
  reloading the page. Public IP means the socket's NAT/VPN egress, not overlay IP.
- NAT/VPN egress location is not necessarily device location. IP-derived pins are
  approximate, not suitable for physical tracking or access-control decisions.
- Inferred locations older than 24 hours are marked stale. Private/unknown source
  observations clear an old inferred location. Manual overrides remain until cleared.
- Manual edits require `node.manage` for that node's network and are audited;
  reads require `node.read`. Overrides do not alter routing or policy epochs.
- The map shows up to 1,000 inventory records per visible network and indicates
  that limit; it does not claim complete fleet coverage beyond it.

## Connections

This version lists approved configured routes for the selected node, subject to
`route.read`. It deliberately does not draw them as active connections. Live peer
edges require a separate opt-in, bounded, expiring report of peer identity and
direct/relay path. Existing aggregate carrier status is not sufficient. No peer
telemetry or packet inspection has been added here.
