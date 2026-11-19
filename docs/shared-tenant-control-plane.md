# Shared Rust control plane

Run one Rust controller and one Rust edge relay. The edge serves the platform
hostname (for example, `lane.example.com`) and one hostname per tenant (for
example, `acme.lane.example.com`). Each hostname has its own administrator
directory, sessions, database, root credential, workload CA, and network.
The platform console is also isolated: its administrators cannot browse a
customer's network from that console.

Shared mode is opt-in. Each tenant has one routable workload network.
Standalone self-hosted installations use the existing installer and
`laneway-controller serve`; they do not need a Platform directory, a tenant
manifest, or a connection to the hosted control plane.

## Preview the operator Platform

The Platform is a separate, loopback-only console. It lists configured
tenant hostnames and tracks new requests without exposing instance APIs or
credentials. Use SSH forwarding for remote access unless you explicitly set
up the shared HTTPS relay integration below. Starting the backend alone does
not change the root hostname or any existing tenant.

```sh
laneway-controller platform init /path/to/private/platform
laneway-controller platform serve /path/to/private/platform /path/to/active-tenants.json 127.0.0.1:4177
```

Open `http://127.0.0.1:4177/` and sign in as `operator` with the password
in the private state directory's `operator.password` file. Choose
**Reserve name** to queue a tenant. An initial manifest may contain just
`domain`, `public_listen`, and an empty `tenants` array.

Prepare tenant-specific certificates, credentials, and relay configuration
as described below. Write a private provisioning JSON file with
`deployment` (the same object used in the manifest), `ipv4_pool`,
`relay_certificate` (the relay workload certificate's absolute path), and
`relay_endpoint` (the node-reachable host and UDP port). Point the
deployment's `database` at a new absolute path.
Run staging as the service user, or arrange ownership of the resulting
database and lock file before activation.

```sh
laneway-controller platform stage /path/to/private/platform /path/to/active-tenants.json acme /path/to/acme-provision.json
```

Staging initializes a fresh database, registers its relay, and checks the candidate against
shared-runtime identity rules. It writes `acme.manifest.json` into the
private Platform directory without publishing anything or restarting
services. Review the relay configuration and DNS. Before applying, compare
the printed base SHA-256 with the current active manifest; never apply a
stale candidate. Activate one tenant at a time through the normal shared
deployment process, then verify HTTPS and bootstrap the tenant owner with
the existing CLI. If staging fails after writing a database, inspect that
unpublished file before reusing its path. Public Platform auth, automatic
activation, and owner invite links are not part of this preview.

### Serve the Platform on the shared HTTPS root

The shared relay can explicitly proxy the Platform's directory and reservation
form on the base hostname. Set `platform_socket` in the root relay config's
`[public_https]` section to an absolute Unix socket path accessible only to
the relay. Do not set it in a tenant relay config. Connect the socket to the
Platform backend on `127.0.0.1:4177` with a local socket proxy, and keep that
backend off public interfaces.

Open the root HTTPS URL and sign in with the Platform's `operator`
credential, not a tenant administrator account. Sessions expire after eight
hours or when the Platform backend restarts. **Sign out** revokes the
current session immediately. The
relay preserves existing discovery and workload paths; only the directory at
`/`, the reservation form at `/tenants`, and the sign-in and sign-out paths
under `/platform/` go to the Platform. Restart the
shared relay to apply or remove the setting. No change is required for
self-hosted installations.

## Provision a tenant

1. Allocate a lowercase DNS label, unique controller and relay identities,
   an overlay pool, and the listeners used by the controller and relay.
   Pick non-overlapping pools unless you explicitly need overlapping
   addresses. Use a fresh offline root and intermediate for each tenant;
   the existing [recovery-kit tooling](../deploy/compose/README.md) can
   generate them. Keep the offline root private key and recovery identity
   off the server.
2. Issue controller and relay workload certificates for the tenant hostname.
   Both must contain that tenant's network ID and their respective service
   IDs. Put the issuer first and the tenant root last in the issuer chain.
   Give the tenant a unique, protected root credential. Initialize the
   database as the controller service user:

   ```sh
   laneway-controller init /var/lib/laneway/acme/controller.db \
     /etc/laneway/acme/controller.crt acme 100.96.32.0/24
   ```

3. Add the following tenant object to the manifest. Set its top-level
   `domain` to `lane.example.com` and `public_listen` to `0.0.0.0:443`.
   The `tenants` array contains objects like this one. The optional
   top-level `platform` field contains a deployment object of the same
   shape, without a slug. It can point at the existing base hostname's
   deployment if that database contains exactly one workload network.
   Without it, the base hostname is not served.

   ```json
   {
     "slug": "acme",
     "deployment": {
       "database": "/var/lib/laneway/acme/controller.db",
       "controller_https": "0.0.0.0:8444",
       "controller_quic": "0.0.0.0:8444",
       "controller_certificate": "/etc/laneway/acme/controller.crt",
       "controller_key": "/etc/laneway/acme/controller.key",
       "root_token": "/etc/laneway/acme/admin.token",
       "issuer_chain": "/etc/laneway/acme/intermediate-chain.crt",
       "issuer_key": "/etc/laneway/acme/intermediate.key",
       "client_ca": "/etc/laneway/acme/ca.crt",
       "bootstrap_profile": "/etc/laneway/acme/bootstrap.json",
       "controller_renewal_dir": "/var/lib/laneway/acme/controller-tls",
       "relay_config": "/etc/laneway/acme/relay.toml"
     }
   }
   ```

4. Use a tenant-specific [relay config](../deploy/examples/relay.toml).
   With colocated controller and relay processes in this example, set
   `controller.endpoint = "https://acme.lane.example.com:8444"`,
   `controller.server_name = "acme.lane.example.com"`,
   `controller.dial_address = "127.0.0.1:8444"`, and
   `controller.quic_endpoint = "127.0.0.1:8444"`. Use the tenant's pinned
   network and controller service IDs and its own relay workload credentials.
   Set `tcp_fallback.listen = "0.0.0.0:443"` to match the manifest, give
   `relay.listen` a unique UDP port, and set `public_https.server_name` to
   the tenant hostname. If using discovery, put the node-reachable controller
   HTTPS and QUIC endpoints in the tenant's bootstrap profile. Register the
   tenant relay using its node-reachable UDP address.
5. Point the base DNS record and the desired tenant DNS records (or a wildcard)
   at the edge. Use separate certificates with the existing per-host public
   TLS renewal configuration, or provision an externally managed public
   certificate with both base and wildcard names. A wildcard by itself
   does not cover the base hostname. Public certificates are separate from
   workload certificates. The edge accepts only manifest hostnames even if
   wildcard DNS resolves an unknown tenant. Open each required workload TCP
   and UDP port to its intended clients; a port being separate is not an
   authorization check.
6. Start the controller and relay under the service manager using the same
   manifest, readable only by the operators and the services. Restrict
   private keys and credentials to the respective service user. Set
   `LANEWAY_CONSOLE_DIR` to the built console when running outside the
   controller image.

   ```sh
   laneway-controller serve-tenants /etc/laneway/tenants.json
   laneway-relay --tenants /etc/laneway/tenants.json
   ```

7. Use the tenant CA, pinned network and controller IDs, and protected root
   credential to run `laneway controller administrator bootstrap` against
   the tenant's workload HTTPS endpoint. The CLI prompts for the owner's
   password. The root credential is not accepted at the public HTTPS edge.
   Then sign in at the tenant's hostname and verify that only its own
   network appears.

Back up each controller database and recovery kit separately before adding
tenants or changing the shared services. Apply manifest changes by restarting
both services together in a maintenance window. The single-tenant Compose
installer and updater do not manage this manifest; keep existing deployment
files intact for rollback. Shared mode isolates tenants within one service
process per component; it does not isolate tenants from a compromised host
or from shared capacity limits.

## Verify isolation

`make rust-tenant-interop` runs the actual Rust controller and relay on
loopback with a platform hostname and two tenants. It checks tenant
sign-in, network inventory, discovery, enrollment, QUIC relay traffic and
TCP fallback, including rejection of foreign sessions, network IDs, node
credentials, enrollment tokens, and cross-tenant packets.
