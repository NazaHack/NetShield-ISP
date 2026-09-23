# NetShield-ISP security model

This document records the threat model the platform is built against and the controls that
answer each threat. It is written for engineers extending the codebase: every new endpoint,
model and task is expected to preserve the invariants below.

## What we are defending

NetShield-ISP is a scanning platform operated by an ISP on behalf of many customers. Three
assets matter, in order:

1. **Tenant data separation.** One customer must never observe another customer's targets,
   scans or findings. This is the product's central promise; a breach of it is unrecoverable.
2. **The scanning capability itself.** A platform that can port-scan arbitrary networks is an
   attractive target. An attacker who gains control of the scan pipeline gets a distributed
   scanner pointed at whatever they choose.
3. **Credentials and network topology.** Scan output maps a customer's internal estate.
   Database credentials, signing keys and raw Nmap output are all sensitive.

## Threat model

| # | Threat | Control |
|---|--------|---------|
| T1 | A query or task omits its tenant filter and returns another tenant's rows | `TenantScopedMixin` plus the repository layer; `TenantAwareTask` refuses tenant-less execution |
| T2 | A caller supplies a tenant identifier and is trusted | Tenant derived from the bearer token in `resolve_tenant_scope`; a tenant named in a path or body is checked against it, never obeyed |
| T13 | A caller enumerates another tenant's resources by identifier | Cross-tenant access returns 404 with the same body as an absent resource, so existence is never confirmed |
| T3 | Tenant input reaches the Nmap command line and injects arguments or a shell | Fixed argument vectors, `shell=False`, allowlisted scan profiles, validated targets, constrained port range |
| T12 | A scanned host returns a hostile banner that reaches an operator's browser or log store | `defusedxml` parsing, control characters stripped, every banner string length-bounded, rendered as text by React |
| T14 | Script injected into the console steals the operator's API token | The token lives in an `httpOnly` cookie read only on the server; it is never in the browser bundle |
| T15 | A stolen password database is cracked offline | Argon2id with memory-hard parameters, salted per account, upgraded on sign-in |
| T16 | The login form is used to discover which addresses are registered | One message for every failure, and a dummy verification when the address is unknown |
| T17 | A dismissed employee keeps working credentials until their token expires | The account is re-read on every request; disabling or deleting it revokes access at once |
| T4 | A tenant scans a network they do not own, or the platform's own infrastructure | `SCAN_DENYLIST_CIDRS` enforced regardless of tenant configuration; per-tenant target ownership checks |
| T5 | A compromised API container is used to scan the internal network | Nmap is absent from the API image; the API container drops every capability |
| T11 | The scanner is deployed without the privileges it needs and fails silently | `health_check` performs a real loopback SYN scan and reports the bounding set, file capabilities, NoNewPrivs and `NMAP_PRIVILEGED`; the worker is unhealthy unless the scan actually succeeds |
| T6 | A Redis foothold becomes code execution on every worker | Celery accepts JSON only; `pickle` is refused in both directions |
| T7 | Error responses leak DSNs, SQL or infrastructure hostnames | Uniform error envelope; details logged, opaque message plus correlation id returned |
| T8 | Credentials appear in logs or crash reports | `SecretStr` for every secret; a redaction processor in the logging pipeline |
| T9 | One tenant exhausts shared worker capacity | `MAX_CONCURRENT_SCANS_PER_TENANT`, prefetch of one, hard and soft task time limits |
| T10 | Scan artefacts persist and are read by the wrong tenant | Artefacts written to a dedicated volume with mode 0750, owned by the worker user |

## Control detail

### Tenant isolation

Structural half: `app/models/mixins.py` defines `TenantScopedMixin`, which every business
table must inherit. It makes `tenant_id` non-nullable, indexed, and foreign-keyed to
`tenants.id` with `ON DELETE CASCADE`, and adds a composite `(tenant_id, created_at)` index
matching the universal access pattern.

Relational half: `scan_results` goes further than a column. It carries a composite foreign key
from `(scan_id, tenant_id)` to `scans (id, tenant_id)`, so a result whose tenant differs from
its parent scan's tenant cannot be inserted at all. This is strictly stronger than a reference
to `tenants` would be, which is why that model is the one place where
`TenantScopedMixin.__tenant_foreign_key__` is disabled. The guarantee holds against raw SQL, a
future refactor and a bug in a repository method alike, and it is asserted directly in
`tests/integration/test_schema.py`.

Behavioural half: a column cannot stop an unscoped `SELECT`. Queries go through the repository
layer, which takes the tenant from the authenticated principal and applies it. Primary keys are
UUIDv4 rather than serial integers, so identifiers in API paths leak neither tenant volume nor
a means of enumerating another tenant's resources.

Request half: the acting tenant is decided in exactly one place, `resolve_tenant_scope` in
`app/api/dependencies.py`, and is derived from the caller's bearer token rather than from the
request. A path parameter or body field naming a tenant is an assertion the server checks, never
an instruction it obeys. Endpoints depend on the resolved scope rather than on a raw path
parameter, so the identifier reaching a repository has already been authorised.

### Why cross-tenant access returns 404

A `403 Forbidden` confirms that the named resource exists. On a platform whose whole promise is
that tenants cannot observe each other, that acknowledgement is itself a leak: it lets one
customer enumerate another's scans and targets by identifier, learning volume and timing without
ever reading a body.

Every cross-tenant attempt is therefore answered `404 Not Found`, with the same body a genuinely
absent resource produces. The single exception is tenant administration, where the response is
403: the caller is authenticated and the endpoint's existence is not a secret, only their
authority to use it.

Queue half: `TenantAwareTask.__call__` raises if a task is invoked without an explicit
`tenant_id`. A refactor that drops the scope produces an immediate, loud failure instead of a
task that quietly operates on every tenant's rows.

### Command execution

Nmap is invoked with a fixed argument vector and `shell=False`. No caller-supplied string is
ever concatenated into a command line. Scan parameters are selected from server-side profiles
rather than passed through, and targets are parsed into `ipaddress` objects and checked against
the denylist before a scan is enqueued.

The first line of that defence is `app/core/network.py`, which every stored target passes
through. Restricting the accepted grammar to what `ipaddress` parses rejects shell
metacharacters, Nmap option injection such as `--script=http-shellshock` or `-oN /app/main.py`,
hostname lookups and Nmap's own shorthand ranges in one step. A CHECK constraint on
`network_targets.ip_address_or_cidr` repeats the restriction in the database, so a manual
INSERT cannot plant a value that later reaches a command line.

`app/workers/tasks/system.py` shows the pattern for the simplest case, the `nmap --version`
probe: a constant argv, `shell=False`, a timeout, and `check=False` with an explicit return
code check.

The scan command itself is built in `app/workers/scanning/command.py`. Its vector is a fixed
flag list followed by targets that have each been validated as an IP network, so targets are the
trailing arguments and none of them can be read as an option. The port range, the one remaining
free-form element, is restricted to digits, commas and hyphens with each bound checked against
1-65535.

Ranges supplied inline for an ad-hoc scan go through exactly the same validation and policy as
registered ones, at the API edge and again in the worker. The queue is a trust boundary: a task
must not assume its arguments were produced by the code that normally produces them.

A tenant user's inline targets must additionally fall inside a range already registered to their
client, checked by network containment rather than equality so that a single host inside an owned
block is allowed. Without that check, target registration would stop meaning anything.

Policy is applied before the vector is built. A set of ranges is refused whatever a tenant has
registered: loopback, link-local including cloud instance metadata, multicast, broadcast and the
operator-configured denylist. Containment is tested by overlap rather than by subset, so owning
`0.0.0.0/0` is not a route to scanning them. A per-scan address ceiling caps how much one job may
cover. A forbidden range is skipped and reported rather than failing the whole scan, so one
misconfigured entry cannot stop an ISP auditing the rest of its estate.

### Scanner output is untrusted input

Everything in an Nmap report that describes a service is banner text returned by the scanned
host. `app/workers/scanning/parser.py` treats the document accordingly:

- `defusedxml` parses it, which closes external entity resolution and entity-expansion denial of
  service. A report containing either is rejected rather than parsed.
- Every banner-derived string is stripped of control characters and length-bounded before it
  becomes a finding, because those values are rendered in an operator's browser and written to a
  log aggregator.
- Addresses from the report go through the same parser as user input, so a malformed address is
  dropped rather than stored.
- The retained per-host evidence fragment is capped, and the whole report is refused above a size
  limit, so a hostile or runaway scan cannot push a worker into swap.

### Privilege separation

| Container | Runs as | Capabilities | Scanner |
|-----------|---------|--------------|---------|
| `backend` | uid 10001 | none | absent |
| `celery_worker` | uid 10001 | `NET_RAW`, `NET_BIND_SERVICE` | Nmap |
| `frontend` | `node` | none | absent |
| `redis` | redis | none | absent |
| `db` | postgres | default set | absent |

`db` keeps the default capability set because the PostgreSQL entrypoint needs
`CHOWN`/`SETUID`/`SETGID` to initialise its data directory. `CAP_NET_ADMIN` is granted to
nothing: no scan type this platform runs needs it.

The worker obtains raw sockets through Linux file capabilities set on the Nmap binary
(`cap_net_raw,cap_net_bind_service+eip`), not by running as root. The container bounding set is
what makes those file capabilities effective, which is why the two halves are configured
together.

### Why the worker does not set `no-new-privileges`

Every other container sets it. The worker cannot, and the reason is kernel behaviour rather
than preference.

A non-root process gains capabilities on `execve` only through the executed file's capabilities.
`prctl(PR_SET_NO_NEW_PRIVS)` tells the kernel to refuse any `execve` that would grant privileges
the caller did not already hold, and file capabilities are exactly such a grant. Setting
`no-new-privileges` on the worker therefore discards Nmap's file capabilities, and every SYN scan
fails with a permission error that looks like a network problem.

The alternatives are worse. Running the worker as root inside the container to hold the
capability directly gives up the unprivileged-process property that matters most here. Ambient
capabilities would work but are not exposed by the Docker API.

Two things keep this from becoming a silent hole. The container's bounding set still contains
only `NET_RAW` and `NET_BIND_SERVICE`, so `no-new-privileges` is not protecting against much
that the bounding set does not already cover. And the `netshield.system.health_check` task reads
`/proc/self/status` together with the scanner's extended attributes and reports all three
governing factors, so a wrong combination surfaces as an unhealthy worker.

### Nmap must be told it is privileged

Nmap decides whether it may run a raw-socket scan by calling `geteuid()`, not by inspecting its
own capabilities. A non-root process holding CAP_NET_RAW through file capabilities is therefore
still refused with *"You requested a scan type which requires root privileges"*.

The worker image sets `NMAP_PRIVILEGED=1`, which is the documented way to combine Nmap with the
Linux capabilities system. Without it the entire privilege model above is inert, so the worker's
health check treats a missing `NMAP_PRIVILEGED` as one of the four preconditions it reports.

### Readiness is verified, not inferred

The kernel's capability rules are subtle enough that modelling them in code is a liability. The
`netshield.system.health_check` task therefore establishes raw-socket readiness by performing an
actual single-port SYN scan against the loopback interface, which costs milliseconds and needs no
external network. The capability fields it reports alongside the result exist to explain a
failure, not to decide it.

The loopback address used by that probe is not subject to the tenant scan denylist: the worker is
probing itself, not auditing a customer network.

### Build-time verification of the capability grant

The worker image runs `nmap --version` before granting file capabilities and verifies the grant
afterwards by reading the extended attribute, never by executing the binary again.

The kernel returns `EPERM` from `execve` whenever a file's permitted capability set contains
anything outside the calling process's bounding set. Build environments differ on this: Docker's
default capability set includes `CAP_NET_RAW`, Podman's does not. An image that executes Nmap
after `setcap` therefore builds on Docker and fails on Podman with a misleading
"Operation not permitted". Reading the attribute needs no privilege and still catches the real
risk, which is a builder or storage driver silently dropping extended attributes.

### Transport and browser surface

The API emits a restrictive Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`,
`no-referrer` and `Cache-Control: no-store` on every response, plus HSTS in production. CORS
uses an explicit origin list; a wildcard combined with credentials would let any site drive the
API with a victim's session.

The dashboard renders untrusted content taken from scanned networks, including hostnames,
service banners and Nmap script output. Its CSP is correspondingly strict, and it is marked
`noindex`. Those values are rendered as text through React, which escapes them, and the API has
already stripped control characters and bounded their length before they were stored.

### The operator console holds a credential the browser never sees

The console acts with an administrator API token, which can create and delete every tenant on
the platform. That token is stored in an `httpOnly` cookie and read only on the Next.js server;
no component receives it and it is absent from the browser bundle. A cross-site scripting flaw in
the console can make the victim's browser act as the operator for the life of the session, but it
cannot exfiltrate the credential for use elsewhere or after the session ends.

The two browser-facing routes under `/api/console/` exist because of this: the browser cannot
call the API directly, so status polling and the JSON export are proxied by the server, which
attaches the token and applies the same authorisation as any other read.

A session the API rejects, whether expired or scoped to a single tenant rather than the platform,
is discarded rather than left to fail one component at a time.

### Secrets

Secrets are held in `SecretStr` and never logged. The logging pipeline redacts a denylist of
sensitive keys as a second line of defence. `.env` is git-ignored, created by
`scripts/generate_env.py` with mode 0600, and the configuration layer rejects the template's
placeholder signing key outright.

### Authentication

Users sign in with an email and password and receive a JWT bearer token signed with `SECRET_KEY`.

**Passwords.** Argon2id, with the `argon2-cffi` defaults that track RFC 9106. Its memory cost is
what makes an offline attack on a stolen database expensive, which bcrypt's pure CPU cost no
longer does against GPUs. A minimum length is enforced rather than a composition rule, because
composition rules push people toward predictable substitutions. Hashes are upgraded transparently
on the next successful sign-in when the cost parameters are raised.

**Account enumeration.** A failed sign-in returns one message whatever went wrong, and an unknown
email still runs a verification against a dummy hash, so the response time does not reveal which
addresses are registered.

**Tokens.** The decoder pins the algorithm to the configured one rather than trusting the token
header, which closes the `alg: none` downgrade and the "RSA public key used as an HMAC secret"
confusion. Issuer and audience are verified, so a credential minted for a sibling service sharing
the key is still rejected. Incoherent claim sets, such as an admin token that also names a
tenant, are refused rather than resolved by guessing.

**Revocation.** The account named by a token is re-read from the database on every request, and
its tenant is checked against the token's. Disabling or deleting a user therefore revokes their
access immediately rather than at the token's expiry. Lifetimes remain short via
`ACCESS_TOKEN_EXPIRE_MINUTES`, and rotating `SECRET_KEY` invalidates every outstanding token at
once.

**Role and tenancy cannot disagree.** A check constraint on `users` makes an administrator with a
tenant, or a tenant user without one, impossible to insert. The authorisation layer therefore
never has to decide what such an account would mean.

Two limits worth stating plainly:

- **`SECRET_KEY` is the platform's root secret.** Anyone holding it can mint a token for any
  account, including an administrator, without touching the database.
- **Login is rate limited.** Failed sign-ins are counted in Redis per email and per source IP
  over a fixed window (`LOGIN_MAX_ATTEMPTS` in `LOGIN_ATTEMPT_WINDOW_SECONDS`). Once either scope
  reaches the limit the endpoint answers `429` with a `Retry-After` until the window passes, and
  a lockout hides a correct password too, so an attacker who exhausts their guesses cannot
  continue. A successful sign-in clears the counters, so an operator's own typos never lock them
  out. The limiter fails open: if Redis is unreachable it allows the attempt rather than locking
  everyone out, and logs the event. Per-IP counting can catch several operators behind one NAT in
  the same bucket, which is acceptable for an internal tool with few operators.

## Invariants for contributors

1. Every business table inherits `TenantScopedMixin`. A model may disable the direct foreign key
   only by replacing it with a stronger constraint, as `ScanResult` does.
2. Every query filters by the authenticated tenant. No exceptions, including admin tooling.
3. Every task that touches tenant data inherits `TenantAwareTask` and receives `tenant_id`.
3a. Every endpoint that touches tenant data depends on `resolve_tenant_scope` or checks
   `Principal.may_act_for` itself. No endpoint reads a tenant identifier straight from the
   request and uses it in a query.
4. No caller-supplied string reaches a command line, a file path or raw SQL.
5. Error responses carry a correlation id and nothing else the caller did not already know.
6. New dependencies are pinned and pass `pip-audit`.
7. A response model never gains a password hash field. `UserRead` has none, which is what stops
   one leaking when a column is added to the table.
