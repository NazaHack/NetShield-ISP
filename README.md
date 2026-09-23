# NetShield-ISP

Multi-tenant network audit and port scanning platform for Internet Service Providers.

FastAPI + Celery + PostgreSQL + Redis on the backend, Next.js + Tailwind + shadcn/ui on the
front end, orchestrated with Docker Compose. Nmap runs in an isolated worker container that
holds raw-socket capability without running anything as root.

---

## Architecture

```
                        ┌──────────────┐
  browser  ──────────▶  │   frontend   │  Next.js 15 · :3000
                        └──────┬───────┘
                               │ REST
                        ┌──────▼───────┐
                        │   backend    │  FastAPI · :8000 · no scanner, no capabilities
                        └──┬────────┬──┘
                  enqueue  │        │  read/write
                     ┌─────▼──┐  ┌──▼──────────┐
                     │ redis  │  │ postgresql  │  tenant-scoped rows
                     └─────┬──┘  └──▲──────────┘
                    consume │        │
                    ┌───────▼────────┴───┐
                    │   celery_worker    │  Nmap · CAP_NET_RAW · runs as uid 10001
                    └────────────────────┘
```

The API never executes a scanner. It validates and authorises a request, then puts a job on
Redis. Only the worker image contains Nmap, and only the worker container is granted the
capabilities a SYN scan needs.

## Repository layout

```
NetShield-ISP/
├── docker-compose.yml        5 services: db, redis, backend, celery_worker, frontend
├── Makefile                  developer entry points (`make help`)
├── .env.example              every environment variable, documented
├── scripts/generate_env.py   creates .env with generated secrets
├── backend/
│   ├── Dockerfile            FastAPI image (no Nmap)
│   ├── Dockerfile.worker     Celery image (Nmap + file capabilities)
│   ├── requirements*.txt     pinned runtime and development dependencies
│   ├── pyproject.toml        ruff, mypy, pytest, coverage and bandit configuration
│   ├── alembic/              migration environment and versioned migrations
│   ├── seed.py               idempotent development seed data
│   ├── app/
│   │   ├── core/             settings, logging, middleware, network parsing, tokens
│   │   ├── db/               declarative base, async and sync session factories
│   │   ├── models/           ORM models, tenancy mixins and user accounts
│   │   ├── repositories/     tenant-scoped data access for the API
│   │   ├── schemas/          Pydantic request and response models
│   │   ├── api/
│   │   │   ├── dependencies.py  authentication and tenant scoping
│   │   │   └── v1/endpoints/    versioned HTTP endpoints
│   │   ├── workers/
│   │   │   ├── celery_app.py   Celery configuration and the tenant-aware base task
│   │   │   ├── scanning/       the scan engine: policy, runner, parser, diff, repository
│   │   │   └── tasks/          registered Celery tasks
│   │   ├── diagnostics/      operator entry points (`python -m app.diagnostics.*`)
│   │   ├── main.py           application factory
│   │   └── healthcheck.py    stdlib-only container probe
│   └── tests/
│       ├── integration/      database-backed tests, skipped without PostgreSQL
│       └── ...               unit tests
└── frontend/
    ├── Dockerfile            multi-stage: deps → development / builder → production
    ├── components.json       shadcn/ui configuration (new-york, CSS variables)
    ├── tailwind.config.ts    design tokens including the finding-severity scale
    └── src/
        ├── middleware.ts     session gate for page routes
        ├── app/
        │   ├── login/        sign-in page
        │   ├── (console)/    the operator console
        │   └── api/console/  server-side proxy: status polling, JSON export, sign-out
        ├── components/
        │   ├── console/      selector, launcher, status badge, tables, alerts, export
        │   └── ui/           shadcn/ui primitives
        └── lib/              API client, server-side data access, session, actions
```

## Quick start

Requirements: Docker Engine 24+ with the Compose plugin, and GNU Make.

```bash
make init     # writes .env with generated SECRET_KEY and database/Redis passwords
make build    # builds all five images
make up       # starts the stack
```

Then open:

| Service        | URL                            |
| -------------- | ------------------------------ |
| Dashboard      | http://localhost:3000          |
| API docs       | http://localhost:8000/docs     |
| Readiness      | http://localhost:8000/health/ready |

`make down` stops the stack and keeps your data. `make clean` deletes the volumes too.

## Everyday commands

```bash
make logs                       # follow every service
make test                       # backend test suite
make check                      # lint + types + tests + security scan, both halves
make migration m="add tenants"  # autogenerate an Alembic migration
make migrate                    # apply migrations
make seed                       # load development seed data (idempotent)
make create-admin email=... name="..."   # bootstrap the first administrator
make worker-ping                # dispatch a health check through Redis, print the report
make nmap-caps                  # show the worker's uid and the Nmap capability set
make runtime                    # show which Compose implementation was detected
```

## Data model

```
Tenant ──< NetworkTarget          ranges the tenant is authorised to audit
   │
   └────< Scan ──< ScanResult     one job, one row per host that answered
```

| Table | Holds | Notes |
| ----- | ----- | ----- |
| `tenants` | One ISP customer account | `code_name` is a unique slug, enforced by a CHECK constraint |
| `network_targets` | Address ranges | Stored as canonical CIDR; validated on write and by a CHECK constraint |
| `scans` | Scan jobs | `status` is a native PostgreSQL enum: PENDING, RUNNING, COMPLETED, FAILED |
| `scan_results` | Per-host findings | `open_ports` is JSONB with a GIN index; `raw_output` keeps the evidence |

Three schema decisions are load-bearing and should not be undone casually.

- **`scan_results` carries `tenant_id`** even though a join through `scans` could
  derive it. Direct filtering is what the platform's isolation rule requires, and the column
  enables the next point.
- **A composite foreign key ties `(scan_id, tenant_id)` to `scans (id, tenant_id)`.** A scan
  result whose tenant differs from its parent scan's tenant cannot be inserted at all, by any
  code path including raw SQL.
- **Ranges are stored canonically and never widened.** `192.168.1.5/24` is rejected rather than
  normalised to `192.168.1.0/24`, because silently turning one host into 256 is the wrong
  default for an audit platform.

Everything a tenant owns is removed when the tenant row is deleted, through `ON DELETE CASCADE`.

## Operator console

The dashboard at `http://localhost:3000` is an operator console. It covers the whole workflow:

- **Client selector** in the top bar switches the active ISP customer. The choice lives in the
  URL rather than in component state, so a link is shareable and the back button behaves.
- **Ranges** view lists, adds and removes the address blocks assigned to the active client.
  Validation is left to the API: the server is the only place that can apply platform policy,
  and a second implementation in the browser would drift out of step with it.
- **Verificación rápida** on the operator's home page scans a range typed straight in, with no
  client involved. Registering a customer is for ranges you audit repeatedly and want a history
  for; a one-off check needs none of that.
- **Panel de ejecución** runs a full audit of every registered range with one button. The
  operator enters nothing, which is the point.
- **Progress indicator** polls while a scan is in flight and stops as soon as it reaches a
  terminal state. State is never conveyed by colour alone: every badge carries a label and a
  distinct icon.
- **Detailed report** shows hosts, ports, protocols and service versions, an "Alertas / Cambios"
  section comparing against the previous scan, and export to JSON or PDF.
- **Clients** section, for administrators only, registers ISP customers and manages who from each
  of them can sign in.

### Accounts and sign-in

Users sign in with an email and a password. Passwords are stored as Argon2id hashes, and no
endpoint can return one.

There are two kinds of account:

| Role | Belongs to | Can do |
| ---- | ---------- | ------ |
| `PLATFORM_ADMIN` | No client | Register and remove clients, create sign-ins for any of them, and act on any client's data for support |
| `TENANT_USER` | Exactly one client | Manage that client's ranges, run its scans and read its reports, and nothing else |

The database enforces that pairing: an administrator with a client, or a client user without one,
cannot be inserted at all. Either would be an identity the authorisation layer could not classify.

An administrator signs in and sees a **Clients** section for registering customers and creating
their sign-ins. A client user has no such section, is taken straight to their own client, and the
API refuses anything else regardless of what the console shows.

Bootstrap the first administrator once, then manage everyone else from the console:

```bash
make create-admin email=ops@example.com name="Operations"
```

`make seed` also creates a development administrator and a client operator, both with the
password printed in its output. The seed refuses to run when `ENVIRONMENT` is production.

**The bearer token never reaches the browser.** Credentials go to a server action, which
exchanges them for a token and stores it in an `httpOnly` cookie read only on the Next.js server.
A cross-site scripting flaw in the console can make the browser act as the operator while the
session lasts, but it cannot read the credential and use it elsewhere.

Every call to the API therefore originates on the Next.js server. The routes under
`/api/console/` are a thin proxy for status polling, the JSON export and sign-out, and they
perform their own session check rather than being redirected by the middleware.

The account is re-read from the database on every request rather than trusted from the token, so
disabling or deleting a user revokes their access immediately instead of when their token
happens to expire.

## HTTP API

| Method | Path | Who may call it |
| ------ | ---- | --------------- |
| POST | `/api/v1/auth/login` | Anyone |
| GET | `/api/v1/auth/me` | Any signed-in account |
| POST | `/api/v1/auth/password` | Any signed-in account, for its own password |
| POST, GET | `/api/v1/users` | Administrator |
| DELETE | `/api/v1/users/{user_id}` | Administrator |
| POST, GET | `/api/v1/tenants/{tenant_id}/users` | That client, or an administrator |
| POST, GET | `/api/v1/tenants` | Administrator |
| GET, PATCH, DELETE | `/api/v1/tenants/{tenant_id}` | Administrator, except GET which a tenant may use on itself |
| POST, GET | `/api/v1/tenants/{tenant_id}/targets` | That tenant, or an administrator |
| GET, PATCH, DELETE | `/api/v1/tenants/{tenant_id}/targets/{target_id}` | That tenant, or an administrator |
| POST | `/api/v1/scans/launch` | The client named in the body, or any signed-in account for an ad-hoc scan |
| GET | `/api/v1/scans/{scan_id}` | The tenant that owns the scan |
| GET | `/api/v1/tenants/{tenant_id}/scans/history` | That tenant, or an administrator |

Interactive documentation is at `/docs` outside production.

### Authentication

Callers present a signed bearer token. **The tenant is a claim inside the token, never a value
read from the request**, so a path parameter or body field naming a tenant is an assertion the
server checks rather than an instruction it obeys.

Two kinds of principal exist. A `tenant` token acts for exactly one tenant. An `admin` token
manages the tenant list, which is inherently cross-tenant because a tenant cannot create itself;
administrator access to tenant data is permitted for operator support and every such access is
logged as an impersonation.

There is no user store yet. Tokens are service credentials issued out of band:

```bash
make token-admin
make token-tenant code=acme-isp
```

### How isolation is enforced

`resolve_tenant_scope` in [backend/app/api/dependencies.py](backend/app/api/dependencies.py) is
the single place the acting tenant is decided. Endpoints depend on it rather than on a raw path
parameter, so the identifier they hand to a repository has already been checked against the
token. Every repository function that touches tenant-owned data takes the tenant as a required
argument and applies it to the statement.

**A cross-tenant attempt returns `404 Not Found`, not `403 Forbidden`.** A 403 confirms the
resource exists, which tells one customer that another customer's scan or target is real. For a
platform whose whole promise is that tenants cannot observe each other, that acknowledgement is
itself a leak. The one exception is tenant administration, where the 403 says only that an
authenticated caller lacks authority for an endpoint whose existence is not secret.

### Ad-hoc scans

`POST /api/v1/scans/launch` takes either a `tenant_id`, whose registered ranges are scanned, or
a `targets` list to check directly. With neither a client nor a registration, an operator can
scan a range immediately.

An ad-hoc scan still belongs to a tenant, because every scan, result and audit record in the
platform does and carving out an exception would mean rows the isolation rules do not cover. It
is attributed to a workspace the operator never creates or manages, flagged `is_system` so it
stays out of the customer list.

There is one such workspace **per operator**, not one for the platform. The per-tenant
concurrency quota exists to stop a single actor monopolising the workers, so a shared workspace
would make every operator compete for the same three slots.

A tenant user may also supply targets, but each must fall inside a range already registered to
their client. Registration is how a customer declares what they are authorised to audit, and
letting them type any address would make that declaration meaningless. An administrator is the
platform operator and is not constrained this way.

## Scanning engine

A scan is one Celery job, `netshield.scans.run_network_scan`. It claims the scan row, resolves
the tenant's registered ranges, runs Nmap, stores one result row per responding host, compares
the outcome against the tenant's previous completed scan, and finishes as COMPLETED or FAILED.

The pipeline is four independently testable pieces under [backend/app/workers/scanning/](backend/app/workers/scanning/):

| Module | Responsibility |
| ------ | -------------- |
| `command.py` | Decides what may be scanned and builds the argument vector |
| `runner.py` | Executes Nmap and bounds its time and output size |
| `parser.py` | Turns the XML report into validated findings |
| `diff.py` | Compares a scan against its predecessor |
| `repository.py` | Every database access, so the tenant filter is auditable in one place |

The command is `nmap -sV -T4 -p 1-10000 --open -n --privileged -oX - <targets>`. Two flags go
beyond the baseline and both are deliberate. `-n` disables DNS, which otherwise leaks the
tenant's address list to the configured resolver and is a common cause of scans that appear to
hang. `--privileged` is required because Nmap gates raw-socket scan types on `geteuid()` rather
than on its own capabilities, and the worker runs unprivileged.

`-oX -` writes to standard output, so no filesystem path derived from tenant data is ever passed
to Nmap.

### Change detection

Every scan is compared against the tenant's last completed scan and the differences come back
with the task result: hosts that appeared or went away, ports that opened or closed, and services
whose version moved on a port that stayed open.

A tenant's first scan reports `has_baseline: false` and no changes. Treating every host as newly
discovered on day one produces noise, not information.

No diff is stored. Both snapshots are persisted, so a comparison can be recomputed at any time,
and changing how a difference is defined needs no backfill.

## Running against real networks

[docs/real-test-runbook.md](docs/real-test-runbook.md) covers what the stack can reach through
its container network, what you may point it at, how long a real audit takes and what to check
when one comes back empty.

## Configuration

Every setting is read from the environment and validated at start-up by
`backend/app/core/config.py`. A malformed value fails the container start rather than the
first request. Two validations are worth knowing about:

- `SECRET_KEY` must be at least 32 characters and must not still contain the template
  placeholder.
- `SCAN_DENYLIST_CIDRS` must parse as networks. These ranges can never be scanned,
  whatever a tenant configures.

`.env.example` documents the full set with defaults.

## Security model

The full rationale is in [docs/security-model.md](docs/security-model.md). In short:

- **Tenant isolation.** `TenantScopedMixin` makes `tenant_id` mandatory, indexed and
  foreign-keyed on every business table. `TenantAwareTask` refuses to execute a queued task
  that was not given an explicit tenant, so a lost scope becomes a loud failure rather than a
  silent cross-tenant query.
- **Least privilege.** The API container drops every Linux capability and has no scanner
  installed. The worker drops every capability except `NET_RAW` and `NET_BIND_SERVICE`, runs as
  uid 10001, and obtains raw sockets through file capabilities on the Nmap binary rather than by
  running as root. Its `health_check` task reports the three factors that govern raw-socket
  access, so a misconfiguration shows up as an unhealthy worker instead of failing every scan.
- **No pickle.** Celery accepts JSON only, in both directions. A pickle-accepting broker turns
  any Redis foothold into code execution on every worker.
- **Contained errors.** Stack traces, DSNs and driver messages are logged, never returned.
  Callers get an opaque message plus a correlation id.
- **Secrets stay out of logs.** Credentials are held in `SecretStr`, and the logging pipeline
  redacts a denylist of sensitive keys.

## Development notes

- **Hot reload works on both halves.** The backend runs Uvicorn with `--reload`; the worker is
  wrapped in `watchmedo auto-restart`, since Celery has no native reloader.
- **The Python virtualenv lives at `/opt/venv`**, outside the bind-mounted `/app`. Changing
  `requirements.txt` and rebuilding takes effect immediately.
- **The frontend's `node_modules` is a named volume**, which Docker populates from the image on
  first start only. After changing `package.json`, run
  `docker compose down -v frontend && make build` or remove the
  `netshield_frontend_node_modules` volume, otherwise the container keeps the old tree.
- **Datastore ports bind to loopback** by default. Override `POSTGRES_HOST_BIND` and
  `REDIS_HOST_BIND` only behind a trusted network.
- **The stack also runs on rootless Podman.** `make` detects the available Compose
  implementation and points it at the Podman socket automatically; run
  `systemctl --user enable --now podman.socket` once first, and `make runtime` to see what was
  detected. Podman omits `CAP_NET_RAW` from its default build-time capability set, which is why
  the worker image never executes Nmap after granting it file capabilities.
- **SELinux hosts need the `z` mount option**, which the bind mounts already carry. Without it
  the container cannot read the source tree at all, and Uvicorn fails with an unhelpful
  "Path 'app' is not readable". The option is ignored on hosts without SELinux.
- **Tool caches are redirected to `/tmp`** inside the development images. The bind-mounted source
  tree belongs to the host user, so ruff, mypy and pytest cannot write their caches beside the
  code.

## Running the quality gates outside Docker

The backend targets Python 3.12.

```bash
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
mypy app alembic tests
pytest
bandit -c pyproject.toml -r app -q
```

```bash
cd frontend
npm ci
npm run lint && npm run typecheck && npm run build
```
