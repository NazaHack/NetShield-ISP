# Running NetShield-ISP against real networks

Written for the operator running this platform. It covers what the stack can reach, what you may
point it at, and how to run a real audit end to end.

## What you may scan

Port scanning is an intrusive act against whatever answers. Point this platform at:

- **networks you operate**, such as your own LAN, your CGNAT pools and your public ranges;
- **a customer's ranges, with their written authorisation**, which is the case the multi-tenant
  model exists to serve;
- **`scanme.nmap.org` (45.33.32.156)**, which the Nmap project publishes explicitly so people can
  test scanners against a real host.

Scanning addresses you neither operate nor have permission for is unlawful in most jurisdictions,
and a `/24` sweep is not subtle: it shows up in the target's logs with your source address on it.

The platform refuses a small set of ranges outright, whatever a client has registered: loopback,
link-local including cloud instance metadata, multicast, broadcast and anything in
`SCAN_DENYLIST_CIDRS`. That list protects infrastructure from an accidental sweep. It is not an
authorisation check and cannot be: only you know which ranges are yours.

## What the stack can reach

The worker runs in a rootless Podman container on its own bridge network and reaches everything
the host reaches, through NAT:

| Target | Works | Notes |
| ------ | ----- | ----- |
| The internet | Yes | SYN scanning included; the file capabilities on Nmap survive the NAT path |
| A routed/public range | Yes | The intended use: an ISP's own public space, CGNAT, a client's public range |
| The compose network | Yes | The other containers are on `10.89.0.0/24` |
| The host's own LAN | Poorly | See below. Use your own console for local-segment scans |

Scans appear to come from the **host's** address, not the container's, because traffic is
NAT'd out through the host. Firewall rules and logs on the target will show the host.

### Why scanning your own LAN from here is misleading

The worker reaches the local LAN only through the container gateway, not on the physical segment.
Two things follow, and both are rootless-Podman limitations rather than bugs in the platform:

- **No ARP.** On a physical LAN, Nmap discovers hosts with ARP and finds only the real devices in
  a second or two. From inside the container there is no ARP, and the gateway answers for the
  whole subnet, so Nmap sees **every** address in a `/24` as "up" — 255 phantom hosts — and then
  port-scans all of them. That is why a local `/24` here takes minutes while the same scan from
  your own console takes seconds: your console is on the physical segment and sees the 2 or 3 real
  devices.
- **Host networking does not rescue it.** Running the worker with `--network host` still fails,
  because a rootless container cannot open the physical interface (`dnet: Failed to open device`).
  Real ARP scanning of the local segment needs rootful Podman or running Nmap on the host itself.

None of this affects the platform's actual job. A routed or public range has no phantom hosts:
every address that answers is a real host somewhere on the internet, so discovery is accurate and
the profiles below make the scan fast. For auditing your own physical LAN, your console is the
right tool; this platform is for the routed ranges an ISP audits.

## Preconfigured lab clients

Two clients are set up for testing:

| Client | Code name | Range |
| ------ | --------- | ----- |
| Laboratorio - Red local | `lab-red-local` | `192.168.1.0/24` |
| Laboratorio - Objetivo publico | `lab-publico` | `45.33.32.156/32` |

Both are ordinary clients. Remove them from the **Clients** section when you are done.

## Running an audit

### From the console

1. Open `http://localhost:3000` and sign in.
2. For a registered client, pick it from the selector and press **Ejecutar Verificación de Red**.
   Every range registered for that client is scanned.
3. For a one-off check, use **Verificación rápida** on the operator home page: type a range and
   press the button. No client needed.
4. The status badge moves from Queued to Scanning to Completed on its own.

### Where the reports are

- A **client's** scans are listed under that client, on its Overview tab. **Open** on a row takes
  you to the report.
- A **quick scan** is listed under **Verificaciones rápidas recientes** on the operator home.
  **Open report** takes you to the same page.

The report itself carries **Export JSON** and **Export PDF** in its top bar. They appear only for
a completed scan: there is nothing to export from one that is queued, running or failed.

### From the API

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@netshield.local","password":"netshield-dev-2026"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# Ad-hoc: no client involved
curl -s -X POST http://localhost:8000/api/v1/scans/launch \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"targets":["192.168.1.0/24"],"port_range":"1-1024"}'

# Poll until it finishes
curl -s http://localhost:8000/api/v1/scans/<scan-id> -H "Authorization: Bearer $TOKEN"
```

## Reaching clients over a VPN

The worker runs in its own network namespace, but its traffic is NAT'd out through the host and
then follows **the host's** routing table. So whatever the host can reach, the worker can reach,
including anything routed over a VPN — no change to the platform is needed.

Two things follow, and both are worth checking before a real client scan:

- **The VPN must be up on the host, and must route the client's range.** Check with
  `ip route get <client-ip>` on the host: if it shows the VPN interface, the worker reaches it;
  if it shows the ordinary internet interface, the VPN is not carrying that range and the scan
  goes out the normal path instead.
- **A split-tunnel VPN only carries the ranges it is configured for.** A public range that is
  not in the VPN's routes is reached over the ordinary internet, VPN or not. Do not assume a
  client's public block goes through the tunnel just because their internal ranges do.

If the VPN drops mid-scan, the routed ranges become unreachable and the scan fails or times out;
re-running once the VPN is back is safe.

## Scan profiles: depth versus speed

Every scan picks a profile. It is a dropdown in the console (Profundidad) and the `profile`
field on the launch API. Two costs drive scan time — how many ports are probed, and whether each
open port is interrogated for its version — and the profiles trade them:

| Profile | Ports | Version detection | Use it for |
| ------- | ----- | ----------------- | ---------- |
| Rápido (`fast`) | 1000 common | No | A quick "what's open" sweep. This is what a bare `nmap <target>` does |
| Balanceado (`balanced`, default) | 1000 common | Yes | The normal audit: services and versions on the ports that matter |
| Exhaustivo (`thorough`) | 1-10000 | Yes | A full sweep when you need the rarely-used high ports |

Measured against a single real host (`scanme.nmap.org`):

| Profile | Time |
| ------- | ---- |
| Rápido | ~2 seconds |
| Exhaustivo | ~27 seconds |

The old behaviour was always Exhaustivo, which is why a scan that your console did in seconds
took the platform far longer. Balanced keeps version detection but drops from 10000 ports to the
1000 common ones, so it is roughly ten times cheaper on the port count while still telling you
what each service is. An explicit port range on the launch API still overrides the profile when
you need exact ports.

`NMAP_SCAN_TIMEOUT_SECONDS` defaults to one hour. A job that exceeds it is killed and the scan is
marked FAILED rather than left running.

## Tuning

Change these in `.env` and restart the affected service with `make up`:

| Setting | Default | What it does |
| ------- | ------- | ------------ |
| `NMAP_MAX_TARGETS_PER_SCAN` | 4096 | Ceiling on addresses per job, summed across ranges. A `/20` |
| `NMAP_SCAN_TIMEOUT_SECONDS` | 1800 | Wall clock budget per scan before the worker kills Nmap |
| `MAX_CONCURRENT_SCANS_PER_TENANT` | 3 | Queued or running scans allowed per client, and per operator for ad-hoc scans |
| `SCAN_DENYLIST_CIDRS` | link-local, loopback | Ranges refused regardless of what a client registers |
| `CELERY_CONCURRENCY` | 4 | Scans the worker runs at once |

A scan larger than the ceiling is not truncated silently: the ranges that would exceed it are
reported as rejected in the scan result, with the reason.

## When something does not work

**The scan completes with no hosts.** The range may genuinely have nothing on it, or the target
is dropping the probes. Confirm with the worker directly:

```bash
make nmap-caps                       # uid, Nmap capabilities and version
podman exec netshield_celery_worker nmap -sn -n 192.168.1.0/24
```

**Every scan fails immediately.** Check the worker's own diagnosis, which performs a real loopback
SYN scan and names whichever precondition is missing:

```bash
make worker-ping
```

**A range is rejected.** The result lists each rejected range with the reason: outside the
address grammar, overlapping a forbidden range, or over the per-scan ceiling.

**A long scan fails partway with "Nmap was terminated by SIGINT".** The worker restarted while
the scan was running. In development it runs under `watchmedo auto-restart`, which signals the
whole process group whenever a backend source file changes, and the running Nmap goes with it.

Avoid editing backend source during a long scan, or run the worker in its production form, where
there is no file watcher:

```bash
WORKER_BUILD_TARGET=production make up
```

This is the single most confusing failure to hit during a real test, because nothing is wrong
with the scan, the target or the configuration.

**Follow what the worker is doing** while a scan runs:

```bash
podman logs -f netshield_celery_worker
```
