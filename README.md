# NGFW

Software-based Linux next-generation firewall for a virtual multi-NIC lab. The implementation keeps the forwarding path independent from management services and routes every detector signal through a shared security context, risk evaluator, policy evaluator and enforcement boundary.

## M1 firewall status

The M1 implementation is code-complete for review, but it is **not yet accepted
as complete**: privileged routing, VLAN, NAT, stateful firewall, restart
reconciliation and rollback still require the Ubuntu VM integration checklist
in `tests/integration/m1/README.md`.

`ngfw-api` never runs `ip` or `nft` and has no Linux capabilities. A commit or
rollback succeeds only after the privileged `ngfw-engine` applies the requested
configuration over `/run/ngfw/engine.sock`. The engine also reconciles the
persisted running config at every startup, enables and persists IPv4 forwarding,
and uses an activation journal plus applied snapshot for recovery.

## Current implementation

The repository contains a runnable control-plane MVP with:

- typed models for interfaces, zones, routes, NAT, sessions, security context, events, profiles, policies and decisions;
- bounded concurrent session/context store with bidirectional flow keys, TTL cleanup and fast-path invalidation;
- explainable 0–100 risk scoring with confidence weighting and IPS/ML correlation;
- deterministic first-match policy evaluation with explicit default deny;
- candidate configuration validation, version conflicts, atomic file persistence and rollback;
- bounded event bus and asynchronous API event collection;
- mock enforcement for Windows development plus an `nft -f -` privileged boundary for Linux;
- deterministic nftables ruleset compiler for stateful forwarding, NAT and temporary blocks;
- bounded HTTP request decoder, URL filtering helper, TLS ClientHello metadata parser and adapters for ML/Suricata;
- HTTP/1.1 and TLS HTTP/2 request gate that keeps the body upstream until decision, plus lab CA generation for selective TLS interception;
- bounded DNS decoder, local reputation store and configurable port/host/rate anomaly detector;
- local Python inference service with bounded input, timeout-friendly HTTP contract and joblib model loading;
- React/Vite operations dashboard for health and active sessions.

Kernel packet capture, conntrack netlink, transparent redirect rules and production nDPI wiring are intentionally behind adapters. The request gate and lab CA are runnable; production interception still requires the Linux redirect/capability setup. The mock engine is safe to run on Windows; privileged network tests belong in the Linux VM described by the implementation plan.

## Run the API locally

Install Go 1.22+ and run:

```powershell
$env:NGFW_API_TOKEN = "dev-token"
$env:NGFW_STATE_DIR = ".\state"
go run .\cmd\ngfw-api
```

Check health:

```powershell
Invoke-RestMethod http://localhost:8080/api/v1/health
```

Local Windows mode supports API reads and candidate editing. Commit and rollback
intentionally return `ENGINE_UNAVAILABLE` unless an engine IPC endpoint is
running; privileged M1 activation is Linux-only.

Write endpoints require `Authorization: Bearer dev-token` when `NGFW_API_TOKEN` is set. Alternatively set `NGFW_ADMIN_USER` and `NGFW_ADMIN_PASSWORD`, call `POST /api/v1/auth/login`, and use the returned short-lived bearer token. For the M2 L3/L4 runtime, load `NGFW_CONFIG=.\configs\examples\m2-lab.json` at startup. State is persisted in `NGFW_STATE_DIR`; do not commit that directory.

## Run the ML service

The service works with a conservative lab heuristic without a model. For a trained model, install the pinned requirements and set `NGFW_ML_MODEL` to a trusted joblib artifact.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r .\ml\service\requirements.txt
python .\ml\service\app.py
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8090/classify -ContentType application/json -Body '{"text":"id=1 union select password from users"}'
```

Training input is JSONL with `text` and `label` fields. Train only with a documented, held-out test split:

```powershell
python .\ml\training\train.py .\data\http.jsonl .\ml\models\http-classifier.joblib
```

## Run the request gate

`ngfw-proxy` is the lab path that holds an HTTP request until the engine has evaluated it. It supports HTTP/1.1 directly and HTTP/2 when started with a TLS certificate/key; each request gets a bounded body, request ID, signature signal and optional ML signal before the upstream receives anything.

```powershell
$env:NGFW_PROXY_ADDR = ":8088"
$env:NGFW_PROXY_UPSTREAM = "http://10.20.0.10:8080"
$env:NGFW_CONFIG = ".\configs\examples\m2-lab.json"
go run .\cmd\ngfw-proxy
```

Set `NGFW_PROXY_FAIL_CLOSED=1` when an explicitly required classifier must be available. Requests exceeding the configured inspection body limit are rejected before forwarding. The built-in signatures are a lab safety net; Suricata remains the authoritative external IDS adapter for the appliance path.

## Run the UI

```powershell
cd web
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. The Vite development server proxies `/api` to `http://localhost:8080`.

The M2 console includes runtime health, live conntrack sessions, L3/L4 decisions,
runtime/policy events, temporary blocks, the local reputation registry,
management audit, policy editing, network inventory, candidate JSON,
validation, commit/rollback and RBAC user administration. Stats and runtime
events use `/ws/stats` and `/ws/events`; bounded polling remains active as a
reconnect fallback. App-ID, risk, DPI, IDS/IPS, ML and TLS inspection are shown
as unavailable because they belong to later milestones.

Monitoring remains available in read-only mode. To use write actions, open **Management access** in the lower-left corner and enter the same token configured in `NGFW_API_TOKEN` (for example `dev-token`), or sign in with the account configured through `NGFW_ADMIN_USER` and `NGFW_ADMIN_PASSWORD`. Account passwords are stored as salted Argon2id hashes, and updates revoke that account's existing bearer sessions.

The UI stores only the bearer token in browser local storage. Raw packet streams, passwords, CA keys and detector payload files are never rendered in the dashboard.

## Linux appliance path

Copy the repository to the Ubuntu 24.04 VM and run the single M1 installer. It
installs the required packages, runs the M1 unit tests, builds the two Go
services, installs the systemd units, persists IPv4 forwarding, and creates a
sample configuration and environment file:

```bash
sudo bash scripts/install-linux.sh --config configs/examples/m2-lab.json
```

The installer does not start services automatically because the sample uses
placeholder interface names (`eth0` ... `eth3`). Replace those names,
addresses and gateways in `/etc/ngfw/lab.json`, review the token and management
bind address in `/etc/ngfw/ngfw.env`, then start the appliance:

```bash
sudo systemctl enable --now ngfw-engine ngfw-api
sudo /usr/local/lib/ngfw/verify-m1-linux.sh
```

After adapting the configuration, `sudo bash scripts/install-linux.sh --start`
can perform the start and non-traffic checks in one invocation. Only the engine
service receives `CAP_NET_ADMIN`; the API runs as `ngfw` with no capabilities.

The installer covers the M1 dataplane and M2 stateful runtime. It does not install or start the
proxy, UI, ML or IDS services. Complete `tests/integration/m1/README.md` after
the non-traffic checks. The nftables adapter checks the ruleset before
atomically replacing only the managed `inet ngfw` table.

When source code changes, restarting systemd alone does not rebuild the installed
executables. Run the installer again to rebuild and copy the current
`ngfw-engine` and `ngfw-api`, then restart the services:

```bash
sudo bash scripts/install-linux.sh --skip-apt --start
```

The sample topology uses WAN, LAN, DMZ and MGMT interfaces. It is a starting configuration only: replace addresses, gateways and interface names for the VM.

## Verification

With Go installed:

```powershell
go test ./internal/config ./internal/dataplane ./internal/engineipc ./internal/management
$env:GOOS = "linux"
go build ./cmd/ngfw-engine ./cmd/ngfw-api
```

These M1 unit tests cover config validation, compiler semantics, reconciliation
plans, injected apply failures, journal recovery, IPC, and API rollback wiring.
They do not replace privileged Linux packet-path testing.

## Safety boundaries

## M2 stateful runtime status

M2 code keeps the runtime session store, conntrack adapter, NAT aliases,
policy generation, bounded decision cache, invalidation guards and event ring
inside `ngfw-engine`. `ngfw-api` queries that state through versioned Unix IPC;
it does not construct a second session engine or execute dataplane commands.
Resync closes sessions absent from a complete kernel dump, and engine startup
clears stale integer conntrack revoke fences while preserving timed source
blocks in the kernel runtime table.

Observed forward sessions are evaluated automatically against the current M2
L3/L4 program. Loopback and traffic to/from an appliance address are classified
as `local` and report the forward-policy decision as unavailable. Unknown
addresses remain `unknown`; they are never silently mapped to WAN. A bounded
periodic conntrack dump refreshes counters that UPDATE events omit. The UI only
labels a session `Fast` when the backend verifies kernel-cache provenance;
otherwise path, App-ID and risk are shown as unavailable. Runtime lifecycle,
policy and security events use separate event classes.
Use `docs/m2-acceptance-matrix.md`, then run
`sudo /usr/local/lib/ngfw/verify-m2-linux.sh` and the traffic cases in
`tests/integration/m2/README.md`. Until those VM cases have evidence, M2 is
code-complete/ready for acceptance rather than completed.

ML never calls enforcement. Database/API/UI are not in the packet path. Event and payload buffers are bounded. A detector outage is represented as unavailable/degraded and is resolved by profile failure policy. The project does not claim HA, upstream DDoS protection, enterprise VPN, HTTP/3 decryption or commercial-scale signatures.
