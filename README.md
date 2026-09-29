# SENTINEL NGFW

Linux NGFW appliance for a virtual multi-NIC lab. The implemented appliance
path currently covers:

- **M1:** interfaces/VLANs/routes, IPv4 forwarding, stateful nftables policy,
  SNAT/MASQUERADE/DNAT, transactional activation and rollback;
- **M2:** one engine-owned conntrack session store, NAT tuple aliases, L3/L4
  policy generation, decision cache, invalidation, kernel fast path and runtime
  IPC/API;
- **M3:** Suricata EVE ingestion, HTTP/TLS/DNS/SSH application metadata,
  NAT-aware session correlation, NFLOG IDS, NFQUEUE IPS, scoped application
  guards, inspection health/capabilities, bounded security events and UI support.

M1/M2/M3 code is intended for Ubuntu Server 24.04. Live VM acceptance remains a
separate gate: local build/unit success is not packet-path evidence.

## Architecture boundary

`ngfw-engine` is the sole owner of the Linux dataplane, session state, policy
generation, inspection coordinator and security-event history. It is the only
NGFW service with `CAP_NET_ADMIN`. `ngfw-api` edits Candidate configuration and
queries the engine through IPC v3; it cannot run `ip`, `nft` or Suricata. API/UI
failure therefore does not stop the installed kernel policy or sensor services.

M3 uses asynchronous inspection:

```text
packet -> M1/M2 connectivity -> NFLOG IDS or NFQUEUE IPS
       -> Suricata EVE -> correlation -> existing M2 session
       -> event/context update -> optional scoped application guard
```

IDS reports alerts and does not create a deny intent. IPS can report an inline
packet drop. A known application outside an IPS policy allowlist can create a
separate nftables session guard. The UI/API deliberately distinguish packet
`REPORTED` from session guard `APPLIED`.

M3 does not implement TLS decryption, HTTP request gating, WAF, HTTP/3, nDPI,
ML, Risk Engine or DoS analytics. Experiments for later milestones remain in the
repository but are not installed or claimed by the M3 appliance path.

## Local development

Requirements: Go 1.22+, Node.js/npm, and PowerShell or a POSIX shell.

Run local code gates:

```powershell
go test -count=1 ./...
go vet ./...
$env:CGO_ENABLED = "0"
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build ./cmd/...

cd web
npm ci
npm test
npm run build
```

Run the API locally for read/candidate UI development:

```powershell
$env:NGFW_API_TOKEN = "dev-token"
$env:NGFW_STATE_DIR = ".\state"
go run .\cmd\ngfw-api
```

Commit/rollback and runtime session APIs require a running engine IPC endpoint.
Privileged engine/dataplane execution belongs on Linux.

Run the Vite UI:

```powershell
cd web
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. Vite proxies `/api` and `/ws` to the API at
`127.0.0.1:8080`. Restarting systemd on Ubuntu does not rebuild binaries; rerun
the installer whenever source changes.

## Ubuntu installation

Copy the repository to an Ubuntu Server 24.04 VM. For M1/M2 only:

```bash
sudo bash scripts/install-linux.sh --config configs/examples/m2-lab.json
```

For M3, explicitly install Suricata, sensor assets, rules and services:

```bash
sudo bash scripts/install-linux.sh --with-inspection \
  --config configs/examples/m3-ids-lab.json
```

The installer preserves existing `/etc/ngfw/lab.json` and
`/etc/ngfw/ngfw.env` unless an explicit `--config` requests replacement. Review
the VM interface names, addresses, routes, management bind address and token.
Then rebuild/start and run non-traffic checks:

```bash
sudo bash scripts/install-linux.sh --skip-apt --with-inspection --start
sudo /usr/local/lib/ngfw/verify-m1-linux.sh
sudo /usr/local/lib/ngfw/verify-m2-linux.sh
sudo /usr/local/lib/ngfw/verify-m3-linux.sh --preflight \
  --evidence-dir /tmp/ngfw-m3-preflight
```

Run the isolated kernel/Suricata capability probe before M3 traffic tests:

```bash
sudo /usr/local/lib/ngfw/probe-m3-capabilities.sh --isolated \
  --evidence-dir /tmp/ngfw-m3-capability
```

The probe creates its own network namespace. It validates the compound nftables
key schema, base-chain ordering, NFLOG, NFQUEUE bypass/listener behavior,
fail-open saturation and the Suricata control socket without changing the host
ruleset.

## M3 traffic acceptance

Use [tests/integration/m3/README.md](tests/integration/m3/README.md) and
[docs/m3-acceptance-matrix.md](docs/m3-acceptance-matrix.md). The runner accepts
one explicit matrix ID at a time and requires an isolated lab plus a topology
JSON with real traffic/action steps and independent assertions:

```bash
sudo --preserve-env=NGFW_API_TOKEN \
  /usr/local/lib/ngfw/verify-m3-linux.sh --traffic --lab \
  --topology /etc/ngfw/m3-lab-topology.json --scenario M3-11 \
  --evidence-dir /tmp/ngfw-m3-M3-11
```

Missing harness/capability exits with `NOT_RUN`; it is never converted to PASS.
The runner collects nftables, conntrack, config, sessions, health, security
events, service status and journals, then executes topology restore commands.

## Web console

The console provides:

- health, bounded statistics and runtime/session views;
- original/reply/translated tuples and M2 decision/cache state;
- M3 application identity with source/confidence and coverage;
- inspection source, process, capture and IPS lease health;
- runtime/policy/security events with cursor/gap handling;
- packet verdict and session enforcement details;
- Candidate policy/profile editors plus the shared advanced JSON workflow;
- Validate, Commit and Rollback with explicit Running/Candidate state;
- temporary blocks, reputation registry, audit and RBAC administration.

`Nạp Running vào trình soạn thảo` only replaces the editor buffer. `Lưu vào
Candidate` does not activate it. Only an explicitly validated current Candidate
can be committed. See [USE.md](USE.md) for field-by-field operator guidance.

## Status and evidence

- [M1 acceptance matrix](docs/m1-acceptance-matrix.md)
- [M2 acceptance matrix](docs/m2-acceptance-matrix.md)
- [M3 implementation plan](docs/M3_IMPLEMENTATION_PLAN.md)
- [M3 implementation status](docs/m3/IMPLEMENTATION_STATUS.md)
- [M3 acceptance matrix](docs/m3-acceptance-matrix.md)
- [OpenAPI contract](docs/openapi.yaml)
- [ADR 0003](docs/adr/0003-m3-inspection-pipeline.md)

Do not describe a milestone as accepted until its live Ubuntu rows have raw
evidence. TLS metadata does not mean decrypted HTTP, no alert does not mean
clean traffic, and an unavailable detector must remain visible as unavailable.
