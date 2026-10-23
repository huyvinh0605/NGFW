# M5 dependency and packaging contract

**PROPOSED profile, not installed or tested in this planning phase.** Select Ubuntu
24.04 LTS amd64 as the reference appliance; T01 records the actual OS/kernel and
aborts this profile if they differ. M5 is optional: installing/upgrading the base
NGFW with absent M5 config must not start extra daemons.

## Dependencies and capability gates

| Component | Initial version family / authoritative source | Package/runtime role | Mandatory capability proof before enablement |
|---|---|---|---|
| FRR | Ubuntu FRR 8.4.4 family; [upstream 8.4 reload](https://docs.frrouting.org/en/stable-8.4/frr-reload.html) | `frr`, `frr-pythontools`, Python3; zebra, ospfd, bgpd, bfdd, watchfrr | integrated config; dry syntax `vtysh -C -f`; bounded reload; JSON commands used by status; generated zebra filters protect static prefixes; proto196 routes visible to filtered redistribution |
| HAProxy | 2.8 LTS family; [management](https://docs.haproxy.org/2.8/management.html) | `haproxy`; dedicated master/worker unit | `-c`; master-worker USR2; JSON schema/info/stats; verified backend TLS; socket file permissions |
| Keepalived | 2.2.8 family; [tagged manual](https://raw.githubusercontent.com/acassen/keepalived/v2.2.8/doc/man/man8/keepalived.8.in) | `keepalived`; VRRP-only unit; optional separate checker unit | nonzero syntax statuses; unicast VRRPv3; structured FIFO and JSON v2; protected JSON dump mount; executable health helper under unprivileged account |
| Kernel/iproute2/nftables | Distribution kernel and `iproute2`, `nftables`; record exact revisions | Existing M1 dependencies plus netlink observation/ECMP | IPv4 forwarding; reserved protocol196 unused; stable required netlink fields; scoped nft guards; fresh socket device bind under engine sandbox |
| Existing Go deps | `go.mod`: Go1.22, netlink1.7.2, conntrack0.5.1, netfilter0.5.2 | Reuse netlink observer and Go stdlib exec/net/json/crypto | No new library for routing protocol logic. Promote already transitive x/sys only if direct setsockopt use needs it; update go.mod/go.sum only then and document why |
| Optional IPVS | Kernel IPVS modules + Keepalived checker | NAT virtual servers only | IPVS_GENERIC_NETLINK family and required attrs; rr/wrr/lc/sh modules; observer conformance; no competing ipvsadm writer |
| Future conntrackd | conntrack-tools; [manual](https://conntrack-tools.netfilter.org/manual.html) | None installed/started for core | Dedicated future sync/import/epoch design and acceptance required |

Pin exact distribution revision, binary SHA-256, package origin, build flags,
JSON schema fixture hashes and installer version in
`/etc/ngfw/network-services-profile.json` (root:root 0644, no secrets).
Upgrades within a family still require capability replay and affected regression
cases. No automatic use of an arbitrary newer FRR command/JSON schema.

T01 creates a manifest, not a claim of capability from a version string:
`dpkg-query -W frr frr-pythontools haproxy keepalived iproute2 nftables`,
`uname -r`, bounded `--version/-vv`, syntax probes on synthetic no-secret files,
sample JSON with required keys, service sandbox probes and packet captures for
ownership reservation. The missing capability stays unavailable in API/UI.
The installer never downloads from an unpinned third-party shell URL.

## Layout and permissions

| Path (PROPOSED unless identified existing) | Owner/mode | Purpose / writer |
|---|---|---|
| Existing `/var/lib/ngfw/running.json` | existing root:ngfw 0640 | Engine authoritative config; only secret references |
| `/var/lib/ngfw/network-services/` | root:root 0700 | Outer WAL, manifest, generation indexes; engine only |
| `.../activation.json` | root:root 0600 | fsync before first runtime mutation; includes old exact activation snapshot, never plaintext keys |
| `.../artifacts/<generation>/<subsystem>/` | root:root 0700 | Immutable source artifacts, hashes; old/active/WAL references retained |
| `/etc/ngfw/network-services/active/<subsystem>/` | root:component-group 0750 | Published runtime material; files 0640 except key bundle 0600/0640 according to component group; journaled replace |
| `/etc/ngfw/secrets/<name>/<version>` | root:root 0700 dirs, 0600 files | Local administrator provisions; never API-readable, no Candidate path traversal |
| `/etc/frr/frr.conf` | root:frr 0640 | Dedicated appliance integration points at generated active FRR config; no hand-edited second authority |
| `/etc/frr/daemons` | root:root 0644 | Installer fixed process profile: zebra/ospfd/bgpd/bfdd as required, staticd disabled; no freeform Candidate writes |
| `/run/frr/` | package frr/frrvty permissions, audited at T01 | daemon vty sockets; API is not in frrvty |
| `/run/ngfw-m5/haproxy/` | ngfw-lb:ngfw-lb 0750 | master/admin socket 0660; only dedicated service group plus engine membership, workers use fixed generated config |
| `/run/ngfw-m5/keepalived/` | root:ngfw-ha 0750 | notify FIFO root:ngfw-ha 0600; root engine reads structured events |
| `/run/ngfw-m5/keepalived/dump/` | root:root 0700; JSON0600 | Private service mount of build temporary dump location |
| `/run/ngfw-m5/readiness.json` | root:ngfw-ha 0640 | Atomic bootID/generation/expiry/dependency result; only engine writes |
| `/var/log/ngfw/network-services/` | root:root 0700 | Sanitized structured operational records; not raw credential-bearing daemon configs |

ArtifactStore writes temp in the destination filesystem, fsyncs contents, renames,
fsyncs parent, records digest, then makes the active reference visible. Retention:
active + previous accepted generation + every journal reference; delete other
artifacts after 24h with a bounded 64-generation cap. Disk quota default256MiB;
refuse preparation before mutation if retention cannot meet it. No secret values
in digest manifests/API. Backups of secret-bearing artifacts use the same access
control, never general evidence archives.

The Keepalived profile maps its build-defined JSON temporary directory to the
protected dump directory with a systemd `BindPaths=host:service` mount. Determine
the exact path from the pinned package before generating the drop-in. Engine uses
the host path and systemd PID-safe signal; it never enters the mount namespace.
Require `json_version 2`, safe non-symlink regular file, root owner, new timestamp
after signal, and complete valid JSON. Precreating a file is insufficient alone:
test whether that package truncates or renames it. A stale/partial dump returns
UNKNOWN. If a confined writable mount cannot work, block this profile, not use a
shared world-writable `/tmp/keepalived.json`.

## Service identities, privileges and lifecycle

| Unit/profile | User/group | Capability bound / exact intent | Hardening and runtime access |
|---|---|---|---|
| Existing ngfw-api | ngfw:ngfw | Empty, remains unchanged | No new M5 secret/tool socket access; read-only status over engine IPC |
| Existing ngfw-engine | root:ngfw, supplementary frr/frrvty/ngfw-lb/ngfw-ha in the installed M5 profile only | **NET_ADMIN only**, preserve current NoNewPrivileges | New narrowly scoped write paths listed above; no SYS_ADMIN/NET_RAW. systemd service control over local bus is a privileged root operation even without additional capabilities |
| FRR vendor unit with NGFW drop-in | supervisor root; routing daemons drop to frr:frr, vty group frrvty | Reference bound for supervisor: CHOWN, DAC_OVERRIDE, FOWNER, KILL, SETGID, SETUID, SETPCAP, NET_ADMIN, NET_RAW, NET_BIND_SERVICE, **SYS_ADMIN**; only daemon-requested subset survives privilege drop | Dedicated appliance; no netns/VRF features enabled, no remote VTY; ProtectHome, PrivateTmp, NoNewPrivileges, allowed write dirs only. Verify actual permitted/effective sets per daemon; remove demonstrably unused supervisor caps after package validation |
| ngfw-haproxy | ngfw-lb:ngfw-lb | NET_BIND_SERVICE only for ports<1024; empty bound is valid for high-port-only profile | Start directly as this user, no daemon user/group/chroot directives requiring elevation; master-worker foreground, NoNewPrivileges, RestrictAddressFamilies AF_UNIX/INET/INET6; secrets read-only |
| ngfw-keepalived | root:ngfw-ha; fixed script executes as ngfw-ha | NET_ADMIN, NET_RAW, SETUID, SETGID; KILL only if package process supervision test proves required, record exception | VRRP-only, no checker/static_route/static_ipaddress/firewall features; ProtectSystem strict, ProtectHome, NoNewPrivileges, fixed FIFO/dump paths, script_security |
| ngfw-ha-health helper | invoked as ngfw-ha:ngfw-ha | Empty | Reads readiness record only, checks monotonic age+boot+generation, exits0/1 within500ms; no systemctl/tool/network access |
| Optional ngfw-ipvs | root:ngfw-ha | NET_ADMIN, NET_RAW, SETUID, SETGID (package-verified) | Checker-only; no VRRP instances, scripts or static route/address directives; private PID/FIFO/dump files |

The FRR SYS_ADMIN issue is concrete, not a reason to enlarge engine privileges:
[FRR 8.4.4 zebra main.c](https://raw.githubusercontent.com/FRRouting/frr/frr-8.4.4/zebra/main.c)
declares that capability even though initial M5 does not expose netns VRFs.
Do not assert that stock FRR works with only NET_ADMIN. T01 checks Ubuntu patches
and actual capsets; a smaller compatible package profile is preferred if proven.
The bounded reference is an explicit external-daemon trust decision recorded in
R03; a deployment that forbids it must leave FRR unavailable until a separately
validated profile exists. No privileged container / blanket capability grant.

UID0 with only NET_ADMIN does not bypass arbitrary file permissions. The M5
installer therefore adds the listed supplementary groups to the engine drop-in;
it creates groups before enabling that drop-in. API is never added. HAProxy's
socket must be 0660, not 0600 owned solely by ngfw-lb. Engine-created runtime
artifacts remain UID0 and use group changes only to its supplementary groups;
no CAP_CHOWN/DAC_OVERRIDE is needed for that operation. Parent active directories
are root:root 0755 for traversal, with per-component directories0750 and files0640.
Private HAProxy key bundles are root:ngfw-lb0640 so the already unprivileged
master can read them; their parent prevents access by unrelated users. The master
has no need to change user/chroot at runtime. T27 tests actual access, not just
the unit declaration. The base engine unit remains usable without M5-installed
groups when the drop-in is absent.

Read-only status access does not mean vty sockets are harmless: frrvty and the
HAProxy admin socket permit control. Only the root engine adapter reaches them.
Status never exposes a generic CLI endpoint.

All M5 units are **disabled for autonomous boot start**; engine starts enabled
features after restoring Running and admission. systemd restarts crashed processes
from the last accepted artifact with bounded RestartSec/StartLimit. Units do not
use BindsTo/PartOf on API; API restart leaves traffic up. Engine crash does not
force-stop FRR/HAProxy; Keepalived readiness ages out and yields VIP. At reboot
there are no persisted runtime ready records; bootstrap closes scoped admission
before starting configured daemons. No dependency cycle makes engine startup
wait for a daemon which is waiting for engine startup.

Use vendor `frr.service` with one audited appliance-only drop-in, not a second
simultaneous FRR instance. Mask/disable conflicting distribution HAProxy and
Keepalived units when dedicated NGFW units are selected, after checking that no
operator-owned instances exist. If foreign managed config/services exist, install
aborts with their paths; it does not overwrite them. Reverse these changes from
installer manifest only on uninstall.

For the unprivileged HAProxy unit, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`
is a ceiling, not a grant. The low-port profile also sets
`AmbientCapabilities=CAP_NET_BIND_SERVICE`; a high-port-only profile leaves both
empty. Test the actual effective capability and bind behavior under that unit.

## Sysctls and packet-path limits

M1 retains IPv4 forwarding ownership. M5 never changes M1's persistence file.
For FRR_ECMP, lease `net.ipv4.fib_multipath_hash_policy=1` after recording previous
value and ownership. Use `rp_filter=2` only on participating data interfaces,
recording old values and effective `all` interaction; reject a platform whose
effective source validation cannot support the documented return path without
unapproved global changes. Do not change MGMT settings.
These changes are journaled, verified and reverted only if current value still
equals the lease value; conflicting operator drift becomes an error. Lease
cleanup is required on disable and boot recovery.

The TCP observer creates a fresh socket, binds source and device once, and closes
it after a bounded connect. [Linux 6.8 socket code](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/core/sock.c)
supports the initial-bind design without enlarging engine caps; T01 must check
actual kernel+systemd behavior. No probe fallback with an unspecified interface.

## Installation, upgrade, downgrade

1. T00 snapshot baseline, package/unit state, binary hashes and config; keep MGMT
   path and VM console. T01 determines a supported package profile in disposable
   lab first. No packages are installed by merely validating a Candidate.
2. Installer checks OS, package signatures, tool paths, service collisions, ports,
   protocol196 reservation and free disk; creates dedicated users/directories;
   installs units and profile with M5 disabled.
3. Syntax and permission probes run with no live protocol/listener configuration.
   A00 proves absent M5 starts no daemon and M1–M4 baseline remains valid.
4. Engine/API/frontend are upgraded together. First enabled commit runs adapter
   preflight, publishes artifacts, starts enabled units and verifies configuration.
5. Upgrade pauses reconcile under activation lock, checks no pending journal,
   syntax-checks current rendered config against new binaries, then performs
   rolling local reload. Preserve a package/binary rollback copy and old hashes.
6. Downgrade first commits M5 disabled and verifies routes/VIPs/listeners/guards/
   leases released, then commits `network_services` omitted. Both Running **and
   previous snapshot** must be old-compatible (second ordinary no-M5 commit if
   necessary). No pending outer/inner journal. Stop M5 services, restore package
   manifest, then replace paired engine/API/UI. Never start an old binary against
   a new active journal/config hoping unknown fields are harmless.

No runtime auto-installation, auto-update, arbitrary service names, arbitrary
commands, arbitrary file paths or remotely supplied scripts. Operational runbook
may provide local administrator secret provisioning; it must not print private
keys in shell traces or VM evidence.

## Planning checkpoint

FINDINGS: distro revision and privilege details matter; stock FRR requests more
capabilities than the existing engine, while API can stay entirely unprivileged.
DECISIONS: fixed audited package profiles, separate accounts, engine-triggered
startup, protected generated artifacts, capability gates and paired releases.
UNRESOLVED: T01 package-specific capset/mount/JSON/dry-run proofs; none are reported
as completed. Failed proof disables that subsystem.
FILES ALREADY INSPECTED: go.mod, engine/API systemd units, API HTTP timeout.
SOURCES ALREADY INSPECTED: SOURCE_NOTES F01–F09/H01–H02/K01–K02/L01–L05/P01.
NEXT TARGETS: implementation cards and failure/acceptance procedures.
