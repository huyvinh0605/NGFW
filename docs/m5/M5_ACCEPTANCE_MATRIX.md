# M5 VM acceptance matrix

**All M5 cases are NOT_RUN. This file specifies future tests; it is not a test
report.** Existing M1 artefacts prove their recorded M1 runs only. Every script,
overlay, peer file and M5 command entry point below is PROPOSED for T26–T28.
Do not run these commands against the current lab during the specification phase.

A case can become PASS only when its setup, raw command output, packet evidence,
assertions and cleanup verification are stored under a new UTC-labelled directory
with commit + dirty-source hashes and package/profile manifest. BLOCKED (missing
VM/tool) and NOT_RUN are never equivalent to PASS. Optional/future rows do not
hold core scope open; their capability must stay absent.

## Lab and fixed addresses

Retain the user's existing G1 network and protect MGMT throughout. Obtain a VM
console and baseline snapshot before destructive test execution.

| Node | Interface / address | Role and required return path |
|---|---|---|
| G1 / huy | ens33 192.0.2.2/24, ens37 192.168.10.1/24, ens38 10.20.0.1/24, ens39 192.168.100.1/24 | Existing WAN/LAN/DMZ/MGMT; add ens40 198.51.100.2/24 on a new isolated WAN2 segment for dual-link tests |
| R1 / existing wan | WAN1 192.0.2.1/24; new transit NIC 203.0.113.1/24 | FRR peer AS65010, router ID192.0.2.1; connected server network; LAN return route via G1 learned by test protocol |
| R2 / new VM | WAN2 198.51.100.1/24; transit 203.0.113.2/24 | FRR peer AS65010, router ID198.51.100.1 |
| S / new VM | transit203.0.113.10/24, gateway203.0.113.1 | Shared real traffic destination, TCP/HTTP18080; not two independent hosts advertising the same endpoint |
| lan | 192.168.10.10/24, gateway192.168.10.1 | Traffic source; temporarily gateway192.168.10.254 only for HA cases |
| dmz | 10.20.0.10/24, gateway10.20.0.1; temporary alias10.20.0.11/24 | B1/B2 distinguishable HTTP/TCP backends18081; alias removed during cleanup |
| mgmt | 192.168.100.10/24, gateway192.168.100.1 | API and observation; never moved to VRF or used for routing fault injection |
| G2 / new NGFW VM | WAN1 .3, LAN192.168.10.2, DMZ10.20.0.2, MGMT192.168.100.2 | Distinct hostname/boot ID/state/keys; local Running version is independent; no copied live engine state |
| HA VIPs | LAN192.168.10.254/24 VRID51; WAN192.0.2.254/24 VRID52 | Keepalived sync group EDGE; G1 priority100, G2 priority90, initial BACKUP, advert1s, preempt false unless case enables it |
| LB listener | ordinary M1 address10.20.0.20/24 on G1 DMZ; ports18080/18443 | Not a VRRP VIP. Backend .10/.11:18081. M4 disabled for delivery cases; certificate lab.example.test with test-only CA |

R1 and R2 use iBGP between transit203.0.113.1/.2 with next-hop-self and explicit
LAN export so S retains a return path through R2 if R1's G1-facing link fails.
Both advertise their connected203.0.113.0/24 to G1. G1 AS65000 advertises only
192.168.10.0/24. ECMP peers share AS65010 and equal attributes; failover fixture
sets imported local preference200 from R1 and100 from R2. Thus the demonstration
is **routed WAN**, without source NAT on203.0.113.0/24. Existing baseline NAT
remains tested separately. Captures must show the actual forward and return
paths; neither ECMP nor this topology promises per-ISP sticky NAT.

OSPF cases reset BGP and use G1–R1 area0.0.0.0; G1 LAN and R1 server-facing
interfaces are passive advertisements. HA cases reset routing-protocol fixtures,
use ordinary default routes to R1, and set R1's LAN route via192.0.2.254.
Two default gateways/VIPs must not be confused with two copies of session state.

Peer interface names are mapped once by MAC at lab setup, recorded in nodes.env,
then immutable for the run. G1's new ens40 name must be confirmed before applying
the interface fixture; if different, use the existing domain Interface.Name
mapping rather than hard-coding a guessed NIC. No test fault targets ens39.

## Common procedure C0: save, commit, collect, restore

These are exact API actions using the current inspected endpoint/envelope:
`GET /api/v1/config` returns `.data.running`, `.data.candidate`,
`.data.version.version`. Candidate PUT takes the entire Config. All auth values
come from environment; disable shell tracing and omit secrets from transcripts.

```sh
export API=http://192.168.100.1:8080
export EVIDENCE=/var/tmp/ngfw-m5-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$EVIDENCE"
curl -fsS -H "Authorization: Bearer $NGFW_TOKEN" "$API/api/v1/config" > "$EVIDENCE/before.json"
jq '.data.running' "$EVIDENCE/before.json" > "$EVIDENCE/baseline-running.json"
jq '.data.candidate' "$EVIDENCE/before.json" > "$EVIDENCE/baseline-candidate.json"
sha256sum "$EVIDENCE/baseline-running.json" > "$EVIDENCE/baseline.sha256"
```

For each case `CASE`, `lab.sh prepare CASE` must generate `target.json` from the
saved baseline and the named sparse fixture. It replaces explicitly listed arrays
by ID, preserves unrelated policy/NAT entries and M3/M4 optional fields, and adds
narrow named allow rules for the specific test endpoints where needed. It never
makes all WAN->LAN traffic allowed. Candidate conflicts stop preparation rather
than deleting existing rules silently. The generated target and semantic diff
are evidence and must be inspected before destructive case actions.

```sh
CASE=A02
tests/integration/m5/lab.sh prepare "$CASE" "$EVIDENCE/baseline-running.json" "$EVIDENCE/target.json"
curl -fsS -X PUT -H "Authorization: Bearer $NGFW_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @"$EVIDENCE/target.json" "$API/api/v1/config/candidate" > "$EVIDENCE/candidate-response.json"
curl -fsS -X POST -H "Authorization: Bearer $NGFW_TOKEN" \
  "$API/api/v1/policies/validate" > "$EVIDENCE/validate-response.json"
V=$(curl -fsS -H "Authorization: Bearer $NGFW_TOKEN" "$API/api/v1/config" | jq -er '.data.version.version')
jq -n --argjson v "$V" --arg c "M5 $CASE" '{expected_version:$v,author:"m5-acceptance",comment:$c}' > "$EVIDENCE/commit-body.json"
curl --max-time 210 -fsS -X POST -H "Authorization: Bearer $NGFW_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @"$EVIDENCE/commit-body.json" "$API/api/v1/policies/commit" > "$EVIDENCE/commit-response.json"
tests/integration/m5/collect.sh "$CASE" applied "$EVIDENCE"
```

A candidate-reject case records HTTP status/body with `curl -sS -o response.json
-w '%{http_code}\n'`; do not use `-f` and lose its error body. Snapshot
Candidate/Running version+checksum and kernel state on both sides of rejection.
A timeout/lost reply triggers Running/status retrieval, not an automatic new
commit operation. If engine stayed alive, existing operation-ID dedup can be
used; after engine restart its in-memory receipt cache is not a durable proof.

C0 collection on each involved gateway (bounded, named scopes only):

```sh
date -u +%FT%TZ
cat /proc/sys/kernel/random/boot_id
ip -j -4 address show
ip -j -4 route show table main
ip -j rule show
nft -j list table inet ngfw
nft -j list table inet ngfw_m5_services
systemctl show ngfw-engine ngfw-api frr ngfw-haproxy ngfw-keepalived \
  -p ActiveState -p SubState -p MainPID -p ExecMainStartTimestamp -p CapabilityBoundingSet -p NoNewPrivileges
journalctl -u ngfw-engine -u frr -u ngfw-haproxy -u ngfw-keepalived \
  --since "$CASE_START_UTC" --until "$CASE_END_UTC" --no-pager -o short-iso-precise
curl -fsS -H "Authorization: Bearer $NGFW_TOKEN" "$API/api/v1/network-services/capabilities"
curl -fsS -H "Authorization: Bearer $NGFW_TOKEN" "$API/api/v1/network-services/status?subsystem=routing&view=routes&limit=200"
```

Capture only case traffic for at most60s:
`timeout 60 tcpdump -ni ens33 -s 160 -w wan1.pcap 'net 203.0.113.0/24 or tcp port 179 or ip proto 89'`;
use ens40/LAN/DMZ as relevant. For TLS/backend cases capture TCP metadata and
synthetic test content only. FRR running config may contain authentication secrets;
store generated **redacted** config/hash and structured status, not unredacted
`show running-config` in shared evidence. Secret-reference files may be recorded,
private key bytes may not.

On all exits remove only case-specific faults first, then:
`tests/integration/m5/lab.sh restore "$EVIDENCE/baseline-running.json"` performs
ordinary Candidate PUT/validate/commit with the current expected version; restore
the originally saved Candidate afterward. Assert config semantic checksum equals
baseline (version increases normally), own VIPs/listeners/guard scopes/test
routes/aliases/leases removed, ordinary addresses/routes and M1 nft semantics
unchanged, no journal remains, services healthy, MGMT->API works. Do not use
`ip route flush`, `nft flush ruleset`, `conntrack -F` or `killall`.
Evidence manifest includes command exit codes, unit PIDs and SHA256SUMS. Archive
only sanitized evidence; raw secret directories are excluded.

## Scenario index

| ID | Scenario | Scope | Initial status |
|---|---|---|---|
| A00 | Package/privilege/disabled preflight | CORE | NOT_RUN |
| A01 | Schema/validation/backward compatibility | CORE | NOT_RUN |
| A02 | OSPF adjacency, learned route and forwarded traffic | CORE | NOT_RUN |
| A03 | OSPF neighbor loss, daemon restart and reconciliation | CORE | NOT_RUN |
| A04 | Static/dynamic route ownership and collision | CORE | NOT_RUN |
| A05 | Startup reconciliation preserves external runtime | CORE | NOT_RUN |
| A06 | BGP exchange and structured status | CORE | NOT_RUN |
| A07 | Prefix filters, route maps, defaults and redistribution | CORE | NOT_RUN |
| A08 | BGP failure, max-prefix and recovery | CORE | NOT_RUN |
| A09 | BFD failure with carrier still up | CORE | NOT_RUN |
| A10 | ECMP distribution and kernel settings | CORE | NOT_RUN |
| A11 | Routed WAN primary/backup and established TCP | CORE | NOT_RUN |
| A12 | Source/device-bound health and timeout observation | CORE | NOT_RUN |
| A13 | Reject unsupported WAN modes and preserve ordinary NAT | CORE | NOT_RUN |
| A14 | TCP balancing algorithms and connection limits | CORE | NOT_RUN |
| A15 | HTTP routing, health failure and recovery | CORE | NOT_RUN |
| A16 | TLS termination, verified bridging and rejection | CORE | NOT_RUN |
| A17 | Local admission, listener conflicts and M4 exclusion | CORE | NOT_RUN |
| A18 | VRRP ownership and master failure | CORE | NOT_RUN |
| A19 | Preempt delay, sync-group fault and engine readiness | CORE | NOT_RUN |
| A20 | FRR syntax/unavailable/crash injection | CORE | NOT_RUN |
| A21 | HAProxy syntax/reload failure and drain bounds | CORE | NOT_RUN |
| A22 | Keepalived unavailable and private-status failures | CORE | NOT_RUN |
| A23 | Partial apply and reverse compensation | CORE | NOT_RUN |
| A24 | Engine SIGKILL at durable activation boundaries | CORE | NOT_RUN |
| A25 | API restart, IPC negotiation and UI status | CORE | NOT_RUN |
| A26 | Stale generated config, daemon drift and event loss | CORE | NOT_RUN |
| A27 | Privileges, secrets, limits and cancellation | CORE | NOT_RUN |
| A28 | M1–M4 regression and clean reboot | CORE | NOT_RUN |
| A29 | Control-plane peer/interface/TTL admission | CORE | NOT_RUN |
| A30 | OPTIONAL IPVS NAT distribution, persistence and health | OPTIONAL | NOT_RUN |
| A31 | Future conntrackd/VRF/PBR remain unavailable | FUTURE BOUNDARY | NOT_RUN |
| A32 | Disable, cleanup and paired downgrade | CORE | NOT_RUN |

## Case recipes

Every case inherits C0 backup, authenticated API actions, scoped collection and
baseline restore. Explicit commands below run on the named node. Native CLI
commands are for acceptance diagnostics, not a second supported configuration
interface exposed by SENTINEL. Start/end timestamps and exit codes are mandatory.

### A00 — Package/privilege/disabled preflight

- **TOPOLOGY:** Existing G1+MGMT.
- **INITIAL CONFIG:** Saved old config with network_services absent; then explicit root disabled.
- **EXACT COMMANDS/API ACTIONS:**
  1. On G1: scripts/verify-m5-linux.sh --output "$EVIDENCE/preflight".
  2. Read /proc/<engine-pid>/status and /proc/<api-pid>/status; getcap each selected binary; systemctl is-enabled frr ngfw-haproxy ngfw-keepalived.
  3. Commit absent and disabled configs through C0; restart only ngfw-engine; repeat capability/status probes.
- **TRAFFIC GENERATOR:** MGMT curl /api/v1/health; baseline LAN->WAN allowed flow.
- **EXPECTED RUNTIME:** Engine NET_ADMIN only; API CapEff0; M5 daemon units stopped/disabled; no M5 table/WAL/workers/tool executions in spy trace.
- **EXPECTED PACKETS:** Baseline packets behave identically to saved config.
- **EVIDENCE:** C0 plus Manifest/tool hashes; process status/unit properties; syscall/Runner spy for no-IO; baseline traffic.
- **CLEANUP:** C0; remove temporary disabled Candidate only.
- **PASS:** Absent/steady disabled produces zero M5 runtime mutation, API reachable, legacy verifier exit0.
- **FAIL:** Any new privilege, daemon, nft table, sysctl or legacy semantic change. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A01 — Schema/validation/backward compatibility

- **TOPOLOGY:** G1+MGMT.
- **INITIAL CONFIG:** invalid-m5.json plus one valid object per supported model.
- **EXACT COMMANDS/API ACTIONS:**
  1. For each invalid fixture use C0 Candidate PUT with -o response.json -w '%{http_code}' and save status.
  2. Exercise ASN0, VLAN/missing interface ref, bad family/route map, max-paths9, same listener tuple, cert path '../', VIP==ordinary IP, M4+LB, unknown vrf/pbr/conntrack_sync field.
  3. Save valid Candidate, GET config, open old interface editor and save a harmless Candidate-only comment then GET again.
- **TRAFFIC GENERATOR:** No traffic required; concurrent baseline ping/curl continues.
- **EXPECTED RUNTIME:** 400 and stable existing Candidate/Running/kernel for invalid PUT; valid optional fields preserved through API/UI.
- **EXPECTED PACKETS:** No runtime packets/routes/listeners created by Candidate validation.
- **EVIDENCE:** C0 plus Per-vector request (secret refs only), HTTP body/status, canonical diff, tool-call counter.
- **CLEANUP:** Restore original Candidate; no commit needed for negative cases.
- **PASS:** All invalid vectors rejected transactionally; old config round-trip unchanged.
- **FAIL:** Unknown key accepted, dropped M5 field, changed Running or privileged command on validation. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A02 — OSPF adjacency, learned route and forwarded traffic

- **TOPOLOGY:** G1,R1,S,LAN.
- **INITIAL CONFIG:** ospf.json; G1/R1 area0, passive LAN/server networks, ReachablePrefixes203.0.113.0/24 zoneWAN.
- **EXACT COMMANDS/API ACTIONS:**
  1. On R1 load peers/r1.conf OSPF profile using pinned vtysh -C then frr-reload.py --reload.
  2. Commit C0; run vtysh -c 'show ip ospf neighbor json'; vtysh -c 'show ip ospf route json'.
  3. On G1: ip -j -4 route show 203.0.113.0/24; query M5 ospf-neighbors/routes; capture ens33 and ens37.
- **TRAFFIC GENERATOR:** On S: python3 tests/integration/m5/traffic.py serve --bind 203.0.113.10 --port 18080 --id S. On LAN: curl --max-time 3 http://203.0.113.10:18080/id.
- **EXPECTED RUNTIME:** Neighbor FULL within60s; OSPF-selected and kernel-installed server route; R1 has LAN return route; explicit WAN zone.
- **EXPECTED PACKETS:** Client reaches S with original LAN source; reply returns through G1; no NAT translation on prefix.
- **EVIDENCE:** C0 plus FRR/API JSON; route protocol+next hop; paired pcap; server client-address log.
- **CLEANUP:** C0 + peer previous config; stop exact S PID.
- **PASS:** FULL, route/provenance, bidirectional content and correct zone all proved.
- **FAIL:** Only adjacency/route exists without traffic, unknown zone, MGMT advertised, NAT unexpectedly applied. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A03 — OSPF neighbor loss, daemon restart and reconciliation

- **TOPOLOGY:** G1,R1,S,LAN.
- **INITIAL CONFIG:** A02 accepted topology/config.
- **EXACT COMMANDS/API ACTIONS:**
  1. On R1: systemctl stop frr; record UTC immediately; poll scoped G1 neighbor/route JSON every1s up to60s.
  2. On R1: systemctl start frr; wait for FULL/route/traffic.
  3. On G1: systemctl restart frr; then systemctl restart ngfw-engine; compare Running checksum and recover FULL.
- **TRAFFIC GENERATOR:** LAN repeats curl --max-time 1 every1s with JSONL timestamp.
- **EXPECTED RUNTIME:** Peer route withdrawn within configured dead interval+5s; return after FULL; Running unchanged; static/M1 objects retained.
- **EXPECTED PACKETS:** Flow fails during no path then new flow recovers; no baseline route silently substituted and labelled OSPF.
- **EVIDENCE:** C0 plus Timestamped state+traffic; filtered engine/FRR journal; nft M1 normalized hashes.
- **CLEANUP:** Start peer frr even on assertion failure; C0.
- **PASS:** Withdraw and restore observed; M1 firewall/NAT unchanged except allowed counter/epoch normalization.
- **FAIL:** Orphan route persists beyond bound, learned routes replayed as static, unrelated firewall/NAT lost. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A04 — Static/dynamic route ownership and collision

- **TOPOLOGY:** G1,R1,R2,S,LAN.
- **INITIAL CONFIG:** bgp.json followed by same-prefix M1 static route via an owned reachable gateway.
- **EXACT COMMANDS/API ACTIONS:**
  1. Before change: ip -j route show table main; save accepted claim manifest (no secrets).
  2. C0 add exact203.0.113.0/24 M1 route; assert union reservation+withdraw precedes ip route replace in phase trace.
  3. C0 remove that static; assert FRR path returns after reservation narrows.
  4. Lab inject one unrelated foreign route: ip route add 198.18.77.0/24 via 192.0.2.1 dev ens33 metric 777 proto 99; submit conflicting M1 route and record rejection.
- **TRAFFIC GENERATOR:** Concurrent LAN->S TCP loop; MGMT curl remains up.
- **EXPECTED RUNTIME:** Own static is protocol196 with exact claim; dynamic prefix excluded while reserved; foreign proto99 never replaced/deleted; unrelated OSPF/BGP routes retained.
- **EXPECTED PACKETS:** Routing follows installed owner; policy remains unchanged; temporary convergence measured.
- **EVIDENCE:** C0 plus Before/after netlink route JSON; typed operation log; reservation artifacts (redacted); API error; pcap.
- **CLEANUP:** Delete exact lab proto99 route using full key; C0 restores prior static provenance/reservations.
- **PASS:** All resource keys/protocols consistent, collision rejected before write, dynamic returns after release.
- **FAIL:** Proto196 alone treated as ownership proof, broad flush, default /0 reservation blocks all specifics, foreign route lost. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A05 — Startup reconciliation preserves external runtime

- **TOPOLOGY:** G1 plus relevant peer/G2.
- **INITIAL CONFIG:** A02 or A06 plus ordinary M1 static route and HA VIP fixture in separate subcase.
- **EXACT COMMANDS/API ACTIONS:**
  1. Record PIDs/bootID/config version; on G1 delete only table inet ngfw and one non-MGMT M1 address/route listed in saved config.
  2. Run systemctl restart ngfw-engine only; leave FRR/Keepalived running.
  3. Capture ip -j address/route and scoped nft table; poll protocol status.
- **TRAFFIC GENERATOR:** Continuous LAN new-flow curl + MGMT API probes.
- **EXPECTED RUNTIME:** M1 objects restored from Running; FRR desired config and own routes retained/reconverge; Keepalived legitimate VIP not deleted; API PID unchanged; no boot change.
- **EXPECTED PACKETS:** Baseline policy and traffic restored; no unrelated-session flush from M5.
- **EVIDENCE:** C0 plus Exact destructive argv, before/after PIDs/hashes, owner-aware route/address diff, journal.
- **CLEANUP:** C0; explicitly confirm ens39 untouched and dynamic services healthy.
- **PASS:** Restored legacy state plus preserved valid external ownership, exact Running unchanged.
- **FAIL:** Engine sweeps learned routes/VIP because absent in ordinary config; misuses stale artifact as authority. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A06 — BGP exchange and structured status

- **TOPOLOGY:** G1,R1,R2,S,LAN.
- **INITIAL CONFIG:** bgp.json; G1 AS65000, R1/R2 AS65010, explicit import203.0.113/24 exportLAN/24.
- **EXACT COMMANDS/API ACTIONS:**
  1. Load both peer files, including transit iBGP next-hop-self and explicit LAN filter.
  2. C0 commit; vtysh -c 'show bgp ipv4 unicast summary json'.
  3. On G1: vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.1 advertised-routes json'; ip -j route show 203.0.113.0/24; GET routing views.
- **TRAFFIC GENERATOR:** LAN curl /id to S; S curl or TCP echo reply; collect each NIC.
- **EXPECTED RUNTIME:** Both neighbors Established within60s; only desired advertisements; JSON counters/uptime/source agree; received routes nullable unless retained.
- **EXPECTED PACKETS:** Bidirectional server flow via chosen eBGP next hop; source LAN unchanged.
- **EVIDENCE:** C0 plus FRR/API JSON; route attrs; peer advertised/received filtered evidence; pcap.
- **CLEANUP:** C0/peer restore.
- **PASS:** Session+prefix+kernel+packet proof and no protected route leak.
- **FAIL:** Only a green daemon or TCP179 established without BGP/routes/traffic. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A07 — Prefix filters, route maps, defaults and redistribution

- **TOPOLOGY:** G1,R1,R2,S.
- **INITIAL CONFIG:** bgp-policy.json plus OSPF redistribution variant.
- **EXACT COMMANDS/API ACTIONS:**
  1. Peer adds test blackhole203.0.114.0/24 and advertises it alongside allowed203.0.113.0/24.
  2. Commit policy allowing only203.0.113.0/24; verify denied route absent from G1 usable FIB.
  3. Add an exact M1 static198.18.10.0/24 fixture and enable filtered M1_STATIC redistribution; compare peer advertisements.
  4. Toggle default_originate only with explicit route-map; compare 0.0.0.0/0 separately from more-specific prefixes; test localpref/MED/prepend on the expected import/export direction.
- **TRAFFIC GENERATOR:** LAN approved /id works; TCP to unapproved test prefix fails under intended routing/security policy.
- **EXPECTED RUNTIME:** Permit/deny and attribute values match; only explicitly allowed static exported; MGMT/local not leaked; proto196 recognized through filtered kernel redistribution.
- **EXPECTED PACKETS:** No packet path gained solely by unauthorized BGP advertisement.
- **EVIDENCE:** C0 plus G1+peer JSON RIB/advertisement/attrs, kernel routes, config validation outputs.
- **CLEANUP:** Remove exact peer test route/advertisement; C0.
- **PASS:** Every positive and negative prefix/attribute/default case observed on correct side.
- **FAIL:** Unconditional redistribute connected/kernel, generated protected guard overridden, claimed static export absent on pinned FRR. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A08 — BGP failure, max-prefix and recovery

- **TOPOLOGY:** G1,R1/R2,S.
- **INITIAL CONFIG:** bgp-max-prefix.json; limit2 and peer three approved test routes, then normal bgp.
- **EXACT COMMANDS/API ACTIONS:**
  1. Bring peer session up, then advertise three prefixes in allowed lab block against maximum_prefixes2.
  2. Observe BGP reason/counter/withdraw; remove extra advertisement and use documented peer clear/session restart.
  3. Stop R1 frr and restore it; verify G1 peer state/prefix recovery.
- **TRAFFIC GENERATOR:** LAN per-second fresh curls; long TCP stream in separate trace.
- **EXPECTED RUNTIME:** Max-prefix session reaction matches pinned FRR; no overload memory growth; neighbor loss withdraws routes; recovery after explicit correction.
- **EXPECTED PACKETS:** Fresh flows use surviving path if installed; preexisting connection outcome recorded separately.
- **EVIDENCE:** C0 plus Neighbor reasons/uptime/counters; routes/pcap/traffic log; package version.
- **CLEANUP:** Remove extra prefix announcements, restore peer config, C0.
- **PASS:** Limit and failure/recovery implemented, safe state no unauthorized route.
- **FAIL:** Test labels a configured limit as enforced without real overrun; unrelated M1 objects altered. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A09 — BFD failure with carrier still up

- **TOPOLOGY:** G1,R1,R2,S,LAN.
- **INITIAL CONFIG:** bfd.json;300ms TX/RX multiplier3 on eBGP peers.
- **EXACT COMMANDS/API ACTIONS:**
  1. On R1 create only lab table: nft add table inet m5_test_fault; nft 'add chain inet m5_test_fault input { type filter hook input priority -300; policy accept; }'.
  2. nft add rule inet m5_test_fault input ip saddr 192.0.2.2 udp dport 3784 drop.
  3. Keep link UP; timestamp vtysh -c 'show bfd peers json', BGP and route snapshots; then nft delete table inet m5_test_fault.
- **TRAFFIC GENERATOR:** LAN fresh curls and independent carrier ip link observation.
- **EXPECTED RUNTIME:** BFD DOWN and dependent route reaction <=5s for this idle lab profile; record negotiated timers and actual interval; recovered UP after rule removed.
- **EXPECTED PACKETS:** Surviving route delivers fresh flows; no kernel link-down explanation substituted.
- **EVIDENCE:** C0 plus UDP3784 pcap, monotonic timestamps, carrier state, BFD/BGP/FIB log.
- **CLEANUP:** Delete only m5_test_fault on peer; C0.
- **PASS:** Measured bound met with carrier UP and routing reaction; recovery seen.
- **FAIL:** Only TCP neighbor timeout, wrong peer fault, route never withdraws, or BFD probe leads to a second Go route writer. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A10 — ECMP distribution and kernel settings

- **TOPOLOGY:** G1,R1,R2,S,LAN.
- **INITIAL CONFIG:** ecmp.json; equal same-AS paths and unrelated baseline NAT preserved.
- **EXACT COMMANDS/API ACTIONS:**
  1. C0 commit; ip -j route show 203.0.113.0/24; record fib_multipath_hash_policy and participating rp_filter.
  2. On G1 capture ens33 and ens40 simultaneously.
  3. On LAN: python3 tests/integration/m5/traffic.py client --host 203.0.113.10 --port 18080 --connections 200 --new-source-port --jsonl ecmp.jsonl.
- **TRAFFIC GENERATOR:** 200 independent TCP flows (distinct source ports), request ID each; selected flows reused separately.
- **EXPECTED RUNTIME:** FRR selected multipath and kernel route has both next hops; hash policy lease1 and permitted per-interface source-validation settings.
- **EXPECTED PACKETS:** Both egress paths used across sample, each stable flow follows a path while topology stable; no strict50/50 promise; returns actually captured.
- **EVIDENCE:** C0 plus FIB nexthops/attrs, lease receipt, flow-ID->egress table, four-way captures, failures.
- **CLEANUP:** C0 restores leased sysctls by compare-and-restore.
- **PASS:** Both paths carry >0 successful distinct flows and >=99% success in idle no-fault window; no packet-by-packet spray.
- **FAIL:** One path unused despite expected eligible route, unintended NAT/mark/ip-rule changes, global MGMT sysctl changed. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A11 — Routed WAN primary/backup and established TCP

- **TOPOLOGY:** G1,R1,R2,S,LAN.
- **INITIAL CONFIG:** failover.json; localpref200/100 and BFD enabled.
- **EXACT COMMANDS/API ACTIONS:**
  1. C0 commit; capture selected R1 next hop.
  2. On G1: ip link set dev ens33 down; keep ens39 up; timestamp; collect next hop and return path.
  3. After30s: ip link set dev ens33 up; observe route preference recovery without changing Running.
- **TRAFFIC GENERATOR:** One held TCP echo stream with sequence numbers plus new curl every1s; S records client address and sequence.
- **EXPECTED RUNTIME:** R2 selected after failure, R1 preferred after recovery; new flow succeeds <=10s in this lab; M2 existing identity unchanged unless connection actually expires/closes.
- **EXPECTED PACKETS:** Actual old stream may recover, stall or close; report sequence loss/retransmission/reconnect; no source-address translation; capture S return via R1 transit->R2 when needed.
- **EVIDENCE:** C0 plus Per-stream sequence/timing, conntrack -L scoped to lab tuple, M2 session ID/mark/epoch, RIB/FIB/pcap.
- **CLEANUP:** Always ip link ens33 up first; C0; verify baseline route and MGMT.
- **PASS:** New-flow failover/recovery and source/return correctness; old-flow outcome accurately reported without fresh flow substituted.
- **FAIL:** No new reachability after bound; old flow silently recreated as 'continuous'; conntrack flush/mark reassignment. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A12 — Source/device-bound health and timeout observation

- **TOPOLOGY:** G1,R1,R2 with TCP18082 services.
- **INITIAL CONFIG:** wan-probe.json with explicit TCP endpoint per path and rise2/fall3.
- **EXACT COMMANDS/API ACTIONS:**
  1. Start test TCP18082 on each peer's directly connected WAN address.
  2. On R1 scoped fault table drop tcp dport18082 from192.0.2.2 while BFD/BGP stay up.
  3. GET status?subsystem=wan&view=paths every1s; remove fault after three failures.
- **TRAFFIC GENERATOR:** Probe TCP only; baseline LAN->S traffic simultaneously.
- **EXPECTED RUNTIME:** Only R1 probe becomes DOWN after configured fall count; FRR/BFD/selected FIB unchanged; probe recovers after rise; counters/time observed.
- **EXPECTED PACKETS:** Probe source/interface matches configured path in pcap; no fallback onto R2; timeout bounded.
- **EVIDENCE:** C0 plus Probe JSON counters, socket/pcap source evidence, unchanged route/ctmark table, goroutine/socket bound metrics.
- **CLEANUP:** Delete exact peer fault table; stop service PIDs; C0.
- **PASS:** Observation correct, no path writer, cancellation closes sockets when config removed.
- **FAIL:** Probe changes routes, binds wrong interface, marks timeout UP, leaks workers, or silently adds engine NET_RAW. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A13 — Reject unsupported WAN modes and preserve ordinary NAT

- **TOPOLOGY:** G1,LAN,WAN1.
- **INITIAL CONFIG:** Saved baseline NAT plus invalid weighted/PBR/multi-zone/overlapping-NAT overlays.
- **EXACT COMMANDS/API ACTIONS:**
  1. Submit each invalid Candidate vector and capture400+state diff using C0.
  2. Run existing M1 DNAT/SNAT/masquerade acceptance procedure on unchanged baseline rules.
  3. Record nft NAT match/counters and conntrack original/reply tuples for a fresh test connection.
- **TRAFFIC GENERATOR:** Existing M1 case traffic on192.0.2/192.168.10/10.20 ranges; no overlapping new multipath prefix.
- **EXPECTED RUNTIME:** No custom WAN route tables/ip rules/ct marks; invalid combinations rejected; original NAT still works.
- **EXPECTED PACKETS:** SNAT/DNAT addresses/ports and reverse mapping agree with M1 evidence semantics.
- **EVIDENCE:** C0 plus HTTP rejection; scoped nft/capture/conntrack tuples; old/new normalized semantics.
- **CLEANUP:** Restore original Candidate; C0 if NAT temporary fixture used.
- **PASS:** All unsupported vectors rejected without mutation and baseline NAT demonstrated.
- **FAIL:** Claiming weighted/sticky multi-ISP NAT is supported or replacing existing NAT ownership. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A14 — TCP balancing algorithms and connection limits

- **TOPOLOGY:** G1,LAN,DMZ.
- **INITIAL CONFIG:** haproxy-tcp.json; listener10.20.0.20:18080, B1/B2 TCP18081.
- **EXACT COMMANDS/API ACTIONS:**
  1. On DMZ add exact temporary10.20.0.11/24 alias; start two traffic.py serve processes with IDs B1/B2 bound to their own address:18081.
  2. C0 round-robin, least-connections and source-hash variants separately; record generated config hash.
  3. Client opens100 independent TCP flows; for leastconn hold20 connections to one server then add new connections; test configured service/backend limit.
- **TRAFFIC GENERATOR:** `python3 tests/integration/m5/traffic.py client --host 10.20.0.20 --port 18080 --connections 100`, plus `hold --seconds 30` with the same host/port.
- **EXPECTED RUNTIME:** HAProxy services/backends UP; active/total counters match actual connections, configured limit enforced.
- **EXPECTED PACKETS:** RR reaches both servers; leastconn favors currently less-busy server under controlled load; same source maps consistently with stable source-hash pool; no exact RR guarantee across pool churn.
- **EVIDENCE:** C0 plus Runtime JSON/schema, backend IDs and source log, client flow logs, DMZ/LAN pcaps.
- **CLEANUP:** Stop exact backend PIDs; remove exact alias; C0 listener ordinary address restoration.
- **PASS:** Each algorithm's expected controlled behavior and connection bound proved.
- **FAIL:** Claiming distribution from one request; traffic succeeds from unauthorized zone; proxy legs mislabelled same M2 session. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A15 — HTTP routing, health failure and recovery

- **TOPOLOGY:** G1,LAN,DMZ.
- **INITIAL CONFIG:** haproxy-http.json; host and /api path rules, HTTP /health expected200.
- **EXACT COMMANDS/API ACTIONS:**
  1. curl -fsS -H 'Host: app.lab.test' http://10.20.0.20:18080/id; curl -fsS -H 'Host: app.lab.test' http://10.20.0.20:18080/api/id.
  2. Switch B1 health file to503 (traffic server local fixture control), keeping application process alive; wait configured interval*fall+2s.
  3. Restore200; wait interval*rise+2s; then stop both backends and record unavailable response without changing Running.
- **TRAFFIC GENERATOR:** Repeated HTTP requests with fresh Connection: close and unique IDs; routing negative host/path vectors.
- **EXPECTED RUNTIME:** Exact rule priority routes expected backend; health DOWN removes server from eligible pool; recovery UP; no false config rollback on backend outage.
- **EXPECTED PACKETS:** No new request reaches unhealthy B1 after down threshold; existing accepted requests not promised recall; no backend request when all unavailable.
- **EVIDENCE:** C0 plus Client status/backend markers; /health access log; HAProxy counters/transitions; request-bound pcap.
- **CLEANUP:** Restore health files/services; C0.
- **PASS:** Correct host/path selection, health removal/re-add and explicit all-down error; engine policy unaffected.
- **FAIL:** Backend chosen after DOWN contrary to algorithm, unknown host gets unintended privileged backend, daemon exit0 mistaken for backend health. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A16 — TLS termination, verified bridging and rejection

- **TOPOLOGY:** G1,LAN,DMZ.
- **INITIAL CONFIG:** haproxy-tls.json; lab.example.test:18443 with locally provisioned versioned cert/CA refs.
- **EXACT COMMANDS/API ACTIONS:**
  1. Client: curl --cacert lab-ca.pem --resolve lab.example.test:18443:10.20.0.20 https://lab.example.test:18443/id.
  2. Client negative: `openssl s_client -connect 10.20.0.20:18443 -servername lab.example.test -tls1_1`.
  3. For backend bridge enable TLS with CA+hostname; rotate backend to wrong-CA then wrong-host certificate; capture handshake failures.
  4. Submit invalid frontend cert/key pair as new secret version and commit; retain old working generation.
  5. Switch to TCP TLS PASSTHROUGH with SNI rules selecting two TLS backends; use `openssl s_client -connect 10.20.0.20:18443 -servername b1.lab.test` and b2.lab.test. Compare returned certificate fingerprint with the selected backend. HAProxy has no frontend key in this variant; payload stays encrypted to backend. Save a separate target overlay/diff for this variant.
- **TRAFFIC GENERATOR:** Synthetic HTTPS /id and backend TLS service; no client private key in evidence.
- **EXPECTED RUNTIME:** TLS floor enforced; key/cert mismatch rejected before reload; wrong backend CA/name marks connection/health failed; original listener stays on failed candidate.
- **EXPECTED PACKETS:** Frontend TLS terminated once in HAProxy; backend encrypted only in bridging fixture; no plaintext backend application request when verification fails.
- **EVIDENCE:** C0 plus Certificate public fingerprints only, CLI exit codes, handshake metadata pcap, sanitized errors, old/target version hashes.
- **CLEANUP:** Restore valid test cert ref/backend process; delete test private keys locally after task retention decision; C0.
- **PASS:** Success with trusted correct identities and failure with wrong CA/name/old TLS; no verify-none fallback.
- **FAIL:** Success despite failed verification, secret content in artifact archive or plaintext bridge misreported as TLS. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A17 — Local admission, listener conflicts and M4 exclusion

- **TOPOLOGY:** G1,LAN,WAN,DMZ,MGMT.
- **INITIAL CONFIG:** haproxy-http.json restricted to LAN CIDR192.168.10.10/32; invalid M4/listener variants.
- **EXACT COMMANDS/API ACTIONS:**
  1. Allowed LAN curl /id; denied WAN curl --max-time2 http://10.20.0.20:18080/id; add temporary LAN .11 client alias to test same-zone denied CIDR.
  2. Inspect nft -j list table inet ngfw_m5_services and dedicated UID OUTPUT counters.
  3. Submit candidate enabling M4 while LB active; reverse case enable LB in saved M4 config; test wildcard/API/VIP/duplicate DNAT listener conflicts.
- **TRAFFIC GENERATOR:** Positive/negative new TCP connections, synthetic backend egress attempt under ngfw-lb UID to unlisted target, legacy forwarded allow/deny flow.
- **EXPECTED RUNTIME:** Only explicit service sources accepted; backend/check egress allowlisted; no other UID affected; invalid combinations reject before apply.
- **EXPECTED PACKETS:** Denied packets never reach backend; legacy FORWARD unchanged; no claim that DELIVERY_ONLY traffic passed M4 request inspection.
- **EVIDENCE:** C0 plus nft scoped counters/trace, client/backend logs, HTTP errors/state hashes, unchanged legacy nft semantics.
- **CLEANUP:** Remove only temporary client alias; restore M4 baseline through normal Candidate flow; C0.
- **PASS:** Admission and both-direction M4 rejection proved on actual packets/config; zero unintended egress.
- **FAIL:** Relying on forward policy for local listener, broad established bypass, HAProxy accepted while effective M4 enabled. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A18 — VRRP ownership and master failure

- **TOPOLOGY:** G1,G2,R1,LAN.
- **INITIAL CONFIG:** ha-g1.json and ha-g2.json; sync groups EDGE, preempt false.
- **EXACT COMMANDS/API ACTIONS:**
  1. Apply node-specific C0 fixtures; on each run ip -j addr show and GET HA groups.
  2. Change LAN default to via192.168.10.254 and R1 LAN route to via192.0.2.254; save old exact route first.
  3. On G1: systemctl stop ngfw-keepalived; poll G2 VIP/role; restart G1 keepalived; capture protocol112 and ARP on LAN/WAN.
- **TRAFFIC GENERATOR:** Continuous LAN new TCP/curl plus separate long stream; MGMT paths remain on ordinary IP.
- **EXPECTED RUNTIME:** Exactly one MASTER and both VIPs on that node after convergence; G2 takes over <=8s in idle advert1s lab; G1 stays BACKUP with nopreempt.
- **EXPECTED PACKETS:** New flows work via G2 after takeover; old TCP may fail because kernel/M2/M4 state not synced; ARP and routing recorded.
- **EVIDENCE:** C0 plus Both-node timestamped role/priority/VIP snapshots, VRRP/ARP pcap, sequence logs, independent boot/config identities.
- **CLEANUP:** Restore client and R1 gateways/routes before stopping HA; C0 on both nodes; check no VIP left.
- **PASS:** Single owner in healthy network, measured takeover and ordinary IP retention; existing-session limitation accurately reported.
- **FAIL:** VIP exists in M1 ordinary config, duplicate owner after settled healthy link, claims seamless established TCP using new connection. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A19 — Preempt delay, sync-group fault and engine readiness

- **TOPOLOGY:** G1,G2,R1,LAN.
- **INITIAL CONFIG:** ha-preempt.json; preempt true delay10s, tracked ens33; second variant nopreempt.
- **EXACT COMMANDS/API ACTIONS:**
  1. After G2 takeover, restore G1; measure preempt occurs no earlier than10s after qualified recovery, within25s idle lab bound.
  2. On current MASTER: ip link set ens33 down; verify LAN+WAN groups yield together; restore ens33.
  3. Stop ngfw-engine on current MASTER; wait readiness age>5s then inspect FAULT/VIPs; restart engine; separately restart ngfw-api and compare role.
  4. In isolated failure subcase drop protocol112 between peers while both healthy, record possible dual-MASTER, then remove fault.
- **TRAFFIC GENERATOR:** New-flow curl during transitions; long stream recorded separately.
- **EXPECTED RUNTIME:** Track interface/readiness causes FAULT and peer ownership; API restart alone does not withdraw VIP; configured preempt/no-preempt behavior holds; partition limitation visible.
- **EXPECTED PACKETS:** VIP packet delivery follows real elected owner; no promise of fencing/quorum under peer partition.
- **EVIDENCE:** C0 plus Readiness metadata (no secrets), clock/boot/gen, both-node FIFO/JSON/VIPs, protocol112 pcap.
- **CLEANUP:** Bring data link up, restart engine/API, remove only peer fault table, C0 both nodes.
- **PASS:** Configured role/timing/readiness behavior; sync group together; partition risk documented rather than hidden.
- **FAIL:** Stale readiness keeps MASTER indefinitely, API outage forces HA unnecessarily, split-brain test falsely claimed solved. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A20 — FRR syntax/unavailable/crash injection

- **TOPOLOGY:** G1 and routing peers.
- **INITIAL CONFIG:** combined.json with lab fault profile; unrelated legacy flow enabled.
- **EXACT COMMANDS/API ACTIONS:**
  1. One-shot lab wrapper returns native syntax failure at frr.prepare; commit and capture error.
  2. Stop/mask only frr in disposable lab, attempt enabled routing commit; undo mask immediately afterward.
  3. Kill only recorded FRR daemon PID with SIGKILL and observe fixed unit/watchfrr recovery; do not kill engine/API.
- **TRAFFIC GENERATOR:** Continuous baseline M1 allowed flow and prohibited flow probe.
- **EXPECTED RUNTIME:** Preflight rejection no runtime writes; apply-unavailable compensated; crash loses/reconverges only dynamic reachability; Running same on rejected commit.
- **EXPECTED PACKETS:** M1 firewall/NAT semantics persist during FRR outage; routing-dependent destination may be unavailable.
- **EVIDENCE:** C0 plus Phase/error logs, commit response, before/after version/nft hashes, service PIDs, route/pcap.
- **CLEANUP:** Remove marker/mask then start required daemon; C0.
- **PASS:** Each of syntax, unavailable and crash tested with distinct evidence and unaffected legacy policy.
- **FAIL:** Only mock tests passed, invalid Candidate substituted for invalid generated/native config test, unrelated nft destroyed. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A21 — HAProxy syntax/reload failure and drain bounds

- **TOPOLOGY:** G1,LAN,DMZ.
- **INITIAL CONFIG:** combined.json, then changed LB config under lab wrapper.
- **EXACT COMMANDS/API ACTIONS:**
  1. Inject nonzero haproxy -c for one staged config; verify no publish/reload.
  2. Next run allow syntax, fail service reload after artifact publication; capture compensation.
  3. Hold old TCP connection; successful later reload and enforce fixed30s drain bound; do not report the terminated stream as restored.
- **TRAFFIC GENERATOR:** Baseline route flow, HTTP request loop, held TCP session.
- **EXPECTED RUNTIME:** Old accepted worker/config preserved or recovered; failed commit leaves old Running or deliberate newer recovery generation; guard remains correct; routing unchanged.
- **EXPECTED PACKETS:** Only affected LB connections may reset; no unauthorized listener exposure while partial config installed.
- **EVIDENCE:** C0 plus Master/worker PIDs+start times, socket JSON, staged/active/accepted hashes, M1/FRR unchanged proof.
- **CLEANUP:** Remove one-shot marker; restore old service artifact via engine; C0.
- **PASS:** Syntax and reload failures contained, old config verified, bounded drain proven.
- **FAIL:** Exit0 accepted without new-worker proof; rollback asserted from file alone; unrelated FRR routes changed. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A22 — Keepalived unavailable and private-status failures

- **TOPOLOGY:** G1,G2.
- **INITIAL CONFIG:** ha fixtures plus lab permission/fault profile.
- **EXACT COMMANDS/API ACTIONS:**
  1. Stop/mask only ngfw-keepalived on G1; attempt HA config commit and capture result; unmask.
  2. Inject read/write permission failure on a root-owned disposable generated directory (not Running or MGMT config).
  3. Make protected JSON snapshot stale/partial using lab wrapper; close/reopen FIFO reader to force resync.
- **TRAFFIC GENERATOR:** LAN new-flow loop, ordinary G1/G2 management probes.
- **EXPECTED RUNTIME:** Apply failure compensated; absent process cannot be labelled MASTER; stale status UNKNOWN; surviving peer serves VIP; ordinary IPs untouched.
- **EXPECTED PACKETS:** No extra ordinary address manipulation to simulate VIP recovery.
- **EVIDENCE:** C0 plus Sanitized error/phase, directory ownership, FIFO+JSON timestamps, both nodes kernel VIP evidence.
- **CLEANUP:** Restore exact saved modes/file provider, unmask/start, C0 both nodes.
- **PASS:** Errors explicit, status truthful, unaffected interface state preserved.
- **FAIL:** World-writable tmp fallback, forced VIP ip addr mutation, stale snapshot green MASTER. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A23 — Partial apply and reverse compensation

- **TOPOLOGY:** G1,G2,peers,LAN,DMZ.
- **INITIAL CONFIG:** combined.json changes one route/protocol, LB backend and HA priority together.
- **EXACT COMMANDS/API ACTIONS:**
  1. Use lab wrapper to succeed FRR apply then fail HAProxy reload; record completed phases.
  2. Second subcase succeeds FRR/LB then fails Keepalived reload.
  3. Third subcase also fails reverse FRR restore once; inspect RECOVERY_REQUIRED and journals, then remove fault and explicitly recover.
- **TRAFFIC GENERATOR:** Independent baseline M1 flow plus case-specific fresh/held flow logs.
- **EXPECTED RUNTIME:** Old config/inner M2 metadata restored before publication; after-publication failure recovers via newer generation; reverse dependency order; failed compensation retains WAL and affected fences.
- **EXPECTED PACKETS:** No blanket kernel/conntrack flush; affected service interruption permitted and measured; unrelated baseline flow/policy stays correct.
- **EVIDENCE:** C0 plus Exact phase trace, Running/previous/outer+inner hashes, sanitized receipts, before/after route/guard/VIP/worker status.
- **CLEANUP:** Remove fault before recovery; do not delete journal; verify accepted desired config then C0.
- **PASS:** Every failure position and failed-compensation case behaves per state machine; raw proof beyond response code.
- **FAIL:** Target published on preapply failure, journal removed while unrecovered, old config compiled with target epoch, learned routes replayed. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A24 — Engine SIGKILL at durable activation boundaries

- **TOPOLOGY:** G1 plus peers/G2 as needed.
- **INITIAL CONFIG:** combined.json with deterministic lab barriers; fresh baseline each subcase.
- **EXACT COMMANDS/API ACTIONS:**
  1. Block at W1 after outer WAL durable/before first runtime write; kill -KILL recorded engine PID, remove block, systemctl start ngfw-engine.
  2. Repeat W2 after legacy apply/before external apply; W3 after FRR/LB apply/before Running publish; W4 after Running publish/before finalization.
  3. Add W5 partial compensation and corrupt outer-journal-copy test on disposable clone; never corrupt the sole recoverable baseline.
- **TRAFFIC GENERATOR:** MGMT records availability; baseline new/held streams timestamped; HA readiness age monitored.
- **EXPECTED RUNTIME:** W1–W3 recover old authoritative Running, W4 converges published target, W5 retains recovery status until fixed; exact inner metadata; corrupt journal stops M5 writes.
- **EXPECTED PACKETS:** Reboot/startup does not open unverified LB service; VIP ready expires after dead engine; M1 state recovers according to inner journal.
- **EVIDENCE:** C0 plus Barrier marker phase + fsync acknowledgment, kill/restart PID and bootID, both journals/Running hashes, outcome snapshots.
- **CLEANUP:** Remove barrier/fault; normal engine recovery; C0; retain corrupt copy as evidence without replacing accepted state.
- **PASS:** Every window deterministically hit and independently restored; no claim based on randomly timed kill.
- **FAIL:** Missed window reported PASS, target guessed from newest file timestamp, deleted journal forces startup, old/target versions mixed. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A25 — API restart, IPC negotiation and UI status

- **TOPOLOGY:** G1,MGMT and traffic endpoints.
- **INITIAL CONFIG:** A06/A14/A18 configured separately; mixed-version test on disposable clone.
- **EXACT COMMANDS/API ACTIONS:**
  1. systemctl restart ngfw-api while traffic runs; compare engine/daemon PIDs and kernel state.
  2. Disconnect HTTP client during delayed commit; retrieve /api/v1/config and M5 status; retry same operation ID only when supported/alive.
  3. Pair new API with old engine fixture: submit M5 Candidate/commit and verify explicit unsupported error before mutation.
  4. Open Network services editor/status: save/validate/commit via existing flow; navigate away during poll; exercise page limit/cursor expiry.
- **TRAFFIC GENERATOR:** Traffic continuous across API restart; UI/status polling bounded.
- **EXPECTED RUNTIME:** API restart leaves data processes/state; cached capabilities correct; long config mutation may exceed old60s without malformed timeout success; no tool per HTTP poll.
- **EXPECTED PACKETS:** No traffic restart because management connection ends.
- **EVIDENCE:** C0 plus HTTP/IPC request IDs without tokens, timestamps, versions, process state, UI request trace and cursor errors.
- **CLEANUP:** Restore paired binaries/profile in clone; C0.
- **PASS:** Authority and timeout/capability gates correct; old engine cannot silently ignore M5; unsaved UI fields preserved.
- **FAIL:** API executes tools, config accepted by old engine but ignored, status polling creates unbounded subprocesses, duplicate new commit after timeout. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A26 — Stale generated config, daemon drift and event loss

- **TOPOLOGY:** G1 plus required peers.
- **INITIAL CONFIG:** A06/A14/A18, one subsystem per subcase.
- **EXACT COMMANDS/API ACTIONS:**
  1. Edit only a disposable generated artifact copy or active reference to an older generation under lab control; do not edit Running.
  2. Restart relevant daemon; wait periodic reconcile<=30s; compare accepted desired digest.
  3. Restart engine status worker/reopen FIFO to lose event; collect fresh JSON role snapshot; inject a legitimate extra learned route permitted by policy.
- **TRAFFIC GENERATOR:** Normal protocol/LB/HA traffic plus status reads.
- **EXPECTED RUNTIME:** Tampered/old artifacts detected/replaced from authoritative Running or explicit RecoveryRequired; legitimate learned route/role transition not treated as config drift.
- **EXPECTED PACKETS:** No teardown of unrelated state during repair; unverified listener remains fenced.
- **EVIDENCE:** C0 plus Generated/Running hash comparison, drift counters, daemon PID/start, JSON/source age, route and VIP state.
- **CLEANUP:** Restore immutable artifact through engine recovery; no manual write memory; C0.
- **PASS:** Desired config repair and legitimate runtime preservation both proved.
- **FAIL:** Deleting allowed learned route/VIP simply absent in Config, regenerating Running from daemon config, trusting stale status. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A27 — Privileges, secrets, limits and cancellation

- **TOPOLOGY:** G1+MGMT.
- **INITIAL CONFIG:** A00 plus enabled component profiles; synthetic large/secret-bearing stderr fixtures.
- **EXACT COMMANDS/API ACTIONS:**
  1. Read actual CapEff/CapBnd/NoNewPrivs for engine/API and each daemon/helper; stat sockets/config/runtime files; try read as ngfw API user.
  2. Under lab wrapper emit secret sentinel in stderr and oversized JSON, then hang child; invoke validation/status and cancel.
  3. Search only this case's sanitized artifacts for exact sentinel; inspect child PIDs after timeout; exercise inaccessible secret and unsafe symlink refs.
- **TRAFFIC GENERATOR:** No real traffic needed except baseline connectivity and probe capability; no secrets in packets.
- **EXPECTED RUNTIME:** API no caps/access to secret/control sockets; engine still NET_ADMIN; bounded subprocess/output/time; no zombie children; unsafe profiles rejected.
- **EXPECTED PACKETS:** No newly privileged network action on failure.
- **EVIDENCE:** C0 plus Process/status/stat proof, sanitized command metadata/error, leak scan results (never print sentinel value), output sizes, timeout duration.
- **CLEANUP:** Restore file modes and remove sentinel secrets/wrappers; C0.
- **PASS:** All boundaries enforced under actual unit, source references private, no leak in logs/API/archive.
- **FAIL:** Claiming least privilege from unit text alone, enlarged API/engine caps, raw stderr/key material exposed, infinite child/output. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A28 — M1–M4 regression and clean reboot

- **TOPOLOGY:** Original four-zone lab plus M5 peers.
- **INITIAL CONFIG:** M5 absent then each supported enabled combination; exact T00 legacy baseline.
- **EXACT COMMANDS/API ACTIONS:**
  1. Run selected named tests in COMPATIBILITY_MATRIX and tests of every touched module; perform Linux cross-build and frontend build.
  2. Run scripts/verify-m1-linux.sh and existing M1 matrix traffic/rollback/startup procedures in disposable lab.
  3. Reboot G1 once per enabled/disabled profile; compare Running, nft semantics, ordinary routes/VLANs, M5 generation/status and service caps.
  4. Run M2 identity/epoch/NAT aliases, M3 ambiguous/late sensor-event rejection, and existing M4 request-gate scenarios with HAProxy disabled.
- **TRAFFIC GENERATOR:** Existing M1 NAT/policy and M3/M4 positive/negative traffic; M5 route flow separately.
- **EXPECTED RUNTIME:** Legacy accepted behavior retained; no-op when absent; correctly reconciled enabled service configs; no failed unit hidden by report.
- **EXPECTED PACKETS:** Default deny, NAT reverse path, correlation and gate verdict behavior unchanged; no cross-generation authorization.
- **EVIDENCE:** C0 plus Legacy raw case outputs plus new hashes/PIDs/bootID/journals, test summary, source dirty baseline hash.
- **CLEANUP:** Restore old config, services and peer topology through C0; document existing network-online boot warning separately.
- **PASS:** No new regressions; all required kernel checks evidenced; pre-existing failures recorded and not attributed as new PASS.
- **FAIL:** Only new M5 tests run, legacy failure hidden/skipped, production code rewritten to satisfy fixture, M4 conflict bypass. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A29 — Control-plane peer/interface/TTL admission

- **TOPOLOGY:** G1,configured peers and isolated unauthorized source.
- **INITIAL CONFIG:** A02/A06/A09/A18 config plus unauthorized WAN-side test sender.
- **EXACT COMMANDS/API ACTIONS:**
  1. Capture protocol scopes in inet ngfw_m5_services.
  2. From unauthorized WAN sender: `nc -vz -w 2 192.0.2.2 179`. For BFD: `sudo python3 -c 'from scapy.all import IP,UDP,Raw,send; send(IP(dst="192.0.2.2",ttl=64)/UDP(sport=49152,dport=3784)/Raw(b"m5-negative"),count=10,inter=0.1,verbose=False)'`. Scapy is a test-sender dependency only.
  3. From LAN (an unauthorized OSPF ingress), run `sudo python3 -c 'from scapy.all import IP,Raw,send; send(IP(dst="192.0.2.2",ttl=1,proto=89)/Raw(b"m5-negative"),count=10,inter=0.1,verbose=False)'`. From unauthorized WAN sender repeat with `ttl=64,proto=112` for VRRP. Compare scoped drop counters/trace and capture; the negative probe need not form a valid adjacency because the admission guard must drop it first.
  4. Verify configured peers still reach FULL/Established/UP and VRRP roles.
- **TRAFFIC GENERATOR:** Native protocol traffic plus <=10 negative packets per vector; no spoof of production networks.
- **EXPECTED RUNTIME:** Wrong peer/source/interface/TTL drops, legitimate control traffic works; other host services unaffected.
- **EXPECTED PACKETS:** Dropped control packets do not reach owned daemon scope; return traffic to configured peer admitted.
- **EVIDENCE:** C0 plus Scoped nft trace/counters, NIC capture, protocol state, generator vector/exit code.
- **CLEANUP:** Remove sender alias/tool process/fault table; C0.
- **PASS:** Every supported control scope positive+negative proved without broad host accept.
- **FAIL:** Tests rely on daemon rejection while guard admits arbitrary peers; established shortcut defeats scope; unrelated MGMT blocked. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A30 — OPTIONAL IPVS NAT distribution, persistence and health

- **TOPOLOGY:** G1,LAN,DMZ with backend default gatewayG1.
- **INITIAL CONFIG:** ipvs.json; ordinary listener10.20.0.20:18080 and realservers.10/.11:18081; HAProxy/M4 off.
- **EXACT COMMANDS/API ACTIONS:**
  1. C0 optional capability commit; read IPVS generic-netlink observer status (ipvsadm -Ln --stats allowed only as human secondary evidence).
  2. Run rr/wrr/lc/sh separate fixtures,200 fresh flows; persistence60s repeated from same source, then from separate allowed source.
  3. Stop B1 health listener, verify exact removal/down state and no new traffic; restore and verify re-add; restart checker-only unit.
- **TRAFFIC GENERATOR:** Identified TCP servers and TCP/UDP case traffic where valid health probe configured; full NAT return captures.
- **EXPECTED RUNTIME:** One Keepalived checker writer; exact virtual/real tuple and counters; persistence retained within configured period on stable pool; optional module state.
- **EXPECTED PACKETS:** Traffic reaches expected servers, replies through G1; M2 NAT alias correlation correct; no direct return shortcut.
- **EVIDENCE:** C0 plus Netlink JSON, IPVS counters, backend logs and both-side pcap, M1/M2/M3 regression output.
- **CLEANUP:** Disable optional config, verify owned virtual services gone; stop checker unit; restore alias/gateway/C0.
- **PASS:** All optional claims proved without core regression; NAT only explicitly recorded.
- **FAIL:** Two writers, unchecked DR/TUN/fwmark support, persistence confused with transport continuity, direct backend return bypass. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A31 — Future conntrackd/VRF/PBR remain unavailable

- **TOPOLOGY:** G1.
- **INITIAL CONFIG:** Unknown future config keys / no package units.
- **EXACT COMMANDS/API ACTIONS:**
  1. Submit root M5 fields conntrack_sync,vrf,policy_routing and weighted WAN enum through Candidate API.
  2. Check no conntrackd/VRF/ip-rule unit or kernel objects added by core installer.
- **TRAFFIC GENERATOR:** No traffic needed; baseline flow continues.
- **EXPECTED RUNTIME:** Explicit schema/capability rejection; existing M2 session authority unchanged.
- **EXPECTED PACKETS:** No state sync/VRF change occurs.
- **EVIDENCE:** C0 plus Rejection bodies and kernel/config diff.
- **CLEANUP:** Restore Candidate.
- **PASS:** Negative boundary only; never labelled a conntrack state-HA acceptance.
- **FAIL:** Unsupported field silently accepted, conntrackd started, seamless HA claimed. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

### A32 — Disable, cleanup and paired downgrade

- **TOPOLOGY:** G1/G2 and original lab.
- **INITIAL CONFIG:** All core enabled features exercised, then disabled and omitted subtree.
- **EXACT COMMANDS/API ACTIONS:**
  1. Commit disabled M5 and verify its daemon resources stopped/removed; preserve ordinary static routes and claims correctly.
  2. Commit config with network_services omitted; repeat ordinary no-M5 commit if previous snapshot still contains M5.
  3. Verify both journals absent; stop dedicated services; restore prior paired engine/API/UI and installer manifest on clone.
  4. Reboot old pair; run legacy verifier and MGMT/API/NAT smoke case.
- **TRAFFIC GENERATOR:** Baseline LAN/MGMT flows and denied WAN probe.
- **EXPECTED RUNTIME:** No M5 listener/VIP/guard/owned lease or active external route service left; both Running and previous schema old-compatible; old build loads normally.
- **EXPECTED PACKETS:** Legacy allowed/denied/NAT behavior returns to exact baseline; no orphan VIP hijack.
- **EVIDENCE:** C0 plus Disabled cleanup receipts, old/new hashes, previous snapshot semantic check, reboot unit/cap proof.
- **CLEANUP:** Return clone to intended release; original baseline retained; C0.
- **PASS:** Complete resource release and usable old pair; no forced state deletion.
- **FAIL:** Old binary launched over active M5 journal/subtree, orphan daemon writes, global route/nft flush. Missing prerequisite/evidence is BLOCKED/NOT_RUN, not PASS.

## Deterministic failure injection contract

The lab fault profile points fixed ToolIDs at a root-owned argv-compatible wrapper
which ultimately invokes the real pinned tool. Only the disposable test unit uses
`NGFW_M5_PROFILE=/etc/ngfw/m5-lab/profile.json`; ordinary production profile has
no wrapper and no network/API fault control. Profile/hash still validated. The
adapter Command.Phase is a fixed enum propagated as NGFW_M5_PHASE for command
correlation; it is never Candidate text. One-shot markers select tool+phase,
expected generation, action FAIL/SLEEP/BLOCK_AFTER_REAL_SUCCESS and expiry.
Wrapper records actual underlying exit status before a barrier marker is made.
Harness waits <=10s for the exact barrier; a missed barrier is BLOCKED.

W1 uses the first reservation guard command after WAL fsync; W2 the first external
apply command after the legacy inner apply; W3 final external verification before
return to Manager; W4 the first finalization verification command after Running
publication. Before killing, harness proves both marker and corresponding durable
file digest/phase. W5 blocks reverse compensation. The wrapper cannot fake packet
or status success; all verdicts are collected from real daemons/kernel after it
is removed. Production code contains no 'skip validation', 'pretend success' or
remote fault endpoint. A32 proves test profile/markers are absent after teardown.

A20 invalid-native-config test differs from A01 bad Candidate: a lab renderer
fixture deliberately yields syntax-invalid generated output at the adapter
boundary, so native validation is exercised. Similarly, A21 distinguishes syntax
failure, apply/reload failure, worker verification failure and backend DOWN. Each
must have its own assertion; they cannot share one generic 'error returned' PASS.

## Acceptance evidence layout and release rule

```text
artifacts/m5-acceptance-<UTC>/
  RESULTS.md                  # per-case actual verdict, dates, limitations
  source-manifest.json        # HEAD, dirty-file hashes, binaries
  profile-manifest.json       # OS/kernel/package/schema/capability proofs
  Axx/<node>/before|during|after/
  Axx/commands.log            # exact commands, times, exit codes; no auth values
  Axx/assertions.json         # expected, observed, supporting raw file
  Axx/cleanup-verification.json
  SHA256SUMS.txt
```

Core completion requires A00–A29 and A32 PASS, directly affected package checks and
selected M1–M4 regression gates. A31 is a negative boundary check and remains
mandatory to keep unsupported fields rejected; it grants no feature acceptance.
A30 is separate OPTIONAL acceptance. Cases relying on a second gateway/router
remain BLOCKED until those VMs exist; no substitution with mocked unit output.
No daemon configuration-apply check alone proves adjacency, packet forwarding,
correct NAT, load distribution or HA role takeover.

## Planning checkpoint

FINDINGS: current four-zone lab needs R2, a shared destination network and G2 for
complete routed failover/VRRP evidence; existing M1 evidence cannot fill those gaps.
DECISIONS: separate new-flow and existing-session assertions, scoped faults and
structured evidence; no universal atomic/seamless-HA claim.
UNRESOLVED: actual NIC mappings, package profile and new VM availability at T00/T01;
these are future execution prerequisites, not tests performed in this phase.
FILES ALREADY INSPECTED: API.configView/candidate/commit/rollback envelopes and
existing matrix/evidence metadata; all new harness files are in the file plan.
SOURCES ALREADY INSPECTED: SOURCE_NOTES selected upstream contracts.
NEXT TARGETS: a coding agent implements harness and runs cases only after instructed.
