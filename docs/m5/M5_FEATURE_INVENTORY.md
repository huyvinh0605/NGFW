# M5 feature inventory and scope

References V/F/H/K/L/C resolve to the URL **and section** in [SOURCE_NOTES](SOURCE_NOTES.md).
Priority P0 is a safety/foundation dependency, P1 core feature, P2 optional,
P3 future. Complexity L/M/H is relative to this repository. Lab feasibility
means a proposed test topology, never a result already obtained.

| Feature / evaluated controls | Classification | User value | VyOS ref | Upstream / why | Integration point | Security impact | Failure impact | Complexity | VM feasibility | Priority |
|---|---|---|---|---|---|---|---|---|---|---|
| Static routes/gateway/interface/metric | REQUIRED_FOR_M5 (preserve) | Preserve accepted routing | V01 | Existing M1 iproute2; already implemented | NetworkOwnership extension | Provenance collision guard | No foreign cleanup | M | Existing 5-node lab | P0 |
| OSPFv2 router ID, area, explicit interfaces/networks, passive, cost | REQUIRED_FOR_M5 | Learn internal routes | V02 | FRR ospfd/zebra F05; mature protocol | routing/frr | Explicit participating interfaces/import prefix boundary | Adjacency/route withdrawal | M | NGFW + wan FRR peer | P1 |
| OSPF timers, MD5 reference, conditional default originate | REQUIRED_FOR_M5 | Controlled adjacencies/export | V02 | FRR F05 | OSPF renderer + secret resolver | No plaintext key in Config; no always-default | Timer mismatch/auth causes DOWN | M | Peer matching/mismatch cases | P1 |
| OSPF network statements | REQUIRED_FOR_M5 (behavior via explicit interfaces) | Predictable area membership | V02 | FRR interface `ip ospf area` | Validator resolves interface IDs and assigned addresses | Avoid broad subnet matching that enables MGMT | Missing interface rejected | L | Inspect enabled interfaces | P1 |
| OSPFv3 / IPv6 equivalent | FUTURE | Dual-stack dynamic routing | V02 | FRR ospf6d | No v1 fields | M1 firewall acceptance is IPv4; do not open unfiltered IPv6 | Dual-stack asymmetry | H | Separate IPv6 regression lab needed | P3 |
| BGP ASN/router ID/numbered single-hop peers/update source/shutdown | REQUIRED_FOR_M5 | Inter-router routing | V03 | FRR bgpd F06 | BGP renderer | Bound source/interface and authenticated peer option | Peer reset withdraws routes | M | NGFW + two AS peers | P1 |
| BGP IPv4 AF/networks/conditional default advertisement | REQUIRED_FOR_M5 | Publish explicit networks | V03 | FRR F06 | BGPAddressFamily | Network must be authorized and present; bounded exports | Missing backing route not advertised | M | RIB + peer capture | P1 |
| BGP IPv6 AF, unnumbered, multihop, route reflectors | FUTURE | Larger topologies | V03 | FRR | No v1 fields | Requires more source/TTL/family policy | New failure modes | H | Beyond baseline | P3 |
| BGP prefix filters, route maps, local preference, MED, local-AS prepend | REQUIRED_FOR_M5 | Route selection and export control | V03/V05/V06 | FRR F06/F08 | routingpolicy | Explicit permit lists, final deny, prefix limits | Wrong policy can withdraw traffic | M | Filter/attribute readback | P1 |
| Redistribution CONNECTED/M1_STATIC and one-way OSPF↔BGP | REQUIRED_FOR_M5 | Join routing domains | V02/V03/V06 | FRR with adapter-generated ownership filters | routingpolicy + FRR | No MGMT/VIP/foreign kernel export; loops rejected | Route leak risk bounded by allowlists | M | Exact permitted/denied test prefixes | P1 |
| Community lists, arbitrary route-map calls/regex, RPKI/full Internet table | REJECTED_FOR_SCOPE | Large provider routing, not current KLTN | V03/V06 | FRR can do it | None | Large trust/validation/memory surface | Resource exhaustion | H | Not suitable baseline | P3 |
| BFD peers/profile timers/multiplier/status; BGP and OSPF binding | REQUIRED_FOR_M5 | Faster fault detection | V04 | FRR bfdd F07 | routing BFD model | No second BFD daemon; timers bounded | False failure under CPU pressure | M | Protocol failure plus CPU observation | P1 |
| BFD echo/multihop | FUTURE | Specialized detection | V04 | FRR | No v1 fields | More ports/source validation | Harder timing guarantees | M | Extra topology | P3 |
| ECMP/maximum paths | REQUIRED_FOR_M5 | Multiple equal routes | V03 | FRR + Linux L01/L04 | BGP/OSPF max_paths | Same zone, no overlapping NAT in multi-link use | Rehash after route change | M | Two peers, many distinct flows | P1 |
| PBR/ip rule/multiple tables | FUTURE | Source/application path policies | V07 | Linux RPDB L02 | Future routingpolicy/kernel adapter | Requires table ownership and mark contract | Wrong rule can trap MGMT | H | Separate RPDB safety acceptance | P3 |
| VRF create/delete/table/interface/member routes/protocol instances/status | FUTURE | Tenant routing isolation | V08 | Linux VRF + FRR L03 | Future vrf adapter | Requires M2 namespace/ct-zone and M3/M4 socket scope design | Enslaving can delete dependent routes | H | Needs isolated tenant lab | P3 |
| VRF unique table/name and conflicting membership validation | FUTURE | Prevent tenant collisions | V08 | Linux/FRR | Not accepted by v1 decoder | Exact scoped resources required | Reject before enslaving | M | Future lifecycle suite | P3 |
| Routed WAN primary/backup and route recovery | REQUIRED_FOR_M5 | Demonstrate uplink failover | V09 | FRR attributes+BFD; architecture C | WAN facade + FRR | No independent writer or mark use | Existing TCP may fail | M | Second WAN NIC + peer | P1 |
| Routed WAN equal-cost per-flow distribution/status/counters | REQUIRED_FOR_M5 | Demonstrate multi-link use | V09 | Linux FIB hashing L04 | WANObserver | Record hash/rp_filter; same return-reachable source | No per-flow permanence across changes | M | Distinct flows + both captures | P1 |
| Read-only source-bound TCP route-health probe | REQUIRED_FOR_M5 | Diagnose beyond neighbor | V09 | Go TCP socket, Linux binding; no protocol reimplementation | wan/health | Endpoint allowlist/no arbitrary shell; observation only | Timeout yields UNKNOWN/DOWN | L | Controlled responder | P1 |
| Weighted WAN per-flow selection, sticky ISP SNAT, independent failover engine | FUTURE | Dual-ISP Internet access | V09 | Kernel RPDB/conntrack needs a separate proven design | No v1 mode | M2 mark low byte is not free; return/NAT mapping ownership unresolved for this scope | Existing TCP cannot just migrate | H | More acceptance than routed ECMP | P3 |
| HAProxy TCP/HTTP pools, maxconn, logging, timeouts | REQUIRED_FOR_M5 | Publish resilient applications | V10 | HAProxy H01/H02; native delivery | loadbalancer/haproxy | Engine local-service admission; DELIVERY_ONLY | Active streams may close on process loss | M | dmz two backend addresses | P1 |
| Round-robin/leastconn/source hash and server weights | REQUIRED_FOR_M5 | Match workload distribution | V10 | Native HAProxy algorithms | Backend model | No custom scheduler | Hash remap when pool changes | M | Response identity and long-lived flows | P1 |
| TCP/HTTP check/URI/status/rise/fall | REQUIRED_FOR_M5 | Remove unhealthy backend | V10 | HAProxy health | HealthCheck model | Fixed bounded targets | All DOWN -> clear unavailable status | L | Stop/restart backend | P1 |
| Host/SNI/path-prefix routing; same-host HTTPS redirect | REQUIRED_FOR_M5 | Virtual hosting | V10 | HAProxy typed ACL renderer | Service rules | No freeform ACL/script or open redirects | Wrong rule selects wrong backend | M | Host/SNI/path cases | P1 |
| TLS termination/verified backend TLS/cert references | REQUIRED_FOR_M5 | Encrypted delivery | V10 | HAProxy TLS | SecretRef + TLS model | Verify required; no shared M4 CA authority | Bad cert/CA rejects activation or backend health | M | Lab CA/SAN/expiry cases | P1 |
| Proxy Protocol OFF/V1/V2 | REQUIRED_FOR_M5 | Backend sees client metadata when supported | V10 | HAProxy | Per-server option | Explicit backend capability acknowledgement | Unsupported backend rejects traffic | L | Dedicated echo backend | P1 |
| HAProxy plus M4 same path; wildcard binds; insecure backend TLS | REJECTED_FOR_SCOPE | Unsafe without additional contracts | V10 | No core implementation | Cross-validator | Prevent request-gate bypass and listener ambiguity | Rejected before mutation | H | Negative Candidate tests | P0 |
| VRRP groups/VIP/priority/preemption/delay/advert/unicast | REQUIRED_FOR_M5 | Router redundancy | V11 | Keepalived K01/K02 | ha/keepalived | VIP sole writer, fixed MGMT remains | Failover disrupts unsynchronized state | M | Requires second NGFW VM | P1 |
| Track interfaces/readiness, sync groups, transition status | REQUIRED_FOR_M5 | Failover on appliance failure | V11 | Keepalived fixed helper/FIFO/JSON | HA lease + status | No arbitrary scripts; expired lease -> FAULT | Conservative withdrawal | M | Stop engine and break NIC | P1 |
| VRRP config replication/quorum/seamless application HA | REJECTED_FOR_SCOPE | Cluster-wide management | V11 | Not provided by VRRP | None | No claim of split-brain prevention | Partitions can yield dual MASTER | H | Fault demonstration only | P3 |
| IPVS TCP/UDP virtual/real servers, NAT, RR/WRR/LC/SH, persistence/health | OPTIONAL_M5 | Kernel L4 services and UDP use | V11 | Linux IPVS via checker-only Keepalived | loadbalancer/ipvs | Exclusive tuple; no fwmark mode; no M4 overlap | Per-connection state can be lost | M/H | Optional T31–T33 | P2 |
| IPVS direct routing/tunneling | FUTURE | High throughput/asymmetric delivery | V11 | Linux IPVS | No v1 optional fields | ARP/backend return path and inspection bypass concerns | Asymmetric failure | H | Dedicated backend networking | P3 |
| conntrackd transport/cache/startup resync/event loss/NAT state | FUTURE | Stateful active-backup firewall | V12 | conntrackd C01 | ConntrackSyncBackend seam only | Imported marks/epoch/identity require explicit invalidation barriers | Stale/lost state possible | H | Mark-collision and live stream acceptance first | P3 |
| IS-IS, multicast PIM, EVPN/VXLAN, VPN/QoS/DHCP/DNS | REJECTED_FOR_SCOPE | Separate appliance milestones | Outside selected reference sections | Mature tools exist, not core M5 | None | Avoid unbounded expansion | Unrelated failure surfaces | H | Separate plans | P3 |

IPVS forwards L4 traffic in kernel and is appropriate for optional UDP/high-volume
virtual services. HAProxy is the selected core tool for HTTP host/path routing,
TLS termination and application backend checks. They are not interchangeable
and may not own the same listener tuple.

Scope checkpoint: FINDINGS — selected tools cover the coherent subset. DECISIONS —
classification above is normative. UNRESOLVED — VM capability gates only. FILES
ALREADY INSPECTED — architecture map. SOURCES ALREADY INSPECTED — V01–P01 ledger.
NEXT TARGETS — implementable contracts for core and explicitly gated IPVS only.
