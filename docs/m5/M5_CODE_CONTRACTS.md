# M5 code contracts

All new symbols in this document are **PROPOSED NEW**. Existing symbols to MODIFY
are explicitly identified in the file plan. This is a specification, not Go
implementation. Module import prefix remains `github.com/kltngfw/ngfw`.

## 1. Configuration envelope and common rules

MODIFY `domain.Config`: append `NetworkServices *NetworkServicesConfig
json:"network_services,omitempty"`. Do not change existing Route/Interface JSON.
Nil remains nil on load/export; no automatic schema migration or default injection
into an old Running checksum. Effective defaults are applied to a cloned planning
view, never to Running. Disabled nested sections may retain structurally valid
settings, but cause no steady-state runtime effects.

PROPOSED files: `internal/domain/network_services.go`, `routing.go`,
`loadbalancer.go`, `ha.go`, `network_services_status.go`; optional `ipvs.go` at T31.
All identifiers: existing identifier rules plus ASCII `[A-Za-z0-9_-]{1,48}`;
reserved `ngfw_`/`NGFW_` namespaces forbidden to users. No newlines, NUL, arbitrary
paths or vendor command fragments. Addresses/CIDRs are parsed with `net/netip`;
prefixes canonicalized in effective plans; duplicate normalized keys rejected.
Config arrays have explicit count limits. Strings are UTF-8 and descriptions are
<=256 bytes. SecretRef is an opaque `name@version` identifier, never a path/value.

`NetworkServicesConfig.UnmarshalJSON([]byte) error` uses an alias type and a
bounded strict decoder with `DisallowUnknownFields`; exactly one JSON value,
no trailing input. This applies recursively to its nested DTOs, so unsupported
VRF/IPv6/weighted/PBR fields cannot be silently discarded by ordinary Go JSON.
`CloneNetworkServices(*NetworkServicesConfig) *NetworkServicesConfig` deep-copies
all pointers/maps/slices. Nil in -> nil out. Config manager and activation snapshot
clone boundaries must retain that isolation.

Notation in tables: R required when section enabled; O optional; `0→N` means
effective default N, without changing stored JSON. Enum values are exact strings.
Runtime meaning follows the validation column; unspecified fields are not accepted.

### NetworkServicesConfig (`network_services.go`)

| Go field | Go type / JSON | Required/default | Validation / runtime meaning |
|---|---|---|---|
| Schema | uint16 / `schema` | R, 1 | Only schema1; optional IPVS adds a negotiated capability, not a silent fallback. |
| Enabled | bool / `enabled` | O false | Root feature switch. |
| Routing | *RoutingConfig / `routing,omitempty` | O nil | Dynamic routing intent. |
| WAN | *WANMultiLinkConfig / `wan,omitempty` | O nil | FRR path/status facade; enabled routing required. |
| LoadBalancer | *HAProxyConfig / `load_balancer,omitempty` | O nil | Application delivery. |
| HA | *VRRPConfig / `ha,omitempty` | O nil | VIP redundancy. |
| IPVS | *IPVSConfig / `ipvs,omitempty` | OPTIONAL T31 only | Not added/accepted in core build; capability `ipvs_nat_v1` required. |

### RoutingConfig, OSPFConfig, OSPFInterface (`routing.go`)

| Type.field | Go type / JSON | Required/default | Validation / meaning |
|---|---|---|---|
| RoutingConfig.Enabled | bool / `enabled` | O false | FRR lifecycle switch. |
| RouterID | string / `router_id` | R | Nonzero unicast IPv4-format router ID, shared by OSPF/BGP; independent of interface ownership. |
| ZoneID | string / `zone_id` | R | Existing non-MGMT zone; every active dynamic next-hop interface belongs to it. |
| ReachablePrefixes | []string / `reachable_prefixes` | R 1..256 | IPv4 remote prefixes allowed for FIB/zone attribution; reject MGMT/local/contradictory-zone overlap. `/0` requires explicit presence and exclusion guards for protected prefixes. |
| OSPF | *OSPFConfig / `ospf,omitempty` | O nil | One default-VRF OSPFv2 process. |
| BGP | *BGPConfig / `bgp,omitempty` | O nil | One default-VRF BGP process. |
| BFD | BFDConfig / `bfd` | O disabled | FRR BFD only. |
| Policy | RoutePolicy / `policy` | O empty | Routing policy, separate from security policy. |
| OSPFConfig.Enabled | bool / `enabled` | O false | Must have >=1 active non-passive interface when enabled. |
| Interfaces | []OSPFInterface / `interfaces` | R 1..32 | Unique InterfaceID. |
| MaxPaths | uint8 / `max_paths` | O 0→1 | 1..8; >1 subject to same-zone/NAT validation. |
| DefaultOriginate | bool / `default_originate` | O false | Conditional on a valid local default route; never render `always`. |
| DefaultRouteMap | string / `default_route_map,omitempty` | R iff originate | Existing route map; only authorized default export. |
| Redistribute | []Redistribution / `redistribute` | O [] | <=3; sources CONNECTED/M1_STATIC/BGP; no duplicate source. |
| OSPFInterface.InterfaceID | string / `interface_id` | R | Existing administratively UP L3/VLAN interface with IPv4; MGMT and parent-only VLAN rejected. |
| Area | string / `area` | R | Canonical dotted-quad 32-bit area ID; core area0 or ordinary non-backbone, no NSSA/stub settings. |
| Passive | *bool / `passive,omitempty` | O true | Nil is passive; explicit false enables adjacency. |
| NetworkType | string / `network_type` | O BROADCAST | BROADCAST or POINT_TO_POINT. |
| Cost | uint16 / `cost` | O 0→10 | 1..65535. |
| HelloSeconds | uint16 / `hello_seconds` | O 0→10 | 1..60. |
| DeadSeconds | uint16 / `dead_seconds` | O 0→40 | <=240 and >=3*hello; effective defaults must satisfy relation. |
| AuthSecretRef | string / `auth_secret_ref,omitempty` | O empty | Versioned MD5 key reference; resolved key 1..16 bytes; no cleartext auth mode. |
| AuthKeyID | uint8 / `auth_key_id,omitempty` | R iff auth | 1..255; zero without auth. |
| BFDProfileID | string / `bfd_profile_id,omitempty` | O empty | Existing BFD profile, BFD enabled, non-passive interface. |

Network-style OSPF selection is deliberately represented by explicit interfaces;
the adapter emits `ip ospf area`, avoiding ambiguous subnet-to-interface expansion.
OSPFv3 is evaluated but has **no accepted v1 config structure**.

### BGPConfig, BGPNeighbor, BGPAddressFamily, BFD and redistribution

| Type.field | Go type / JSON | Required/default | Validation / meaning |
|---|---|---|---|
| BGPConfig.Enabled | bool / `enabled` | O false | Requires ASN and neighbors. |
| LocalASN | uint32 / `local_asn` | R | 1..4294967294; zero/reserved max rejected. |
| Neighbors | []BGPNeighbor / `neighbors` | R 1..32 | Unique ID and address/source/interface key. |
| Networks | []string / `networks` | O [] <=256 | IPv4 canonical exact local connected or enabled M1 static prefixes; no unconditional route injection. |
| MaxPaths | uint8 / `max_paths` | O 0→1 | 1..8; equal-eligible FRR paths, not arbitrary weights. |
| Redistribute | []Redistribution / `redistribute` | O [] | CONNECTED/M1_STATIC/OSPF; reject simultaneous OSPF→BGP and BGP→OSPF in core. |
| BGPNeighbor.ID | string / `id` | R | Stable API identifier, separate from address. |
| Address | string / `address` | R | Unicast IPv4 single-hop peer in InterfaceID connected prefix. |
| RemoteASN | uint32 / `remote_asn` | R | Same ASN bounds; iBGP/eBGP inferred. |
| InterfaceID | string / `interface_id` | R | Existing UP IPv4 interface in routing zone. |
| UpdateSource | string / `update_source` | R | Ordinary assigned local IPv4 on that interface; not VIP. |
| Shutdown | bool / `shutdown` | O false | Administrative peer disable. |
| AuthSecretRef | string / `auth_secret_ref,omitempty` | O empty | TCP-MD5 reference; resolved 1..80 bytes, no control chars. |
| BFDProfileID | string / `bfd_profile_id,omitempty` | O empty | Existing enabled BFD profile. |
| AF | BGPAddressFamily / `address_family` | R | Exactly one AF in core. |
| BGPAddressFamily.Family | string / `family` | R IPV4_UNICAST | Other families rejected. |
| ImportRouteMap | string / `import_route_map` | R | Existing map; generated ownership/reachable-prefix guard also applies. |
| ExportRouteMap | string / `export_route_map` | R | Existing map; export only explicit authorized local/redistributed prefixes. |
| MaximumPrefixes | uint32 / `maximum_prefixes` | O 0→256 | 1..4096; configured table-wide cap4096. |
| DefaultOriginate | bool / `default_originate` | O false | Conditional default advertisement only. |
| DefaultRouteMap | string / `default_route_map,omitempty` | R iff originate | Explicit route condition/map; no unconditional always. |
| RetainReceivedRoutes | bool / `retain_received_routes` | O false | Enables bounded inbound soft-reconfiguration for pre-policy status; cap<=1024 when true. |
| Redistribution.Source | string / `source` | R | Enum above; M1_STATIC maps to exact filtered kernel-origin routes, never FRR staticd. |
| RouteMapID | string / `route_map_id` | R | Existing source-compatible map; protected prefixes always excluded. |
| BFDConfig.Enabled | bool / `enabled` | O false | No Keepalived BFD. |
| Profiles | []BFDProfile / `profiles` | O [] <=16 | Required for references. |
| Peers | []BFDPeer / `peers` | O [] <=128 | Standalone monitored peers; protocol-created peers de-duplicated by endpoint key. |
| BFDProfile.ID | string / `id` | R | Unique. |
| TransmitMS | uint32 / `transmit_ms` | O 0→300 | 100..60000. |
| ReceiveMS | uint32 / `receive_ms` | O 0→300 | 100..60000. |
| Multiplier | uint8 / `multiplier` | O 0→3 | 2..50; do not promise exact detection time under scheduling load. |
| BFDPeer.ID | string / `id` | R | Unique. |
| Address | string / `address` | R | Single-hop IPv4 remote. |
| LocalAddress | string / `local_address` | R | Ordinary assigned source. |
| InterfaceID | string / `interface_id` | R | Same-zone peer interface. |
| ProfileID | string / `profile_id` | R | Existing profile. |

### RoutePolicy, PrefixList and RouteMap (`routing.go`)

| Type.field | Go type / JSON | Required/default | Validation / meaning |
|---|---|---|---|
| RoutePolicy.PrefixLists | []PrefixList / `prefix_lists` | O [] <=64 | Unique IDs. |
| RouteMaps | []RouteMap / `route_maps` | O [] <=64 | Unique IDs, no arbitrary command bodies. |
| PrefixList.ID | string / `id` | R | Normal identifier. |
| Entries | []PrefixListEntry / `entries` | R 1..128 | Unique ascending Sequence in effective plan. |
| PrefixListEntry.Sequence | uint32 / `sequence` | R | 1..65535. |
| Action | string / `action` | R | PERMIT or DENY. |
| Prefix | string / `prefix` | R | IPv4 CIDR. |
| MinLength | *uint8 / `min_length,omitempty` | O nil | PrefixLen<=min<=max<=32; nil/nil means exact. |
| MaxLength | *uint8 / `max_length,omitempty` | O nil | Missing partner uses explicit defined range: min absent -> prefix length; max absent with min ->32. |
| RouteMap.ID | string / `id` | R | Normal identifier. |
| Entries | []RouteMapEntry / `entries` | R 1..128 | Unique ascending sequence; implicit final deny. |
| RouteMapEntry.Sequence | uint32 / `sequence` | R | 1..65535. |
| Action | string / `action` | R | PERMIT or DENY. |
| PrefixListID | string / `prefix_list_id,omitempty` | R for PERMIT | Existing list; empty only allowed for final explicit DENY. |
| LocalPreference | *uint32 / `local_preference,omitempty` | O nil | BGP import only; 0..4294967295. |
| MED | *uint32 / `med,omitempty` | O nil | BGP only. |
| PrependLocalAS | uint8 / `prepend_local_as,omitempty` | O0 | BGP export only, 0..3 repeats of configured local ASN. |

No setters on DENY entries; no route-map recursion, community/raw AS regex or
policy name resolution against SecurityPolicy. Adapter intersects user maps with
generated protected-prefix guards; concatenating two independently permissive
route-map bodies is forbidden.

### WANMultiLinkConfig, WANPath, WANHealthCheck (`routing.go`)

| Type.field | Go type / JSON | Required/default | Validation / meaning |
|---|---|---|---|
| WANMultiLinkConfig.Enabled | bool / `enabled` | O false | Requires active BGP and >=2 paths. |
| Mode | string / `mode` | R | FRR_FAILOVER or FRR_ECMP only. |
| Paths | []WANPath / `paths` | R 2..4 | Unique interface/neighbor; same routing zone. |
| Prefixes | []string / `prefixes` | R 1..32 | Subset of Routing.ReachablePrefixes; no conflicting M1 route or overlapping NAT. |
| HealthChecks | []WANHealthCheck / `health_checks` | O [] <=4 | Observation only. |
| WANPath.ID | string / `id` | R | Stable status key. |
| InterfaceID | string / `interface_id` | R | References BGP peer's interface. |
| NeighborID | string / `neighbor_id` | R | Enabled peer with BFD; route preferences live in route maps. |
| WANHealthCheck.PathID | string / `path_id` | R | Existing WAN path. |
| Address | string / `address` | R | IPv4 literal within monitored prefixes; no hostname/DNS side effects. |
| Port | uint16 / `port` | R | 1..65535; TCP connect probe. |
| IntervalMS | uint32 / `interval_ms` | O0→3000 | 1000..60000. |
| TimeoutMS | uint32 / `timeout_ms` | O0→1000 | 100..5000 and <interval. |
| Rise / Fall | uint8 / `rise`, `fall` | O0→2 / 0→3 | 1..10 consecutive results; bounded counters. |

Source IP is the peer UpdateSource; bind to its device and source address. Create
a fresh TCP socket per attempt and set SO_BINDTODEVICE once before connect; never
rebind a reused socket. Linux 6.8 permits the initial device binding without adding
NET_RAW (source L05). T01 must verify this under the actual engine unit. An EPERM
is a capability failure, never a fallback to an unbound probe or a privilege grant. Probe
results never program routes. No weight/sticky/NAT-migration knobs are accepted.
VRFConfig and generic PBR structures are deliberately absent from this core schema.

### HAProxyConfig and service/backend data (`loadbalancer.go`)

| Type.field | Go type / JSON | Required/default | Validation / meaning |
|---|---|---|---|
| HAProxyConfig.Enabled | bool / `enabled` | O false | DELIVERY_ONLY; effective M4 prohibited. |
| MaxConnections | uint32 / `max_connections` | O0→2048 | 1..20000. |
| TLSMinVersion | string / `tls_min_version` | O TLS12 | TLS12 or TLS13; package fixed cipher profile MODERN. |
| LogLevel | string / `log_level` | O INFO | ERROR/WARNING/INFO; metadata only, no body/auth/query logs. |
| Timeouts | LBTimeouts / `timeouts` | O effective defaults | Millisecond values below. |
| Services | []HAProxyService / `services` | R 1..32 | Unique ID and concrete IPv4:TCP-port listener tuple. |
| Backends | []HAProxyBackend / `backends` | R 1..64 | Unique backend IDs. |
| LBTimeouts.ConnectMS | uint32 / `connect_ms` | O0→3000 | 100..60000. |
| ClientMS / ServerMS | uint32 / `client_ms`, `server_ms` | O0→30000 each | 1000..3600000. |
| CheckMS | uint32 / `check_ms` | O0→1000 | 100..10000. |
| HAProxyService.ID | string / `id` | R | Stable ID. |
| ListenAddress | string / `listen_address` | R | Existing ordinary M1 non-MGMT IPv4; no wildcard/VIP. |
| Port | uint16 / `port` | R | 1..65535, no API/M4/other listener/NAT tuple collision. |
| Mode | string / `mode` | R | TCP or HTTP. |
| TLSMode | string / `tls_mode` | O NONE | NONE/TERMINATE/PASSTHROUGH; PASSTHROUGH only TCP. |
| CertificateRef | string / `certificate_ref,omitempty` | R iff TERMINATE | Existing cert+key version; validate pair/expiry/SAN metadata. |
| BackendID | string / `backend_id` | R | Existing same-mode default backend. |
| Access | ServiceAccess / `access` | R | Explicit engine admission, never HAProxy security rules. |
| Rules | []ServiceRoute / `rules` | O [] <=64 | Ordered delivery rules only. |
| RedirectHTTPSServiceID | string / `redirect_https_service_id,omitempty` | O empty | HTTP+NONE to known HTTP+TERMINATE service, same host, no loops; fixed 308. |
| ClientTimeoutMS | uint32 / `client_timeout_ms,omitempty` | O0 inherit | Same bounds as global client timeout. |
| Log | bool / `log` | O false | Metadata log switch. |
| ServiceAccess.SourceZones | []string / `source_zones` | R nonempty | Existing zones; derived iif set. |
| SourceCIDRs | []string / `source_cidrs` | R 1..32 | IPv4 prefixes; explicit `0.0.0.0/0` required for all sources. |
| InspectionMode | string / `inspection_mode` | R DELIVERY_ONLY | No other value accepted in core. |
| ServiceRoute.Priority | uint16 / `priority` | R1..65535 | Unique within service; first matching delivery rule. |
| Host / SNI / PathPrefix | string / `host,omitempty`, `sni,omitempty`, `path_prefix,omitempty` | O empty | At least one selector. Host/SNI canonical exact DNS names<=253; path<=256 starts `/`, no control/query. HTTP host/path or TLS SNI appropriate to mode; no wildcard regex. All provided selectors AND. |
| BackendID | string / `backend_id` | R | Same-mode backend. |
| HAProxyBackend.ID | string / `id` | R | Unique. |
| Mode | string / `mode` | R | TCP/HTTP; matches referencing services. |
| Algorithm | string / `algorithm` | O ROUND_ROBIN | ROUND_ROBIN/LEAST_CONNECTIONS/SOURCE_HASH; vendor mapping isolated. |
| Servers | []HAProxyServer / `servers` | R1..32 | Unique endpoint and ID within backend. |
| Health | LBHealthCheck / `health` | R | Built-in TCP/HTTP check. |
| TLS | BackendTLS / `tls` | O disabled | Verification mandatory when enabled. |
| ConnectTimeoutMS / ServerTimeoutMS | uint32 / `connect_timeout_ms,omitempty`, `server_timeout_ms,omitempty` | O0 inherit | Same global bounds. |
| HAProxyServer.ID | string / `id` | R | Unique in backend. |
| Address | string / `address` | R | IPv4 literal; no API/MGMT/self-listener recursion. |
| Port | uint16 / `port` | R | 1..65535. |
| Weight | uint16 / `weight` | O0→1 | 1..256, HAProxy handles weighting. |
| MaxConnections | uint32 / `max_connections` | O0→1024 | 1..20000. |
| ProxyProtocol | string / `proxy_protocol` | O OFF | OFF/V1/V2; backend compatibility must be explicitly confirmed by field selection. |
| LBHealthCheck.Kind | string / `kind` | O TCP | TCP or HTTP; HTTP requires HTTP backend. |
| Port | uint16 / `port,omitempty` | O0 server port | Alternate check port within configured allowed backend endpoint. |
| URI | string / `uri,omitempty` | O `/health` for HTTP | <=256, local path only, no secrets/query. |
| ExpectedStatus | uint16 / `expected_status,omitempty` | O0→200 HTTP | 100..599, unused for TCP. |
| IntervalMS | uint32 / `interval_ms` | O0→2000 | 500..60000, >CheckMS. |
| Rise / Fall | uint8 / `rise`, `fall` | O0→2 / 0→3 | 1..10. |
| BackendTLS.Enabled | bool / `enabled` | O false | Re-encryption supported. |
| CARef | string / `ca_ref,omitempty` | R iff TLS | Trust-bundle secret reference. |
| ServerName | string / `server_name,omitempty` | R iff TLS | DNS identity for SNI and certificate verification; cannot disable verification. |

### VRRPConfig / VRRPGroup (`ha.go`)

| Type.field | Go type / JSON | Required/default | Validation / meaning |
|---|---|---|---|
| VRRPConfig.Enabled | bool / `enabled` | O false | Core IPv4 VRRPv3, unicast, initial BACKUP. |
| Groups | []VRRPGroup / `groups` | R1..8 | Unique ID and `(interface,VRID,family)` pair. |
| SyncGroups | []VRRPSyncGroup / `sync_groups` | O[] <=4 | Related groups fail over together. |
| VRRPGroup.ID | string / `id` | R | Stable instance name. |
| InterfaceID | string / `interface_id` | R | Existing UP ordinary L3/VLAN interface, never MGMT/parent-only. |
| VRID | uint8 / `vrid` | R1..255 | Zero invalid. |
| Addresses | []string / `addresses` | R1..8 | IPv4 CIDRs in connected subnet, distinct from all ordinary addresses/foreign live owners. |
| LocalAddress | string / `local_address` | R | Ordinary local IPv4 source on interface. |
| Peers | []string / `peers` | R1..3 | Distinct nonlocal IPv4 sources in same connected subnet. |
| Priority | uint8 / `priority` | O0→100 | 1..254; owner255 excluded. |
| Preempt | bool / `preempt` | O false | false renders nopreempt. |
| PreemptDelaySeconds | uint16 / `preempt_delay_seconds` | O0 | 0..1000; nonzero requires Preempt. |
| AdvertSeconds | uint8 / `advert_seconds` | O0→1 | 1..10. |
| TrackInterfaces | []string / `track_interfaces` | O[] | Existing IDs, no scripts; group interface always tracked. |
| TrackSubsystems | []string / `track_subsystems` | O[] | ENGINE always implicit; FRR/HAPROXY only if corresponding feature enabled. |
| VRRPSyncGroup.ID | string / `id` | R | Unique. |
| Members | []string / `members` | R2..8 | Existing groups, no duplicate membership; compatible preemption/advert/health settings. |

No VRRP password field: core VRRPv3 profile has no shared-password security claim.
Peer allowlists protect protocol admission; network isolation remains necessary.

### Optional IPVS v1 (`ipvs.go`, not implemented in core tasks)

| Type.field | Go type / JSON | Default / constraint |
|---|---|---|
| IPVSConfig.Enabled | bool / `enabled` | false; capability `ipvs_nat_v1` required |
| VirtualServers | []VirtualServer / `virtual_servers` | 1..16 when enabled |
| VirtualServer.ID | string / `id` | required identifier |
| Address / Port / Protocol | string,uint16,string / `address`,`port`,`protocol` | Explicit owned ordinary/VIP IPv4; port1..65535; TCP/UDP |
| VIPGroupID | string / `vip_group_id,omitempty` | required if address is VRRP VIP |
| Algorithm | string / `algorithm` | RR/WRR/LC/SH; default RR |
| ForwardMode | string / `forward_mode` | NAT only; DR/TUN rejected |
| PersistenceSeconds | uint16 / `persistence_seconds` | 0 disabled; <=3600 |
| DelaySeconds | uint8 / `delay_seconds` | 0→2; 1..30 |
| RealServers | []RealServer / `real_servers` | 1..16, unique ID/address/port |
| RealServer.ID / Address / Port | string,string,uint16 / `id`,`address`,`port` | Required ID, IPv4, port1..65535 |
| Weight | uint16 / `weight` | 0→1;1..256 |
| CheckPort | uint16 / `check_port` | 0 means target port; TCP connect health, including explicit TCP health port for UDP service |

Require backend return via active gateway for NAT mode. Reject M4 use, overlapping
HAProxy/DNAT listeners and IPVS fwmark mode. Keepalived checker-only instance is
the writer; the IPVS adapter must not also directly program the same entries.

## 2. Core and adapter Go signatures

All interfaces are SENTINEL-owned. `Apply` is idempotent for generation+digest;
`Verify` proves desired config installed, not external peer/backend availability.
The type `Prepared` contains artifact references/hashes, never plaintext secrets.
Adapters receive immutable copies. **No adapter may persist Running.**

```go
// internal/networkservices/contracts.go
type Generation uint64
type ArtifactRef struct { RelativePath, SHA256 string; Size int64 }
type Prepared struct { Subsystem, Digest string; Generation Generation; Artifacts []ArtifactRef }
type Snapshot struct { Subsystem, Digest string; Generation Generation; Artifacts []ArtifactRef; WasEnabled bool }
type ApplyReceipt struct { Subsystem, Digest string; Generation Generation; Changed bool }
type BackendStatus struct { Configured, Reachable, Applied, Operational bool; Generation Generation; ObservedAt time.Time; Reason string }
type AdapterError struct { Subsystem, Phase, Code string; Retryable bool; Cause error }

// internal/routing/backend.go
type RoutingBackend interface {
    Prepare(context.Context, domain.Config, Generation) (Prepared, error)
    Snapshot(context.Context) (Snapshot, error)
    Reserve(context.Context, []resources.RouteClaim) error
    Apply(context.Context, Prepared) (ApplyReceipt, error)
    Verify(context.Context, Prepared) error
    Restore(context.Context, Snapshot) error
    Status(context.Context, domain.RoutingQuery) (domain.RoutingStatus, error)
}
// internal/loadbalancer/backend.go
type LoadBalancerBackend interface {
    Prepare(context.Context, domain.Config, Generation) (Prepared, error)
    Snapshot(context.Context) (Snapshot, error)
    Apply(context.Context, Prepared) (ApplyReceipt, error)
    Verify(context.Context, Prepared) error
    Restore(context.Context, Snapshot) error
    Status(context.Context) (domain.LoadBalancerStatus, error)
}
// internal/ha/backend.go
type HABackend interface {
    Prepare(context.Context, domain.Config, Generation) (Prepared, error)
    Snapshot(context.Context) (Snapshot, error)
    Apply(context.Context, Prepared) (ApplyReceipt, error)
    Verify(context.Context, Prepared) error
    Restore(context.Context, Snapshot) error
    Status(context.Context) (domain.HAStatus, error)
}
// optional internal/loadbalancer/ipvs/backend.go
type VirtualServerBackend interface {
    Prepare(context.Context, domain.Config, Generation) (Prepared, error)
    Snapshot(context.Context) (Snapshot, error)
    Apply(context.Context, Prepared) (ApplyReceipt, error)
    Verify(context.Context, Prepared) error
    Restore(context.Context, Snapshot) error
    Status(context.Context) (domain.IPVSStatus, error)
}
// FUTURE seam only, not a core file or accepted config
type ConntrackSyncBackend interface {
    Validate(context.Context, SyncPlan) error
    Apply(context.Context, SyncPlan) error
    Status(context.Context) (SyncStatus, error)
    PrepareTakeover(context.Context, ImportBarrier) (ImportReceipt, error)
    Stop(context.Context) error
}
// internal/wan/backend.go -- read-only; no ApplyRoutes/SetMark method
type WANBackend interface {
    Observe(context.Context, domain.WANMultiLinkConfig) (domain.WANStatus, error)
}
// internal/netserviceexec/runner.go
type Command struct { Tool ToolID; Phase CommandPhase; Args []string; Stdin []byte; SecretOutput bool }
type Result struct { Stdout, Stderr []byte; ExitCode int; Truncated bool }
type Runner interface { Run(context.Context, Command) (Result, error) }
type ServiceManager interface {
    Inspect(context.Context, ServiceID) (ServiceState, error)
    Ensure(context.Context, ServiceID, ServiceAction) error
}
type SecretResolver interface { Resolve(context.Context, string, SecretPurpose) (SecretMaterial, error) }
```

Names `Generation`, `Prepared`, `Snapshot`, `ApplyReceipt` above are qualified
`networkservices.*` outside their defining package. To prevent an import cycle,
`networkservices/contracts.go` has no adapter/core imports. Artifact/WAL concrete
implementations live in `networkservices/state/`; only that state package imports
the existing dataplane ActivationSnapshot. The route guard implementation is
`networkservices/ownership/`, which may import dataplane; `resources/` stays a
leaf DTO/observer package and never imports dataplane or FRR. Move coordinator to
`internal/engine/network_services.go`; it imports the interfaces, not vice versa.
`resources.RouteClaim` is in a leaf package using domain DTOs only. Optional IPVS
interface should actually live in `internal/loadbalancer/virtualserver.go`, with
implementation in `ipvs/`; the seam shown above does not authorize vendor types
in callers. Future SyncPlan/ImportBarrier definitions require a later state-HA
spec and are not fabricated as current implementable data.

Adapter constructors are `NewFRRBackend(Options)`, `NewHAProxyBackend(Options)`,
`NewKeepalivedBackend(Options)` (and optional `NewIPVSBackend(Options)`). Each
Options holds Runner, ServiceManager, ArtifactStore, SecretResolver, KernelObserver,
Clock and a fixed installed Profile. No user-supplied executable path/command.
Constructors validate dependencies and return `(*Backend,error)`; they do no IO.

## 3. External execution profiles

| Adapter | Prepare/validate | Apply/reload | Structured status | Cleanup/compensation |
|---|---|---|---|---|
| FRR | Deterministic integrated config; `vtysh -C -f <staged>`; `frr-reload.py --test <staged>` only a bounded delta preview, secrets suppressed | Fixed `/usr/lib/frr/frr-reload.py --reload <staged>` profile using its pinned confdir/rundir; no `--overwrite` or `write memory`; verify actual daemon config has zero allowed delta | `show ip ospf neighbor/interface/route json`; `show bgp ipv4 unicast summary json`; bounded peer `routes`/`advertised-routes` JSON; `show bfd peers json`; `show ip route json` | Reload previous desired artifact; `Reserve` installs generated zebra prefix guard and waits for targeted kernel readback; no learned-route replay |
| HAProxy | `/usr/sbin/haproxy -c -f <staged>` + secret/socket checks | Publish journaled active artifact; fixed unit master-worker USR2 reload; verify new worker/socket/stats | Unix `show schema json`, `show info json`, `show stat json`; pinned field-name decoder | Previous artifact reload with closed admission; old worker drains within bound; active connections not recoverable |
| Keepalived | `/usr/sbin/keepalived --config-test -f <staged>`; every nonzero exit fails | Fixed unit reload after artifact publication; readiness false during changed groups | FIFO grammar `INSTANCE/GROUP "id" STATE priority`; JSON v2 snapshot via pinned `--signum=JSON` and PID-safe systemd signaling; verify VIP addresses | Previous config, no forced role. Remove only owned config/expired artifacts; Keepalived withdraws VIP |
| IPVS optional | Same syntax validator with checker-only config | Separate checker-only unit; exclusive virtual tuples | Generic-netlink IPVS observation through pinned adapter; no console scraping | Previous virtual-server desired config; do not restore saved live connection table |

Tool paths are package profile constants checked at T01, not portable guarantees.
FRR `--test` does not guarantee live semantic validity. Missing required command/
JSON fields returns `CAPABILITY_UNSUPPORTED`; no fallback to human table parsing.
Status decoders ignore additive unknown fields but reject missing required keys,
oversize/inconsistent values and stale records. Every command has a deadline and
bounded stdout/stderr; output truncation is failure, never partial success.

Keepalived JSON dump has a build-defined temporary location. T01 records that
location; a **service-only bind mount** maps it into `/run/ngfw-m5/keepalived/dump`,
visible to the engine without reading a world-writable `/tmp` file. Precreate the
file root-owned 0600; require a new mtime/inode-safe completed JSON parse after
signal. No `setns` or SYS_ADMIN in the engine. If this profile is unavailable,
Keepalived capability fails; do not guess state from a missing FIFO event.

## 4. Validators and transaction contracts

`config.ValidateNetworkServices(c domain.Config) []ValidationIssue` calls pure
validators `ValidateRouting`, `ValidateRoutePolicy`, `ValidateWAN`,
`ValidateLoadBalancer`, `ValidateHA`, optional `ValidateIPVS`, and
`ValidateResourceConflicts`. `ValidationIssue{Path,Code,Message string}` is formatted
into existing Validator.Validate string errors without changing legacy errors.
Pure validation never executes tools. Runtime `Coordinator.Prepare` rechecks
capabilities, installed secrets, foreign claims, active listeners and exact hash.

Mandatory error codes: `M5_SCHEMA_UNSUPPORTED`, `M5_FIELD_INVALID`,
`M5_REFERENCE_MISSING`, `M5_RESOURCE_CONFLICT`, `M5_M4_LB_CONFLICT`,
`M5_UNSUPPORTED_COMBINATION`, `M5_CAPABILITY_UNSUPPORTED`, `M5_SECRET_UNAVAILABLE`,
`M5_SYNTAX_REJECTED`, `M5_TOOL_UNAVAILABLE`, `M5_TIMEOUT`, `M5_OUTPUT_LIMIT`,
`M5_VERIFY_FAILED`, `M5_APPLY_FAILED`, `M5_COMPENSATION_FAILED`,
`M5_RECOVERY_REQUIRED`, `M5_STATUS_STALE`. Errors expose phase/subsystem/code and
sanitized message; raw config/secret stderr remains private or discarded.

Coordinator methods (PROPOSED in `internal/engine/network_services.go`):

```go
func NewNetworkServicesCoordinator(Deps) (*NetworkServicesCoordinator, error)
func (c *NetworkServicesCoordinator) Prepare(ctx context.Context, target domain.Config, generation uint64) error
func (c *NetworkServicesCoordinator) Apply(ctx context.Context, target domain.Config, generation uint64) error
func (c *NetworkServicesCoordinator) Finalize(ctx context.Context, target domain.Config, generation uint64) error
func (c *NetworkServicesCoordinator) Recover(ctx context.Context, running domain.Config, generation uint64) error
func (c *NetworkServicesCoordinator) Reconcile(ctx context.Context) error
func (c *NetworkServicesCoordinator) Status(query domain.NetworkStatusQuery) (domain.NetworkStatusPage, error)
```

Deps contains lazy typed backend providers, artifacts/journal/clock, provenance guard, legacy
prepared apply/current-snapshot/restore/finalize callbacks, status/event sink.
Provider closures are constructed without IO and first resolve the installed
profile/adapters only in an explicit enabled Prepare or recovery of previous M5
state. They serialize initialization, return typed interfaces and allow a later
retry after a failed capability check; do not cache a failed context forever.
Compiled schema support can be reported without probing installed tools. Initial
capabilities have probed=false, component_versions empty and available empty;
supported lists implemented schema features. Negotiation checks schema support;
Prepare establishes runtime availability. UI may edit a supported but unprobed
feature and states that commit will perform preflight; it does not label it ready.
After active-to-disabled cleanup, workers stop and cached status remains readable
without starting tools/timers again. A status poll never triggers lazy startup.
Startup may perform one bounded read-only existence/load check of the outer WAL
and ownership manifest even if Running has no M5 subtree. This is necessary to
discover a crash during the first enable before Running publication. With no
prior M5 state the check creates no directories/files and invokes no tools; all
other disabled paths are no-op. Tests asserting constructor/steady-state no IO
must distinguish this explicit recovery probe from runtime mutation.
No backend imports engine. One activation gate serializes apply/recovery/reconcile;
status reads immutable snapshots. Do not hold the M2 session mutex while doing IO.
Lock order during apply: existing RuntimeServiceAdapter apply lock -> existing
inspection activation gate / Manager activation serialization -> M5 method mutex
-> inner controller. Prepare releases its mutex before returning: Commit invokes
preflight before pausing inspection, but Rollback pauses inspection first. Never
hold a new mutex across those callbacks. An in-flight generation flag, not a mutex
held across methods, suppresses background reconcile until Finalize/compensation.
Reconcile reads a Running snapshot before locking M5, checks its generation again
against the cached accepted generation, and never acquires the inspection gate or
calls back into Config commit. Startup recovery runs before workers start. Each
method must support duplicate calls after lost IPC replies.
Prepare artifacts expire after 5 minutes unless referenced by WAL. Apply rejects
different target digest under a prepared generation. Total commit budget 120s;
compensation uses a separate bounded 60s context after caller cancellation.

Existing IPC mutation timeout is 60s and API HTTP WriteTimeout is 95s; neither
can carry that budget. PROPOSED capability `config_mutation_timeout_ms:190000`
negotiates a longer deadline for config commit/rollback only in a paired M5 build.
Other mutations/queries retain existing limits. The client caches negotiation;
an old server keeps 60s and cannot accept an M5 Candidate. The new server applies
190s only to those two operations when its M5 optional interface is installed.
API commit/rollback use Go ResponseController.SetWriteDeadline at 200s for that
capability; frontend mutation requests use 205s. API's default 95s remains for
other requests. Record this intentional timing-only compatibility change. A lost
reply is not authorization to submit a new operation ID; retrieve Running/status
or retry the same operation ID. Compensation may outlive a disconnected HTTP
client and remains serialized by the engine activation gate.

Control-plane admission is also engine-owned. PROPOSED
`CompileNetworkServiceGuard(config, readiness, serviceUID)` renders only
`inet ngfw_m5_services`: scoped INPUT guards for HAProxy tuples, BGP TCP/179 from
configured single-hop peers, OSPF IP protocol89 on explicit non-passive interfaces
(same-link source subnet and TTL1), BFD UDP/3784 from configured peers (TTL255),
and VRRP IP protocol112 from unicast peers (TTL255). BFD echo/multihop are disabled.
When a selected protocol is enabled, its local destination-port/IP-protocol scope
covers the appliance's local INPUT on all interfaces, allowing only the configured
peer/interface/TTL combinations. This matters because bgpd can listen on wildcard
TCP179: merely guarding the authorized interface would leave another interface
exposed. OSPF allows explicitly configured non-passive interface source subnets;
authentication is the supported additional peer check. Unrelated protocols/ports
remain outside that feature's scope. Packets outside owned scopes return; unauthorized
traffic drops. Generated protocol guards allow authorized established replies
within the same scope; never add a general established accept before admission.
HAProxy OUTPUT is restricted by its dedicated UID to configured backend/check
tuples and established conntrack-reply traffic from owned listener tuples (not an
unconditional source-port allowance). Other UIDs are unaffected. Accepted
packets still traverse any other base chains; this table cannot override an
external drop. New/changed service tuples stay closed until verified. A generation
change atomically replaces this one table, never flushes the M1 table. Turning off
a feature first stops its listener/daemon, then removes its exact guard scope.

`dataplane.NetworkOwnership.PreparePlan(ctx, previous, desired, operations)` returns
validated operations with exact route provenance clauses; nil means current legacy
behavior. `NetworkOperation` adds `RouteClaim *RouteMutation` (ID, action, full
typed route key) only for route operations. The guard uses this metadata rather
than parsing human Description or freeform command strings. `Controller` gets a
read-only `CurrentActivationSnapshot() (ActivationSnapshot,bool)` clone accessor
for the outer journal. Existing restore/apply/finalize functions remain authoritative.

Shared support types (PROPOSED, typed contract rather than vendor data):

- `resources.RouteKey`: `Family uint8; Table,Metric uint32; Prefix,Gateway string;
  IfIndex int; Type uint8`; RouteClaim adds `RouteID string; Owner ResourceOwner;
  Protocol uint8; Generation uint64`. Owner enum is SENTINEL_MANAGED,
  EXTERNAL_DAEMON_MANAGED, KERNEL_RUNTIME, OBSERVED_ONLY. A manifest never turns an
  unmatched kernel object into an owned one merely by naming its prefix.
- `dataplane.RouteMutation`: `RouteID string; Action RouteAction; Key resources.RouteKey`;
  RouteAction is UPSERT/DELETE; NetworkOwnership uses typed operations, not string parsing.
- `ArtifactFile`: `Name string; Contents []byte; Mode uint32; Secret bool` (private
  memory only). ArtifactStore interface is Stage/Publish/Accepted/Accept/Prune with
  signatures in the file plan. Active and accepted pointers are distinct.
- `state.ActivationRecord`: `Schema uint16; OperationID string; OldGeneration,
  TargetGeneration uint64; OldDigest,TargetDigest string; Phase string;
  Previous dataplane.ActivationSnapshot; TargetPrepared []networkservices.Prepared;
  PreviousExternal []networkservices.Snapshot; Claims []resources.RouteClaim;
  Completed []networkservices.ApplyReceipt; Leases []SysctlLeaseRecord;
  StartedAt time.Time; Checksum string`. Atomic JSON uses snake_case keys.
  Phase enum PREPARED/QUIESCED/RESERVED/LEGACY_APPLIED/EXTERNAL_APPLIED/
  PUBLISHED/FINALIZED/COMPENSATING/RECOVERY_REQUIRED. Validate checksum and refs
  on load; Running file decides whether publication occurred, not this phase alone.
- `SysctlLeaseRecord`: `Key,Before,Applied string; Generation uint64`;
  readiness `ReadyRecord`: `BootID string; Generation uint64; WrittenAt time.Time;
  MonotonicNS int64; Ready bool; Dependencies map[string]bool`. Only local helper
  consumes readiness; payload not a remote administrative interface. MonotonicNS
  uses CLOCK_BOOTTIME on both writer and helper. Publish checks generation equals
  current accepted Running/runtime and no affected activation is in-flight;
  EvaluateReadiness checks Ready, nonzero generation, same boot, nonnegative age
  <=5s and required dependencies. It takes nowMonotonicNS, not deserialized Go
  time.Time monotonic data (which JSON does not preserve). Publish false before
  the first affected mutation, even if the normal heartbeat interval has not elapsed.
- `CommandPhase` is a fixed internal enum including PREPARE/SNAPSHOT/RESERVE/
  APPLY/VERIFY/FINALIZE_VERIFY/RESTORE/STATUS. Runner may export that enum as
  NGFW_M5_PHASE for command correlation; no Candidate string is allowed. Only
  the separately selected root-owned lab profile uses a fault wrapper. Normal
  production executables receive unchanged vendor argv and no fault switches.
- `Clock` supplies `Now() time.Time` and `BoottimeNS() int64`; fake clocks are
  injected for tests. `GuardBackend` exposes Apply/Snapshot/Restore using typed
  guard contracts; `LeaseBackend` exposes Apply/Restore; `ReadinessSink` exposes
  Publish. These small interfaces are declared with the T02 contracts so T07
  compiles against fakes before concrete nft/sysctl/Keepalived implementations.
- Error enums/queries are bounded SENTINEL contracts. Methods using local helper
  types RenderBindings, RenderedConfig, Directive, RawRoutingJSON, StatsSchema,
  GuardPlan and KernelSnapshot are adapter-internal values; they never enter
  Config, IPC or persisted authoritative Running. Keep their fields minimal for
  the exact renderer/observer outputs, with fixtures capturing vendor schemas.

## 5. Status DTOs and API contracts

Every status record contains `id`, `generation`, `observed_at`, `stale`, `reason`.
Whole responses also contain `schema:1`, `snapshot_id`, `snapshot_time`,
`next_cursor`, `has_more`, `truncated`. Max page200; default50; max aggregate4096;
cursor binds subsystem/filter/snapshot ID for 30s and returns `CURSOR_EXPIRED`
after generation change, never mixes generations silently.

| DTO | Exact additional typed fields (JSON names equal snake_case) |
|---|---|
| SubsystemStatus | configured/reachable/applied/operational bool; state string DISABLED/STARTING/READY/DEGRADED/RECOVERY_REQUIRED/UNKNOWN; reason_code string |
| OSPFNeighborStatus | router_id,address,interface_id,area,state string; dead_remaining_ms int64; uptime_seconds uint64 |
| OSPFInterfaceStatus | interface_id,area,state,network_type string; passive bool; cost uint16; neighbor_count uint32 |
| BGPNeighborStatus | address,interface_id,state string; local_asn,remote_asn uint32; uptime_seconds,accepted_prefixes,advertised_prefixes uint64; received_prefixes *uint64 (nil unavailable); shutdown bool |
| BFDPeerStatus | local_address,address,interface_id,state string; transmit_ms,receive_ms uint32; multiplier uint8; last_transition time.Time |
| RouteStatus | prefix,protocol,owner,interface_id,gateway string; table,metric uint32; selected,installed bool; nexthops []NextHopStatus; source enum SENTINEL_STATIC/KERNEL_CONNECTED/OSPF/BGP/FOREIGN/UNKNOWN |
| NextHopStatus | gateway,interface_id string; weight uint16; active bool |
| RoutingStatus | subsystem SubsystemStatus; neighbors/interfaces/bfd/routes typed slices above |
| LoadBalancerStatus | subsystem; services []LBServiceStatus; backends []LBBackendStatus; servers []LBServerStatus |
| LBServiceStatus | listen_address,mode,state,inspection_mode string; port uint16; active_connections,total_connections,requests uint64 |
| LBBackendStatus | state,algorithm string; available_servers uint32; active_connections uint64 |
| LBServerStatus | backend_id,address,health string; port uint16; active_connections,total_connections uint64; last_change time.Time |
| WANStatus / WANPathStatus | mode string; paths []; path has interface_id,neighbor_id,bfd_state,probe_state string; selected bool; consecutive_successes/failures uint32; successes/failures uint64; last_transition time.Time |
| HAStatus / VRRPGroupStatus | subsystem; groups []; group has interface_id,state string MASTER/BACKUP/FAULT/STOP/UNKNOWN; vrid,priority uint8; addresses []string; vip_present bool; last_transition *time.Time; evidence_source string |
| IPVSStatus optional | subsystem; virtual_servers []; each ID/protocol/address/port, real_servers[] with health/weight/active_connections/inactive_connections; no connection payloads |
| NetworkServicesCapabilities | schema uint16; supported,available []string; probed bool; component_versions map[string]string; profile_digest string; limits map[string]uint64; config_mutation_timeout_ms uint32; unavailable_reasons []string; production_ready bool (false until acceptance) |

Core queries: `NetworkStatusQuery{Subsystem,View,Filter,Cursor string; Limit int}`;
View allowlist: routing summary/ospf-neighbors/ospf-interfaces/routes/bgp-neighbors/
bgp-accepted/bgp-advertised/bgp-received/bfd, load-balancer summary/services/backends,
wan paths, ha groups, optional ipvs virtual-servers. Filters are typed IDs/prefixes,
not vendor CLI. Use specialized DTO unions internally, not arbitrary raw JSON.

`RoutingQuery` has `View,PeerID,Prefix string; Limit int`; each nonempty field is
validated against the configured peer ID/canonical IPv4 prefix and view allowlist.
`NetworkStatusPage` fields (Go type / JSON) are `Schema uint16/schema`,
`Subsystem string/subsystem`, `Status SubsystemStatus/status`,
`Generation uint64/generation`, `SnapshotID string/snapshot_id`,
`SnapshotTime time.Time/snapshot_time`, `Items []NetworkStatusItem/items`,
`NextCursor string/next_cursor,omitempty`, `HasMore bool/has_more`,
`Truncated bool/truncated`. `NetworkStatusItem` is a tagged union: `Kind string/kind`
and exactly one typed optional pointer among ospf_neighbor, ospf_interface,
bgp_neighbor, bfd_peer, route, lb_service, lb_backend, lb_server, wan_path,
vrrp_group, optional virtual_server. Pointer types are the corresponding status
rows above. Encoder/decoder reject kind/pointer mismatch. Summary views return
Status plus zero or bounded summary items, never a raw vendor JSON body.

PROPOSED optional `engineipc.NetworkServicesRuntimeService`:
`NetworkServicesStatus(context.Context, domain.NetworkStatusQuery)
(domain.NetworkStatusPage,error)` and
`NetworkServicesCapabilities(context.Context) (domain.NetworkServicesCapabilities,error)`.
Add v3 optional operation names `network_services.status` and
`network_services.capabilities`; keep existing envelope/request bounds and methods.
New clients must negotiate the schema before committing any nonnil M5 config.
Old service missing capability -> refuse M5 commit, not silent field loss. Nil M5
commits keep existing IPC behavior. Deploy engine/API/web as one versioned release.

HTTP reads (existing auth/RBAC/envelope):

- `GET /api/v1/network-services/capabilities`
- `GET /api/v1/network-services/status?subsystem=routing&view=routes&limit=50`
- `GET /api/v1/network-services/status?subsystem=load-balancer&view=backends`
- `GET /api/v1/network-services/status?subsystem=wan&view=paths`
- `GET /api/v1/network-services/status?subsystem=ha&view=groups`

Configuration continues through existing full Candidate PUT, validation at
`POST /api/v1/policies/validate`, commit at `POST /api/v1/policies/commit` with
`{expected_version,author,comment}`, and administrative rollback at
`POST /api/v1/policies/rollback`. No public FRR/HAProxy/Keepalived mutation endpoint.
No secret upload API in core; reference provisioning is a local admin action.

Contract checkpoint: FINDINGS — exact core schema and interfaces defined; future
types deliberately not exposed. DECISIONS — strict optional subtree/typed limits,
capability negotiation and same Candidate lifecycle. UNRESOLVED — T01 installed
profiles/VM evidence only. FILES/SOURCES ALREADY INSPECTED — cached ledgers.
NEXT TARGETS — file/function cards and tasks implement these names, not replacements.
