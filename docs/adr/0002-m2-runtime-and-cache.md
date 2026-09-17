# ADR 0002: M2 runtime ownership, conntrack and cache marks

Status: accepted for M2 implementation

## Decision

`ngfw-engine` is the only owner of running configuration generation, the
conntrack source, the bounded `RuntimeStore`, policy evaluation, decision cache,
invalidation and kernel guard mutations. `ngfw-api` keeps authentication and
candidate editing and reaches those operations through versioned Unix socket
IPC. The API process has no network administration capability.

The Linux adapter consumes typed ctnetlink events and bounded dumps. A session
is keyed by scoped conntrack identity and indexes original, reply, translated
and pre-SNAT/post-DNAT aliases to one `SessionID`. A complete dump is used for
recovery; incomplete tracking is reported as degraded and never becomes a
packet-forwarding dependency.

The M2 nft compiler reserves the upper 24 bits of `ct mark`: a 12-bit durable
epoch and two 6-bit zone slots. The lower byte is preserved. Only a current
epoch/zone pair can hit the established cache rule. Invalid state, runtime
source blocks and exact conntrack revocation guards run before that cache. A
startup activation allocates a fresh epoch, so old marks are treated as cache
misses after restart or rollback. Epoch exhaustion disables cache marks and
keeps the full policy path.

M2 evaluates only L3/L4 connectivity. For DNAT, the evaluator uses the
pre-SNAT source and post-DNAT destination tuple, matching the nft forward hook;
inspection, risk, IDS, ML and proxy decisions remain later milestones.

## Consequences and limits

Policy and network activation retain M1's journal, compensating rollback and
atomic nft policy replacement. The engine preserves its separate runtime guard
table across policy replacement, so temporary block TTLs and revoke fences are
not removed by commit or rollback. IPv6 tuple tracking is modeled, while M1's
IPv4-only policy compiler and forwarding acceptance scope remain unchanged.

The current Linux conntrack implementation uses the pinned typed decoder and
applies record/byte/deadline limits before handing records to the store. A
successful resync reconciles the observed identity set and closes sessions
missing from a complete dump. On startup the engine clears the integer revoke
set because conntrack IDs can be reused; source-block elements retain their
kernel TTL. A large-kernel-dump memory profile and nft mark/guard syntax still
require Ubuntu VM acceptance evidence; those checks are deliberately not
represented as unit test passes.
