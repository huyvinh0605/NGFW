# Inspection guard schema 2

The original App-ID key was `ct zone . ct id . original source address/port .
original destination address/port . protocol`: seven concatenated fields.
Ubuntu nft 1.0.9 accepted its installation, lost leading datatype information
and crashed when listing the rule. Removing only a field also produced
incorrect integer lengths on readback. The
[upstream datatype definition](https://git.netfilter.org/nftables/log/include/datatype.h?id=c89fbc25102d126aa957e8a99d9ceb6ceaaf0193&showmsg=1)
documents the five-type representation limit.

Schema 2 preserves the complete identity with two lookups:

1. `app_denied_v4` maps the scalar conntrack ID to an owned chain.
2. That chain checks the conntrack zone and looks up the original five-tuple
   in a private timeout set for this ID/zone.

The tuple set uses fixed address, service and protocol types. Its elements
retain independent expiry, including when different zones share the same CT
ID. Install and group replacement are one nft batch; removal keeps any other
zone or tuple using the same ID. The manager's existing 10,000-guard bound also
bounds the number of dispatch entries, chains and sets. Startup, downgrade and
inspection-runtime replacement remove owned dynamic objects. Throughput and
memory at this maximum still require M3/M4 load measurement.

The same ID dispatch is used in the forward guard and the M4 prerouting guard,
so TPROXY cannot bypass an installed App-ID denial. The executable namespace
test is `TestLinuxInspectionGuardExactIdentityAndLifecycle`; it verifies real
UDP traffic with a real conntrack ID, wrong zone/protocol/port, exact DROP,
renew/remove, independent timeout and cleanup. Enable it only on the lab with
`NGFW_NFT_NETNS_TEST=1` as root.

Activation snapshots now use schema 3. Readers still authenticate schema-1/2
artifact and ruleset hashes using their historical compiler bytes. The
controller then recompiles the same configuration, generation, cache options
and accepted M4 artifact identities for the corrected kernel schema. A real
schema-2 VM snapshot is retained as a compatibility fixture.

An existing **live inspection schema-1 table requires a drained upgrade**.
The adapter detects the legacy set using a targeted query and rejects it
before the known-crashing whole-table dump. It does not erase active dynamic
guards automatically. Stop inspection, confirm the old guard/lease sets are
empty and that the table belongs to this appliance, then replace the owned
table and restart the updated engine to reconstruct it from Running. On the
tested VM M3 was OFF and the newly created legacy table was removed during
recovery; the updated engine successfully recovered the saved activation
journal and created schema 2. This test does not establish an automatic
migration of an active legacy M3 deployment.
