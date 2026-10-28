# M3-27 network recovery repair — 2026-10-28

The original invalid-next-hop test exposed repeated address deletion being
treated as a failed rollback. The repair also addresses the surrounding
transaction and recovery invariants:

- `Restore` applies a recovery target without reverting to the failed source
  if recovery itself fails. Controller compensation and startup recovery use
  this directed operation.
- `VerifyTransition` checks desired state and absence of stale NGFW-managed
  addresses/routes/VLANs; unrelated OS state remains permitted.
- Cancellation and journal removal errors remain explicit failures.
- Pending recovery reconciles both journaled sources. An unrelated third
  configuration is rejected before kernel mutation until recovery finishes,
  so another crash cannot leave objects missing from the durable journal.

Production code commits: `d86a60b`, `10aaa20`, following the initial address
error classification repair `71f218f`. All were pushed and pulled onto the VM.

Verification includes 13 real Linux failure/recovery cases in a disposable
namespace, an invalid-next-hop regression and SIGKILL of a controller probe,
then two failed commits through the actual appliance API while the same HTTP
socket/session/kernel identity remains live. A subsequent valid commit works.
Full Go tests and vet passed, including a clean published source tree and a
Linux race run for dataplane/config/engine.

M2 specification F31 requires a fresh cache epoch during compensation. API
ruleset comparison preserves every lower mark bit and policy/NAT rule while
normalizing only handles and the verified applied epoch. The original
Running generation and file hash remain unchanged on failed activation.

The appliance ends at Running version 160 with original Running/Candidate
content restored and engine/API/IDS/IPS active. Deployed engine SHA-256:
`f4a024adca4ba762ddadc2a99f1a0419d8ab090ee185b00b51d7015d21045042`.

This evidence does not include rebooting the entire appliance in the middle
of activation and does not accept the whole M3 matrix.

Repeatable commands: [recovery runbook](../../tests/integration/m3/RECOVERY.md).
Local evidence and raw archives: [repair results](../../artifacts/m3-recovery-repair-20261028/RESULTS.md).
