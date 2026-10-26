# M3-03 Candidate workflow acceptance

M3-03 passed on the Ubuntu NGFW VM on 2026-10-26: **25 assertions passed,
zero failed**. This covers the management REST Candidate workflow. Browser
form/JSON navigation remains the separate M3-32 scenario; enabled IDS/IPS packet
inspection is outside this result.

## Corrected failure classification

The previous runner confused a JSON response envelope with its `data` object:

```python
# The response is {"success": true, "data": {"running": ..., "version": ...}}.
_, after_save = api("GET", "/config")
after_save.get("running")   # None: that key is inside data, not at this level.
after_save.get("version")   # None for the same reason.
```

The same mistake existed in the post-validation read. Initial and final reads
used a helper that unwrapped `data`, explaining why the old report appeared to
show a transient failure. Those observations do not establish a production
API defect. The new runner uses `config_data` consistently, rejects truly
missing/null fields explicitly, and preserves the complete HTTP response for
every request. Its success path also fixes the old runner's default `NOT_RUN`
status, which was never changed to PASS after successful execution.

No NGFW production Go code or service binary was changed for this repair.

## Repeat the accepted scenario

From the management machine, install `paramiko` and `requests`, supply the lab
password in `NGFW_LAB_PASSWORD`, and use a new evidence directory:

```bash
python -m unittest discover -s tests/integration/m3 -p test_lab_candidate_acceptance.py -v
python tests/integration/m3/lab_candidate_acceptance.py --evidence-dir artifacts/m3-03-new-run
```

The runner reads the API bearer token from `/etc/ngfw/ngfw.env` through SSH;
the token and SSH password are excluded from evidence. `--host`, `--user` and
`--api-base` can override the lab appliance settings. There is no Commit or
Rollback request in this scenario.

1. Save the operator's Candidate and validation state, Running generation and
   config, nftables rules, addresses, routes, state-file hashes, service PIDs
   and audit baseline.
2. Stage a Candidate with M3 globally enabled, a supported IDS profile and a
   reference from the existing scoped LAN-to-WAN ALLOW policy. This stays a
   draft; it is never committed.
3. GET the draft, verify the complete Running view is unchanged, and compare
   kernel/service snapshots.
4. Validate and check that the validation checksum is bound to that revision.
5. Edit a limit, verify the old validation becomes NOT_RUN, validate the new
   revision, and repeat the Running/kernel checks.
6. Restore the original Candidate and validation state, verify the final state
   and confirm audit contains no COMMIT or ROLLBACK.

Restore comparison permits only documented normalization of OR selector
representations: sorted/deduplicated zones, applications and services, and
canonical IP prefixes. Rule order, priority, action, profile selection and all
other configuration fields remain part of the exact comparison. Regression
checks reject real changes to action, priority, service, subnet or zone scope.
Concurrent Candidate edits are preserved rather than overwritten by cleanup.

## Recorded VM result

- Running version: **93**; config checksum
  `de0d7be3b5e52810cf2d4f14712bcecf69dacb415d58500edd9d4a62240d4828`.
- Persisted `running.json` SHA-256:
  `6dff9a11d22c37747d1b36ef03ae3e480d26821c344dd9b973c67a61ced63956`.
- M3 remained disabled in Running; no Suricata sensor was started by draft
  save/load/validate. Engine/API PIDs, network state and applied snapshot did
  not change.
- Seven runner regressions passed. The existing Go management regressions for
  no activation and Candidate validation revision also passed.
- Full raw HTTP/command/state evidence remains in the local evidence archive
  `artifacts/m3-03-repair-20261026T104615Z/vm-run-3/`. Historical runs are retained:
  the first new fixture used an invalid TLS enum and was correctly rejected;
  the second completed the workflow but its raw-equality cleanup assertion
  rejected equivalent API selector normalization. The final runner handles
  both cases without changing the backend validator or weakening policy checks.

The old report's alleged API null fields are superseded by this analysis and
the accepted run. This result does not accept the remaining M3 scenarios.
