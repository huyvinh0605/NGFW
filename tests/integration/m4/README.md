# M4 T01 capability probe

Run on the target Ubuntu appliance VM before enabling the M4 proxy selector:

```bash
sudo bash tests/integration/m4/probe-capabilities.sh --mechanism tproxy --evidence-dir /tmp/ngfw-m4-probe
```

Requires `ip`, `nft`, `ss`, `sysctl`, `python3`, `openssl`, `suricata`, and `timeout`, plus root for temporary network namespaces. It creates three temporary namespaces, two veth pairs, a private nftables table **inside the router namespace**, a temporary CA, and a separate Suricata Unix-socket worker. It does not modify the host ruleset or production NGFW services. The temporary CA private key is removed and is not copied into the evidence directory.

Exit `0` means all probes passed. Exit `1` means a capability or behavior failed. Exit `2` means a prerequisite is missing. Preserve `original-dst.jsonl`, `client.jsonl`, `backend.jsonl`, `nft-ruleset.txt`, `suricata-control.json`, and error logs from the evidence directory. The Ubuntu VM result is recorded in `artifacts/m4-t01-20261022T1135Z/`: `--mechanism redirect` failed the public DNAT case (five client/backend requests, four proxy accepts); `--mechanism tproxy` passed and recovered `10.251.0.2:443` as the **post-DNAT** upstream destination. The TPROXY probe also uses a FIB egress-interface match before interception.

The script is only a capability probe. Passing it does not mark M4 VM acceptance complete. The Ubuntu package is Suricata 7.0.3, whose initial socket greeting has no newline, `command-list` returns a counted object, and idle `pcap-current` returns `"None"`. The request worker and probe use those observed values; see the [Suricata 7 Unix-socket documentation](https://docs.suricata.io/en/suricata-7.0.14/unix-socket.html).

## T29 deployment and evidence collection

The M4 request-worker Suricata configuration, rules and hardened proxy units
are staged with `sudo bash scripts/install-m4-assets.sh`. Use the optional
`--proxy-binary /absolute/path/ngfw-proxy` to install a matching built proxy.
The installer requires the Ubuntu `acl` package (`setfacl`) for search-only
access to the M1/M2 state and configuration parent directories.
The script runs `suricata -T` as `ngfw-proxy` and installs the engine socket
group drop-in. Restart the engine for that group membership, explicitly
provision the CA when DECRYPT is required, and enable/start `ngfw-proxy`.
Committing M4 through the management API then prepares the proxy and activates
the nft/route snapshot. The installer itself does not change nftables.

The proxy account must **not** belong to the privileged `ngfw` group. The
installer grants search-only ACLs on `/etc/ngfw` and `/var/lib/ngfw`; the engine
drop-in grants search-only access to `/run/ngfw` on every restart. Only the
dedicated `root:ngfw-proxy` request-gate socket is accessible to the proxy.
The proxy cannot read `/etc/ngfw/ngfw.env` or access `engine.sock`. Stop a
running proxy before upgrading its unit/account, then restart engine before
starting proxy so its socket and directory ACL are refreshed.
The CA directory/key belong to `ngfw-proxy:ngfw-proxy` at `0700`/`0600`; the
API account `ngfw` must fail to read the key. Request-worker processes are
bounded child processes started by the proxy's `requestworker.ProductionFactory`.
`ngfw-request-worker-preflight.service` validates their common config before
the proxy starts; starting separate systemd Suricata worker instances would
compete for the same per-worker Unix sockets and is intentionally avoided.

On Ubuntu, collect a read-only baseline:

```bash
sudo bash scripts/verify-m4-linux.sh --evidence-dir /tmp/ngfw-m4-evidence
cat /tmp/ngfw-m4-evidence/summary.json
```

Exit `0` means collection completed and the CA permission preflight did not
find a violation. `summary.json` deliberately says `acceptance_status: PENDING`.
Exit `1` means the API can read the CA key or the proxy cannot read it; exit
`2` means missing prerequisites. The collector saves kernel/Suricata versions,
service hardening fields, nftables/conntrack snapshots and M4
health/capabilities. Request evidence requires an authenticated management
query and must be saved separately with its bearer token redacted. The
collector never copies private keys or environment secrets.

For each traffic scenario in [the M4 acceptance matrix](../../../docs/m4-acceptance-matrix.md),
copy [the evidence template](EVIDENCE_TEMPLATE.md) into a scenario directory,
record exact commands and UTC timestamps, and compare the proxy/engine verdict
with the upstream access log. A `BLOCK` needs a matching request ID and proof
that the upstream saw no application request. Keep every VM row `NOT_RUN`
until that evidence has been captured.

## Reversible HTTP VM run

`lab_http_acceptance.py` uses the existing lab addresses and host accounts.
It requires Python Requests and Paramiko on the controller, reads the SSH
password from `NGFW_LAB_PASSWORD`, and obtains the API token on NGFW without
printing or persisting it. With the updated binaries and proxy already running:

```bash
python tests/integration/m4/lab_http_acceptance.py --evidence-dir artifacts/m4-http-RUN
```

Use `--preserve-draft` to snapshot a Candidate that differs from Running and
restore that exact draft after the test. The runner starts a temporary DMZ
origin, commits a narrow LAN→DMZ HTTP gate and tests clean, SQLi and XSS. A PASS
requires the client response, Suricata SID, authoritative reason/coverage and
upstream nonce presence/absence to agree. The finalizer restores Running and
Candidate, checks that the activation journal and M4 policy route are absent,
checks that the proxy table has no prerouting hook, and stops its origin.
An early refusal never replaces a Candidate draft.

The successful Ubuntu run is under `artifacts/m4-fix-20261024/http-final/`.
This runner covers HTTP/1.1; it does not mark HTTPS/H2/NAT or the complete M4
matrix accepted. The new Linux namespace test for the App-ID guard is described
in [the guard schema note](../../../docs/m4/INSPECTION_GUARD_SCHEMA.md).

## Reversible HTTPS VM run

`lab_https_acceptance.py` covers M4-07 and M4-08 with a temporary DMZ TLS
origin and a dedicated temporary CA. It requires `NGFW_LAB_PASSWORD`, Requests,
Paramiko and a local Go toolchain for the verified Linux client:

```bash
python tests/integration/m4/lab_https_acceptance.py --evidence-dir artifacts/m4-https-RUN
```

The runner preserves Running and any separate Candidate draft, installs a
runtime-only systemd CA environment override, and restores/removes these
resources on completion or failure. It does not replace the NGFW binaries.
The client verifies the CA chain and DNS SAN using NGFW's time plus five
minutes, recording the time explicitly; it does not disable certificate
verification or change VM clocks. A direct upstream TLS preflight runs on
NGFW. This keeps lab clock skew separate from the TLS interception checks.

Counters reach the management endpoint on the proxy heartbeat. The runner
waits up to eight seconds for a healthy same-generation heartbeat newer than
the engine request evidence and for the expected counter deltas. It records
each sampled timestamp/counter map. A zero counter after that deadline still
fails, as does a generation change; an older snapshot is never a PASS or
proof of a counter defect. The runner stops before the next traffic case on
the first failed assertion.

Run the polling regression checks without a VM:

```bash
python -m unittest discover -s tests/integration/m4 -p test_health_poll.py -v
```

## TLS continuation and first-failure behavior

Continue after M4-07/08 with the same reversible setup and finalizer:

```bash
python tests/integration/m4/lab_https_acceptance.py --suite tls-continuation --evidence-dir artifacts/m4-tls-RUN
```

`lab_tls_cases.py` exercises BYPASS, 11 exclusion variants, split ClientHello,
missing SNI, upstream hostname mismatch, client CA distrust/pinning, and upstream
mTLS. The client uses its OS clock with normal CA/SAN validation. Synchronize lab
VM clocks before running; this suite does not change them or disable verification.

The observer records writes from existing engine threads without following
forked ip/nft children. tcpdump uses immediate mode on the LAN/DMZ interfaces;
the runner reconstructs TCP streams and rejects capture gaps/conflicting bytes.
Only synthetic test traffic is captured. No private CA key is archived.

The [2026-10-24 run](../../../artifacts/m4-tls-continuation-20261024T1120Z/RESULTS.md)
accepts rows 09/10/11/14 and leaves 12/13 partial. It stops at M4-15: safe 502 and
no upstream HTTP request, but no request-correlated mTLS failure reason. The raw
runner initially deferred the diagnostic review; ACCEPTANCE_ASSESSMENT.json
records the final FAIL. The maintained runner now asserts that reason and stops
automatically. No product fix or further VM traffic run followed that finding.

## Focused M4-15 fix recheck

The subsequent fix is tested with:

```bash
python tests/integration/m4/lab_https_acceptance.py --suite mtls-recheck --evidence-dir artifacts/m4-mtls-RUN
```

It uses normal client OS time and CA/SAN verification. `lab_mtls_cases.py`
tests TLS 1.2 and TLS 1.3 with no, optional and required client authentication;
hostname mismatch, connection closure after optional client authentication,
TCP refusal and clean/SQLi/XSS controls are included. A PASS requires the
correlated engine `forward` result, unchanged content verdict, expected counter
delta, no silent bypass, and correct origin presence/absence. The observer
waits for the result record and then for its same-generation health heartbeat.
The existing finalizer restores Running/Candidate and removes temporary assets.

The [successful 14-case run](../../../artifacts/m4-mtls-fix-20261024T113924Z/RESULTS.md)
accepts M4-15 after installing the matched fixed binaries. An earlier attempt
in that directory is retained: it stopped at clean control because LAN/DMZ
clocks had drifted behind freshly issued certificates. One-time OS clock
alignment corrected the lab prerequisite; verification stayed enabled and
product certificate-validity rules were not changed.

## HTTP/2 and encoded-body continuation

Continue on the installed engine/API/proxy pair with matching shared M4 DTOs:

```bash
python tests/integration/m4/lab_https_acceptance.py --suite h2-clean --evidence-dir artifacts/m4-h2-clean-RUN
python tests/integration/m4/lab_https_acceptance.py --suite h2-isolation --evidence-dir artifacts/m4-h2-isolation-RUN
python tests/integration/m4/lab_https_acceptance.py --suite body-limits --evidence-dir artifacts/m4-body-RUN
```

The H2 client warms one verified TLS connection, forbids a second TCP dial and
starts 2 then 24 simultaneous requests. Engine evidence must show one connection
and session, distinct request/decision IDs and ordinals, correct clean/SQLi/XSS
verdicts and signatures, exact clean origin body hashes and no blocked origin
requests. This isolation run uses two workers and an explicit ten-second request
deadline; it does not measure the default-deadline overload capacity.

The body client sends real HTTP/1.1 chunk framing and gzip/zlib-deflate over
verified TLS. The temporary origin can decode chunk framing so its body hash
represents the actual application bytes. The runner checks clean and attack
controls, decompression/raw-body limits, explicit partial-allow behavior and
parser rejection in matrix order. A generated Python client is written as LF
bytes and invoked through `python3`, avoiding Windows shebang translation.
All traffic is synthetic. The first failed assertion stops later cases and the
existing finalizer restores Running/Candidate and removes the temporary CA,
origin and systemd overrides.

The [2026-10-30 repair and continuation](../../../artifacts/m4-forward-fix-20261030/RESULTS.md)
accepts M4-16..20 and stops at M4-21's decompression-limit classification failure.
M4-22/23 code paths in the runner remain unexecuted. Raw failures and fixture
prerequisite failures are retained with their separate assessments.
