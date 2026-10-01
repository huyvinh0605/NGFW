# M4 scenario evidence (copy per scenario)

Status: NOT_RUN  
Matrix ID: M4-__  
UTC run ID / operator:  
Git commit / dirty diff hash:  
Running generation / config hash:  
Ruleset ID + SHA-256:  
Kernel / nftables / conntrack / Suricata / Go versions:  
Topology and interface names:  

## Preconditions

- M1/M2/M3 baseline run IDs:
- T01 capability probe result and interception mode:
- CA fingerprint (public certificate only; never copy private key):
- Health and capabilities JSON path:

## Exact commands and timestamps

| UTC time | Host | Command | Exit code | Output path |
|---|---|---|---|---|
| | | | | |

## Correlation

- Connection ID / Request ID / session ID / policy generation:
- Client request nonce and HTTP version:
- Engine connection action and request verdict/reason:
- Suricata worker job ID, EVE SID and completion evidence:
- Upstream log/pcap path and matching or absent nonce:
- nftables/conntrack snapshot paths:
- Error, timeout, partial coverage or fail-mode observations:

## Result

Expected behavior:  
Observed behavior:  
PASS / FAIL / NOT_RUN: NOT_RUN  
Why the evidence proves the result:  
Known limitation or follow-up bug:  

Do not mark PASS from a build, unit test, health endpoint, or the read-only
collector alone. Do not include CA private keys, bearer tokens, Authorization
or Cookie headers, or real-user request bodies in evidence artifacts.
