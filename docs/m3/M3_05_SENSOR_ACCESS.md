# M3 sensor filesystem access

Suricata IDS/IPS run as `ngfw-inspect` with `CAP_NET_ADMIN`. Their configuration
is under `/etc/ngfw/inspection` and their writable runtime under
`/var/lib/ngfw/inspection/{ids,ips}`. The privileged parent directories belong
to `root:ngfw` with mode `0750`; their permissions previously prevented the
sensor from reaching its own files.

`scripts/configure-inspection-access.sh` grants a named, search-only ACL for
`ngfw-inspect` on `/etc/ngfw` and `/var/lib/ngfw`. It preserves other ACL entries
and does not grant management group membership, directory listing, recursive
access or default ACL inheritance. It verifies that the sensor can read its
configuration and write its runtime, but cannot access management credentials,
Running/applied snapshots, management state, CA or request-worker directories.

The opt-in Linux installer installs the `acl` dependency, runs this helper
before syntax checks and after final permission reconciliation, and tests both
configurations as the sensor account. The launcher supplies its runtime as the
Suricata log directory. Root-only syntax checks do not establish service access.

For an existing installation, install the helper and updated launcher, then run:

```bash
sudo /usr/local/lib/ngfw/configure-inspection-access.sh
sudo -u ngfw-inspect suricata -T -c /etc/ngfw/inspection/ids.yaml -l /var/lib/ngfw/inspection/ids
sudo -u ngfw-inspect suricata -T -c /etc/ngfw/inspection/ips.yaml -l /var/lib/ngfw/inspection/ips
```

Previous root syntax checks can leave root-owned EVE files. Preserve these files
and correct their ownership before running an unprivileged syntax check; do not
discard traffic logs. In the recorded lab failure, both files were empty and
were moved to the repair backup while the sensors were stopped.

The Linux regression `TestInspectionAccessAcrossReinstall` exercises real ACL
access as the unprivileged sensor, reproduces the inaccessible parent, checks
token isolation, preserves an existing unrelated ACL, repeats after installer
chmod, and rejects unsafe credential permissions. Run on a Linux target with
the sensor account and ACL tools installed:

```bash
sudo go test -count=1 -v ./internal/deploy -run InspectionAccess
```

This repair and a successful syntax check do not themselves accept M3-05.
Early HTTP/TLS/DNS/SSH identification still requires real forwarded traffic,
correlated API/EVE evidence and observation before the connection closes.
