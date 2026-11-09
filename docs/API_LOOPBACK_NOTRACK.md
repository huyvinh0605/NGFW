# Optional IPv4 loopback API conntrack exemption

The Vite proxy calls the management API at `127.0.0.1:8080`. This opt-in service
exempts TCP packets with both IPv4 addresses exactly `127.0.0.1`, routed out `lo`,
and source or destination port 8080. The output hook runs at raw priority -300,
before conntrack. Both local request and response packets traverse output.
Other loopback addresses, IPv6, ports, management-client connections to Vite and
forwarded traffic remain tracked. Port/address matching includes any other local
process using this API endpoint; it does not identify the Vite process.

Install from a reviewed source checkout on the appliance:

```sh
sudo bash scripts/install-api-loopback-notrack.sh
```

On a running appliance, first drain local API clients. Close short-lived tools
and stop only the verified Vite process. Let the TCP close exchange complete,
then enable the exemption and restart the UI:

```sh
sudo systemctl enable --now ngfw-api-loopback-notrack.service
bash start-web.sh
```

The helper refuses to apply while it sees tracked ESTABLISHED/SYN API loopback
connections. Otherwise switching an active connection to untracked packets can
leave its old entry ESTABLISHED until the long timeout. Do not flush conntrack
or DELETE entries to hide this transition. Already closed entries can remain
until their normal timeout. Close/drain the identified clients and retry if the
helper refuses; it makes no table change on this failure.

The unit starts before ngfw-engine/ngfw-api on subsequent boots and after
nftables.service when that service is present. The helper replaces only its
owned table as one checked nft transaction. It refuses an existing table with
the same name but a different ownership comment. The management API port here
is fixed at 8080; this feature must be reviewed if the API endpoint changes.

```sh
sudo systemctl status ngfw-api-loopback-notrack.service
sudo /usr/local/lib/ngfw/api-loopback-notrack.sh status
sudo systemctl reload ngfw-api-loopback-notrack.service
# Disable persistently and remove only this exemption:
sudo systemctl disable --now ngfw-api-loopback-notrack.service
```

Removing/reloading this exemption while sockets are active does not preserve
their conntrack identity. Drain clients for planned transitions in either
direction. Enabling it changes the appliance's diagnostic coverage: exempted
flows have no conntrack ID/counters and no corresponding RuntimeStore session,
so conntrack-based revoke/history cannot operate on those flows. Socket and
application authentication still apply; this does not bypass API auth. Inspect
the local sockets with `ss -tanp`, and API/service logs when diagnosing them.

This reduces conntrack and RuntimeStore tracking for the selected transport.
It does not remove TCP sockets, their buffers, or Windows-to-Vite sessions.
Do not report a RAM saving from session count alone. Kernel slab pools may
retain allocated pages after entries expire.

The installer never rebuilds or restarts engine/API/proxy and never changes
Running/Candidate. It does not run the full appliance installer. A manual
`nft flush ruleset` also removes this table; reapply the service only after
reviewing and draining any newly tracked API sockets.

Integration test (root, disposable network namespaces only):

```sh
sudo python3 tests/integration/management/test_loopback_notrack.py
```
