# M1 Ubuntu VM integration checklist

These checks are intentionally pending until they run on the four-NIC Ubuntu
24.04 VM. Unit tests and cross-compilation do not satisfy this checklist.

## Prepare the appliance

1. Copy the repository to the VM and run the installer. It installs Go,
   `iproute2`, `nftables`, `conntrack`, `curl`, `tcpdump`, `jq`, builds the M1
   binaries and installs the service units:

   ```bash
   sudo bash scripts/install-linux.sh --config configs/examples/m2-lab.json
   ```

2. Copy or edit a lab-specific config at `/etc/ngfw/lab.json`. Replace every interface
name, address, and gateway from `configs/examples/m2-lab.json` with the VM's
   actual WAN/LAN/DMZ/MGMT values.
   The installer preserves an existing file and creates a timestamped backup
   when `--config` replaces one.
3. Put these values in `/etc/ngfw/ngfw.env` and make the file `0640 root:ngfw`:

   ```text
   NGFW_STATE_DIR=/var/lib/ngfw
   NGFW_CONFIG=/etc/ngfw/lab.json
   NGFW_ENGINE_SOCKET=/run/ngfw/engine.sock
   NGFW_API_ADDR=<MGMT-IP>:8080
   NGFW_API_TOKEN=<LAB-ONLY-TOKEN>
   ```

4. Start the engine before the API:

   ```bash
   sudo systemctl enable --now ngfw-engine ngfw-api
   sudo bash scripts/verify-m1-linux.sh
   ```

Keep `journalctl -u ngfw-engine`, `ip -details -json link`, `ip -json address`,
`ip -json route`, and `nft -j list table inet ngfw` as evidence for each run.

## Commit through the unprivileged API

Never run the API as root. Replace the candidate through `PUT
/api/v1/config/candidate`, validate it, then commit with the running version:

```bash
curl -fsS -H "Authorization: Bearer $NGFW_API_TOKEN" \
  -H 'Content-Type: application/json' --data-binary @/etc/ngfw/lab.json \
  -X PUT "http://$MGMT_IP:8080/api/v1/config/candidate"
curl -fsS -H "Authorization: Bearer $NGFW_API_TOKEN" \
  -X POST "http://$MGMT_IP:8080/api/v1/policies/validate"
curl -fsS -H "Authorization: Bearer $NGFW_API_TOKEN" \
  -H 'Content-Type: application/json' -d '{"expected_version":0,"comment":"M1 VM test"}' \
  -X POST "http://$MGMT_IP:8080/api/v1/policies/commit"
```

Confirm from `/proc/<api-pid>/status` that `CapEff` is zero and from the engine
log that the request arrived over `/run/ngfw/engine.sock`.

## Acceptance scenarios

| Scenario | Procedure | Required evidence |
|---|---|---|
| Startup reconciliation | Remove one managed address/route or the `inet ngfw` table, restart only `ngfw-engine`. | The running address, route, VLAN and full nft table are restored; `recovered_interrupted_activation` is recorded when a journal existed. |
| IPv4 forwarding | Reboot, start services, run the status script. | Runtime value and `/etc/sysctl.d/90-ngfw-ip-forward.conf` both equal 1. |
| VLAN lifecycle | Commit a `VLAN_PARENT` plus a `VLAN_SUBINTERFACE` with `parent_interface_id` and VLAN ID; then commit a candidate without the subinterface. | `ip -d link` shows the correct parent/ID after create and no subinterface after delete. Its old addresses/routes are absent. |
| Address/route reconciliation | Replace an interface prefix and route, then remove them in another commit. | Old kernel objects disappear; only the new managed objects exist. |
| Stateful LAN to WAN | From LAN, open TCP and ICMP traffic to the WAN test host through an explicit allow policy and MASQUERADE rule. | Forward traffic succeeds, replies use the same conntrack entry, and tcpdump shows the translated source. |
| Default deny | Send traffic for a zone/service with no allow rule. | No packet reaches the destination; nft counter on the forward chain/default policy increases. |
| Policy OR semantics | Put two source CIDRs, two destination CIDRs, and TCP/80 plus UDP/53 in one policy. Test every allowed member and one nonmember. | Every listed alternative passes independently; the nonmember is denied. |
| DNAT to DMZ | Connect from WAN to the configured public address/port. Repeat with wrong source network, protocol, port and ingress zone. | Only the exact match reaches the translated DMZ address/port; return traffic is correct. |
| SNAT/MASQUERADE filters | Exercise matching and nonmatching source/destination zones, networks, protocols and ports. | Translation occurs only for the matching rule, in ascending priority order. |
| Failed activation rollback | Commit a route with a syntactically valid but unreachable gateway so `ip route replace` fails. | API commit fails; running version stays unchanged; old address/route/VLAN/nft state is restored; no activation journal remains after the API's restoration request. |
| API rollback | Make one successful network/NAT/policy commit, then call `POST /api/v1/policies/rollback`. | Kernel state and `running.json` both return to the previous configuration with a new version number. Repeat after restarting the API to prove previous-state persistence. |
| Management outage | Stop `ngfw-api` while forwarding test traffic. | Existing M1 routing, stateful firewall and NAT continue; only management commits are unavailable. |

Do not mark M1 complete until all rows have artifacts from the Ubuntu VM. M2
session caching, DPI, IDS, TLS interception, ML, and their tests are outside
this checklist.
