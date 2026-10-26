# Optional Internet uplink for the NGFW lab host

The fifth VMware adapter is connected to VMnet8 NAT and appears as `ens40`.
On this host, VMware supplies DHCP addresses in `192.168.5.0/24`, with gateway
and DNS server `192.168.5.2`. The NGFW VM obtained `192.168.5.138/24`; that address
is a DHCP lease and may change.

## Cause of the original outage

Ubuntu had no network configuration matching ens40. The link was UP but
unmanaged, with only an IPv6 link-local address. No DNS server was configured.
The main IPv4 default route pointed to the isolated WAN host, `192.0.2.1` on
ens33, which does not provide Internet transit in this lab. VMware NAT and DHCP
services on Windows were already running correctly.

## Installed configuration and ownership

The persistent host configuration is
`/etc/systemd/network/10-ngfw-update-uplink.network`, from the explicit optional
[lab template](../../deploy/lab/10-ngfw-update-uplink.network). The installer does
not enable it automatically. It was tested with Ubuntu 24.04 / systemd 255.

- `systemd-networkd` owns ens40 and obtains IPv4, gateway and DNS via DHCP.
- DHCP routes go into table **108**. The table and priorities **10000/10010**
  must be unused before installing the template.
- Rule 10000 matches locally originated IPv4 packets (`iif lo`) and uses
  specific main-table routes while suppressing the main default route.
- Rule 10010 sends remaining local IPv4 traffic through table 108's NAT default.
- Forwarded LAN/DMZ/WAN traffic continues to use the main table. Its existing
  default remains `via 192.0.2.1 dev ens33 metric 100`.
- `systemd-resolved` uses the DHCP DNS server on ens40, with routing domain
  `~.`. `/etc/resolv.conf` remains the normal resolved stub symlink.
- `RequiredForOnline=no` avoids blocking boot if the optional uplink is absent.
  IPv6 RA is disabled on this interface; the update uplink is IPv4.

The NGFW still manages its four configured WAN/LAN/DMZ/MGMT interfaces. This is
an OS configuration for host package/Git/dependency access, outside the
product's Running/Candidate routing configuration.

The VM already had loose reverse-path filtering (`all`, `default` and ens40
`rp_filter=2`), which supports the separate uplinks. No sysctl change was needed.

## Apply and verify

Back up any existing file first. For this lab, the original file was absent.
Only reconfigure the new interface after installing the template:

```bash
sudo install -o root -g root -m 0644 deploy/lab/10-ngfw-update-uplink.network \
  /etc/systemd/network/10-ngfw-update-uplink.network
sudo networkctl reload
sudo networkctl reconfigure ens40

ip -4 address show dev ens40
ip -4 rule show
ip -4 route show table 108
resolvectl status ens40
ip route get 1.1.1.1
ip route get 1.1.1.1 from 192.168.10.10 iif ens37
ip route get 192.168.100.10
git ls-remote https://github.com/huyvinh0605/NGFW.git refs/heads/main
sudo apt-get update
```

The first Internet lookup should use ens40; the forwarded lookup should use
ens33, and management should use ens39. Confirm the NGFW network verifier
passes before resuming acceptance traffic tests.

On 2026-10-26, HTTPS to GitHub, the Go module proxy and NPM returned HTTP 200;
Git read the remote main branch directly. APT refreshed 6.5 MB of indexes and
downloaded the real 44,584-byte `iputils-ping` package. DHCP renewal preserved
the expected rules, DNS and HTTPS access. The downloaded probe package was
removed after verification, without installing or upgrading packages.

The configuration is read by the already-enabled networkd/resolved services
at boot. Validation covered live application and DHCP renewal; a full VM
reboot was not performed during this network maintenance task.

Raw maintenance evidence is retained locally under
`artifacts/ngfw-ens40-internet-20261026T110302Z/`. Original Netplan and dataplane
ownership files were backed up in
`/var/lib/ngfw/maintenance-backups/ens40-internet-20261026T110302Z/` and were not
edited. Running configuration remains version 93.

## Disable the optional uplink

For the exact template installed here, disable the file and remove only its
reserved rules/routes. Verify table 108 is still dedicated to this uplink first.

```bash
sudo mv /etc/systemd/network/10-ngfw-update-uplink.network \
  /etc/systemd/network/10-ngfw-update-uplink.network.disabled
sudo networkctl reload
sudo networkctl down ens40
sudo ip -4 rule del priority 10010 iif lo table 108 || true
sudo ip -4 rule del priority 10000 iif lo table main suppress_prefixlength 0 || true
sudo ip -4 route flush table 108
sudo resolvectl revert ens40
```

This leaves the four lab interfaces and their main-table routing in place.
