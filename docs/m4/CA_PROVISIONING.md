# M4 lab CA provisioning (local implementation; Ubuntu acceptance pending)

The proxy never creates a CA during normal startup. A missing, mismatched,
expired, or insecure CA key makes CA mode fail startup. Use a dedicated
directory owned by the dedicated `ngfw-proxy` account; do not place the key in
`/etc/ngfw` where the management API has group read access. The API runs as
`ngfw` and must fail `test -r` for the private key.

After building/installing the `ngfw-proxy` binary on Ubuntu:

```bash
sudo bash scripts/install-m4-assets.sh
sudo install -d -o ngfw-proxy -g ngfw-proxy -m 0700 /var/lib/ngfw/ca
sudo -u ngfw-proxy /usr/local/lib/ngfw/ngfw-proxy ca init
sudo -u ngfw-proxy /usr/local/lib/ngfw/ngfw-proxy ca fingerprint
sudo stat -c '%a %U:%G %n' /var/lib/ngfw/ca /var/lib/ngfw/ca/ca.key /var/lib/ngfw/ca/ca.crt
sudo -u ngfw test ! -r /var/lib/ngfw/ca/ca.key
```

`ca init` refuses to overwrite an existing CA. It prints the SHA-256
fingerprint of the new certificate; `ca fingerprint` prints it again without
creating files. Set `NGFW_PROXY_CA_CERT` and `NGFW_PROXY_CA_KEY` to distinct
absolute paths to use another location. Export only `ca.crt` to lab clients
for trust installation. Never export or log `ca.key`.

The private directory must be mode 0700 and the key mode 0600. The certificate
is mode 0644. The leaf cache defaults to 1024 entries and a 24-hour TTL;
profile limits are validated in the M4 configuration. Leaf certificates last
at most seven days, are generated only for a valid DNS/IP target, and carry
the correct DNS or IP SAN. A client without SNI requires a verified original
destination IP for certificate selection; no placeholder certificate is made.

The current M1/M3 installer does not install the production M4 proxy command
yet. That deployment wiring belongs to T28/T29; these commands are for
provisioning once the M4 binary is installed, not evidence of VM acceptance.
