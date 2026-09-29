#!/usr/bin/env bash
set -Eeuo pipefail

# M4 T01: live capability probe. All nftables and addresses stay in temporary
# network namespaces. Exit 0 only after every network, TLS and Suricata check.
usage() {
  echo 'Usage: sudo bash tests/integration/m4/probe-capabilities.sh [--evidence-dir DIR]' >&2
  echo 'Exit 0 = all probes passed; 1 = capability failed; 2 = missing prerequisite.' >&2
}

evidence_dir=''
while (($#)); do
  case "$1" in
    --evidence-dir) (($# >= 2)) || { usage; exit 2; }; evidence_dir=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo 'root is required for network namespaces' >&2; exit 2; }
for dependency in ip nft ss sysctl python3 openssl suricata timeout; do
  command -v "$dependency" >/dev/null 2>&1 || { echo "missing prerequisite: $dependency" >&2; exit 2; }
done

work=$(mktemp -d /tmp/ngfw-m4-cap.XXXXXX)
suffix=$$
router="m4r${suffix}"
client="m4c${suffix}"
server="m4s${suffix}"
client_host="mc${suffix}a"
client_router="mc${suffix}b"
server_host="ms${suffix}a"
server_router="ms${suffix}b"
backend_pid=''
proxy_pid=''
suricata_pid=''
cleanup() {
  set +e
  for pid in "$proxy_pid" "$backend_pid" "$suricata_pid"; do
    [[ -n "$pid" ]] && { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; }
  done
  ip netns del "$client" 2>/dev/null
  ip netns del "$server" 2>/dev/null
  ip netns del "$router" 2>/dev/null
  if [[ -n "$evidence_dir" ]]; then
    mkdir -p -- "$evidence_dir"
    for artifact in nft-ruleset.txt original-dst.jsonl client.jsonl backend.jsonl backend-errors.jsonl proxy-errors.jsonl proxy.log backend.log suricata-control.json suricata.log suricata-config.log; do
      [[ -f "$work/$artifact" ]] && cp -- "$work/$artifact" "$evidence_dir/$artifact"
    done
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT INT TERM

ip netns add "$router"
ip netns add "$client"
ip netns add "$server"
ip link add "$client_host" type veth peer name "$client_router"
ip link add "$server_host" type veth peer name "$server_router"
ip link set "$client_host" netns "$client"
ip link set "$client_router" netns "$router"
ip link set "$server_host" netns "$server"
ip link set "$server_router" netns "$router"
for namespace in "$router" "$client" "$server"; do ip -n "$namespace" link set lo up; done
ip -n "$client" addr add 10.250.0.2/24 dev "$client_host"
ip -n "$router" addr add 10.250.0.1/24 dev "$client_router"
ip -n "$router" addr add 10.251.0.1/24 dev "$server_router"
ip -n "$server" addr add 10.251.0.2/24 dev "$server_host"
for entry in "$client:$client_host" "$router:$client_router" "$router:$server_router" "$server:$server_host"; do
  ip -n "${entry%%:*}" link set "${entry#*:}" up
done
ip -n "$client" route add default via 10.250.0.1
ip -n "$server" route add default via 10.251.0.1
ip netns exec "$router" sysctl -q -w net.ipv4.ip_forward=1

# DNAT at -100, proxy redirect at -90. Output is deliberately untouched:
# upstream sockets opened by the proxy must not re-enter the redirect chain.
cat >"$work/redirect.nft" <<EOF
table ip ngfw_m4_probe {
  chain dnat {
    type nat hook prerouting priority -100; policy accept;
    ip daddr 198.51.100.20 tcp dport 443 dnat to 10.251.0.2:443
  }
  chain intercept {
    type nat hook prerouting priority -90; policy accept;
    iifname "$client_router" tcp dport 80 redirect to :18080
    iifname "$client_router" tcp dport 443 redirect to :18443
  }
}
EOF
ip netns exec "$router" nft -c -f "$work/redirect.nft"
ip netns exec "$router" nft -f "$work/redirect.nft"
ip netns exec "$router" nft -a list table ip ngfw_m4_probe >"$work/nft-ruleset.txt"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=NGFW M4 temporary probe CA' \
  -keyout "$work/ca.key" -out "$work/ca.crt" >"$work/openssl-ca.log" 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=probe.local' \
  -keyout "$work/leaf.key" -out "$work/leaf.csr" >"$work/openssl-leaf.log" 2>&1
printf 'subjectAltName=DNS:probe.local,IP:10.251.0.2,IP:198.51.100.20\nextendedKeyUsage=serverAuth\n' >"$work/leaf.ext"
openssl x509 -req -in "$work/leaf.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile "$work/leaf.ext" -out "$work/leaf.crt" >"$work/openssl-sign.log" 2>&1

cat >"$work/netprobe.py" <<'PY'
import json, os, select, socket, ssl, struct, sys, threading, time

mode, work = sys.argv[1:3]
def record(filename, value):
    with open(os.path.join(work, filename), 'a', encoding='utf-8') as output:
        output.write(json.dumps(value, sort_keys=True) + '\n')

def listen(port):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(16)
    return sock

def backend_connection(conn, tls):
    try:
        if tls:
            conn = context.wrap_socket(conn, server_side=True)
            alpn = conn.selected_alpn_protocol()
            version = conn.version()
        else:
            alpn = None
            version = None
        conn.settimeout(3)
        data = conn.recv(4096)
        if b'GET /probe ' not in data:
            raise ValueError('unexpected application request')
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nm4-probe')
        record('backend.jsonl', {'tls': tls, 'alpn': alpn, 'version': version})
    except Exception as exc:
        record('backend-errors.jsonl', {'error': str(exc)})
    finally:
        conn.close()

def relay(left, right):
    sockets = [left, right]
    try:
        while sockets:
            ready, _, _ = select.select(sockets, [], [], 4)
            if not ready:
                break
            for source in ready:
                data = source.recv(65536)
                if not data:
                    return
                target = right if source is left else left
                target.sendall(data)
    finally:
        left.close()
        right.close()

def proxy_connection(conn, listener_port):
    try:
        raw = conn.getsockopt(socket.SOL_IP, 80, 16)  # SO_ORIGINAL_DST
        family = struct.unpack_from('=H', raw, 0)[0]
        port = struct.unpack_from('!H', raw, 2)[0]
        address = socket.inet_ntop(socket.AF_INET, raw[4:8])
        if family != socket.AF_INET:
            raise ValueError('original destination was not IPv4')
        record('original-dst.jsonl', {'listener': listener_port, 'address': address, 'port': port})
        upstream = socket.create_connection((address, port), timeout=3)
        relay(conn, upstream)
    except Exception as exc:
        record('proxy-errors.jsonl', {'error': str(exc)})
        conn.close()

if mode == 'backend':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(os.path.join(work, 'leaf.crt'), os.path.join(work, 'leaf.key'))
    context.set_alpn_protocols(['h2', 'http/1.1'])
    listeners = {listen(80): False, listen(443): True}
    while True:
        ready, _, _ = select.select(listeners, [], [])
        for server in ready:
            conn, _ = server.accept()
            threading.Thread(target=backend_connection, args=(conn, listeners[server]), daemon=True).start()
elif mode == 'proxy':
    listeners = {listen(18080): 18080, listen(18443): 18443}
    while True:
        ready, _, _ = select.select(listeners, [], [])
        for server in ready:
            conn, _ = server.accept()
            threading.Thread(target=proxy_connection, args=(conn, listeners[server]), daemon=True).start()
elif mode == 'client':
    address, port, version, alpn = sys.argv[3], int(sys.argv[4]), sys.argv[5], sys.argv[6]
    sock = socket.create_connection((address, port), timeout=4)
    selected = None
    negotiated = None
    if version != 'plain':
        context = ssl.create_default_context(cafile=os.path.join(work, 'ca.crt'))
        context.minimum_version = context.maximum_version = getattr(ssl.TLSVersion, version)
        context.set_alpn_protocols([alpn])
        sock = context.wrap_socket(sock, server_hostname='probe.local')
        selected, negotiated = sock.selected_alpn_protocol(), sock.version()
        if selected != alpn:
            raise ValueError('ALPN mismatch: ' + str(selected))
    sock.sendall(b'GET /probe HTTP/1.1\r\nHost: probe.local\r\nConnection: close\r\n\r\n')
    response = bytearray()
    sock.settimeout(4)
    while True:
        part = sock.recv(4096)
        if not part:
            break
        response.extend(part)
    sock.close()
    if b'200 OK' not in response or not response.endswith(b'm4-probe'):
        raise ValueError('upstream did not receive and answer request')
    record('client.jsonl', {'destination': address, 'port': port, 'tls': negotiated, 'alpn': selected, 'ok': True})
else:
    raise ValueError('unknown netprobe mode')
PY

ip netns exec "$server" python3 "$work/netprobe.py" backend "$work" >"$work/backend.log" 2>&1 & backend_pid=$!
ip netns exec "$router" python3 "$work/netprobe.py" proxy "$work" >"$work/proxy.log" 2>&1 & proxy_pid=$!
for _ in {1..50}; do
  kill -0 "$backend_pid" 2>/dev/null && kill -0 "$proxy_pid" 2>/dev/null || { echo 'probe server exited' >&2; exit 1; }
  if ip netns exec "$server" ss -lnt | grep -q ':80 ' &&
     ip netns exec "$server" ss -lnt | grep -q ':443 ' &&
     ip netns exec "$router" ss -lnt | grep -q ':18080 ' &&
     ip netns exec "$router" ss -lnt | grep -q ':18443 '; then
    break
  fi
  sleep 0.1
done
ip netns exec "$router" ss -lnt | grep -q ':18080 ' || { echo 'proxy listener did not start' >&2; exit 1; }
ip netns exec "$client" timeout 10 python3 "$work/netprobe.py" client "$work" 10.251.0.2 80 plain none
ip netns exec "$client" timeout 10 python3 "$work/netprobe.py" client "$work" 10.251.0.2 443 TLSv1_2 http/1.1
ip netns exec "$client" timeout 10 python3 "$work/netprobe.py" client "$work" 10.251.0.2 443 TLSv1_3 h2
ip netns exec "$client" timeout 10 python3 "$work/netprobe.py" client "$work" 198.51.100.20 443 TLSv1_3 h2

# Keep the nft rules, restart only the proxy and prove the path still works.
kill "$proxy_pid"; wait "$proxy_pid" 2>/dev/null || true; proxy_pid=''
ip netns exec "$router" python3 "$work/netprobe.py" proxy "$work" >>"$work/proxy.log" 2>&1 & proxy_pid=$!
for _ in {1..50}; do
  ip netns exec "$router" ss -lnt | grep -q ':18080 ' && break
  kill -0 "$proxy_pid" 2>/dev/null || { echo 'proxy restart failed' >&2; exit 1; }
  sleep 0.1
done
ip netns exec "$router" ss -lnt | grep -q ':18080 ' || { echo 'proxy restart listener did not start' >&2; exit 1; }
ip netns exec "$client" timeout 10 python3 "$work/netprobe.py" client "$work" 10.251.0.2 80 plain none
python3 - "$work" <<'PY'
import json, pathlib, sys
work = pathlib.Path(sys.argv[1])
clients = [json.loads(x) for x in (work/'client.jsonl').read_text().splitlines()]
destinations = [json.loads(x) for x in (work/'original-dst.jsonl').read_text().splitlines()]
backend = [json.loads(x) for x in (work/'backend.jsonl').read_text().splitlines()]
if len(clients) != 5 or len(destinations) != 5 or len(backend) != 5:
    raise SystemExit('request/proxy/backend counts differ; redirect or recursion failed')
for row in destinations:
    expected_port = 80 if row['listener'] == 18080 else 443
    if (row['address'], row['port']) != ('10.251.0.2', expected_port):
        raise SystemExit('original destination did not resolve to post-DNAT upstream: ' + str(row))
if (work/'proxy-errors.jsonl').exists() or (work/'backend-errors.jsonl').exists():
    raise SystemExit('proxy/backend recorded an error')
print('PASS: TCP/80, TCP/443, post-DNAT original destination, non-recursive upstream, restart, CA/TLS/ALPN')
PY

# Private Suricata PCAP-mode worker: check availability and actual job drain.
mkdir -p "$work/suricata-output" "$work/suricata-log"
cat >"$work/suricata.yaml" <<EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.0.2.0/24]"
    EXTERNAL_NET: "any"
default-rule-path: $work
rule-files: []
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types: [alert, flow]
unix-command:
  enabled: yes
  filename: $work/suricata.sock
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
EOF
python3 - "$work/probe.pcap" <<'PY'
import struct, sys, time
def checksum(data):
    if len(data) % 2:
        data += b'\0'
    words = struct.unpack('!%dH' % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff
ethernet = bytes.fromhex('00112233445566778899aabb0800')
src, dst = bytes.fromhex('c0000202'), bytes.fromhex('c6336401')
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1, 0, 64, 6, 0, src, dst)
ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
tcp = struct.pack('!HHIIHHHH', 40000, 80, 1, 0, 0x5002, 65535, 0, 0)
pseudo = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
frame = ethernet + ip + tcp
with open(sys.argv[1], 'wb') as output:
    output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    output.write(struct.pack('<IIII', int(time.time()), 0, len(frame), len(frame)))
    output.write(frame)
PY
suricata -T -c "$work/suricata.yaml" >"$work/suricata-config.log" 2>&1
suricata --unix-socket="$work/suricata.sock" -c "$work/suricata.yaml" -l "$work/suricata-log" >"$work/suricata.log" 2>&1 & suricata_pid=$!
for _ in {1..80}; do
  [[ -S "$work/suricata.sock" ]] && break
  kill -0 "$suricata_pid" 2>/dev/null || { echo 'Suricata Unix-socket worker exited' >&2; exit 1; }
  sleep 0.1
done
[[ -S "$work/suricata.sock" ]] || { echo 'Suricata control socket unavailable' >&2; exit 1; }
timeout 20 python3 - "$work" <<'PY' >"$work/suricata-control.json"
import json, pathlib, socket, sys, time
work = pathlib.Path(sys.argv[1])
sock = socket.socket(socket.AF_UNIX)
sock.settimeout(3)
sock.connect(str(work/'suricata.sock'))
stream = sock.makefile('rb')
def exchange(value):
    sock.sendall((json.dumps(value)+'\n').encode())
    line = stream.readline()
    if not line:
        raise RuntimeError('Suricata closed the control socket')
    reply = json.loads(line)
    if reply.get('return') != 'OK':
        raise RuntimeError('Suricata rejected command: '+str(reply))
    return reply
exchange({'version': '0.1'})
commands = exchange({'command': 'command-list'})['message']
required = {'pcap-file', 'pcap-current', 'pcap-file-list', 'pcap-file-number'}
if not required.issubset(set(commands)):
    raise RuntimeError('required PCAP commands unavailable: '+str(required-set(commands)))
added = exchange({'command': 'pcap-file', 'arguments': {'filename': str(work/'probe.pcap'), 'output-dir': str(work/'suricata-output')}})
deadline = time.monotonic() + 10
observed = False
while time.monotonic() < deadline:
    current = exchange({'command': 'pcap-current'})['message']
    listed = exchange({'command': 'pcap-file-list'})['message']
    number = exchange({'command': 'pcap-file-number'})['message']
    count = listed.get('count', 0) if isinstance(listed, dict) else len(listed)
    observed = observed or bool(current) or int(number) > 0 or int(count) > 0 or any((work/'suricata-output').iterdir())
    if observed and not current and int(number) == 0 and int(count) == 0:
        print(json.dumps({'commands': sorted(required), 'enqueued': added, 'drained': True}, sort_keys=True))
        break
    time.sleep(0.05) # bounded queue-state poll, not a completion assumption
else:
    raise RuntimeError('PCAP job did not drain before deadline')
sock.close()
PY
echo 'PASS: Suricata Unix-socket PCAP commands and bounded queue drain'
echo 'M4 T01 capability probe PASS (capture evidence with --evidence-dir).'
