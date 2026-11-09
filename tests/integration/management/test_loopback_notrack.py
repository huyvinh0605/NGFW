#!/usr/bin/env python3
"""Exercise the real optional helper in disposable Linux network namespaces."""
import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time


def run(args, *, data=None, env=None, ok=True):
    result = subprocess.run(args, input=data, text=True, capture_output=True,
                            env=env, timeout=20)
    if ok and result.returncode:
        raise RuntimeError(f"{args}: {result.stderr}")
    return result


def inside(repo, client_ns, server_ns):
    if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        raise RuntimeError('Refusing to test in the host network namespace')
    checks = {}

    def check(name, value):
        checks[name] = bool(value)
        if not value:
            raise AssertionError(name)

    run(['ip', 'link', 'set', 'lo', 'up'])
    run(['nft', '-f', '-'], data='''table inet control {
 chain output { type filter hook output priority filter; policy accept;
  ct state established counter
 }
 set revoked { typeof ct id; }
 chain forward { type filter hook forward priority filter; policy drop;
  ct id @revoked counter drop
  ct state established,related counter accept
  tcp dport 8080 counter accept
 }
}
''')

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            body = b'isolated-api-ok'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    class V6Server(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6

    servers, connections = [], []
    origin = None
    with tempfile.TemporaryDirectory(prefix='ngfw-notrack-test-') as temporary:
        env = dict(os.environ, NGFW_API_LOOPBACK_RULES=str(repo / 'deploy/api-loopback-notrack.nft'),
                   NGFW_API_LOOPBACK_RUNTIME=temporary)

        def helper(action, **kwargs):
            return run(['bash', str(repo / 'scripts/api-loopback-notrack.sh'), action],
                       env=kwargs.pop('env', env), **kwargs)

        def flow(host='127.0.0.1', port=8080, source=None):
            connection = http.client.HTTPConnection(host, port, timeout=2,
                                                    source_address=source)
            connections.append(connection)
            connection.request('GET', '/probe')
            response = connection.getresponse()
            body = response.read()
            check('http_' + str(len(connections)), response.status == 200 and body == b'isolated-api-ok')
            local = connection.sock.getsockname()
            return connection, (local[0], local[1], host, port)

        def tracked(tuple_):
            src, sport, dst, dport = tuple_
            text = run(['conntrack', '-L', '-p', 'tcp']).stdout
            return f'src={src} dst={dst} sport={sport} dport={dport} ' in text

        try:
            for address, server_class in [(('127.0.0.1', 8080), http.server.ThreadingHTTPServer),
                                          (('127.0.0.1', 8081), http.server.ThreadingHTTPServer),
                                          (('127.0.0.2', 8080), http.server.ThreadingHTTPServer),
                                          (('::1', 8080), V6Server)]:
                server = server_class(address, Handler)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                servers.append(server)
            old, old_tuple = flow()
            check('baseline_is_tracked', tracked(old_tuple))
            refused = helper('apply', ok=False)
            check('refuses_live_tracked_socket', refused.returncode != 0 and 'Drain' in refused.stderr)
            check('refusal_did_not_add_table', 'ngfw_api_loopback_notrack' not in run(['nft', 'list', 'tables']).stdout)
            old.close()
            for _ in range(20):
                text = run(['conntrack', '-L', '-p', 'tcp']).stdout
                if not re.search(r' ESTABLISHED .*sport=' + str(old_tuple[1]) + r' dport=8080 ', text):
                    break
                time.sleep(.05)
            helper('apply')
            target, target_tuple = flow()
            check('target_not_tracked', not tracked(target_tuple))
            source_port = target.sock.getsockname()[1]
            target.request('GET', '/reuse')
            response = target.getresponse()
            check('keepalive_still_works', response.status == 200 and response.read() == b'isolated-api-ok'
                  and target.sock.getsockname()[1] == source_port)
            _, other_port = flow(port=8081)
            _, other_destination = flow(host='127.0.0.2')
            _, other_source = flow(source=('127.0.0.2', 0))
            _, ipv6 = flow(host='::1')
            check('other_port_tracked', tracked(other_port))
            check('other_destination_tracked', tracked(other_destination))
            check('other_source_tracked', tracked(other_source))
            check('ipv6_tracked', tracked(ipv6))
            check('old_closed_entry_retained', tracked(old_tuple))
            helper('apply')
            check('reload_idempotent', not tracked(flow()[1]))
            invalid = Path(temporary) / 'invalid.nft'
            invalid.write_text('this is invalid nft syntax\n')
            failed = helper('apply', env=dict(env, NGFW_API_LOOPBACK_RULES=str(invalid)), ok=False)
            check('invalid_update_rejected', failed.returncode != 0)
            check('failed_update_preserves_table', helper('status').returncode == 0 and not tracked(flow()[1]))

            # Real routed traffic to the same destination port must still use
            # stateful forwarding and a conntrack-ID revoke guard.
            for left, right, peer_ns, local_ip, peer_ip in [
                ('lc', 'cl', client_ns, '198.18.0.1/30', '198.18.0.2/30'),
                ('ls', 'sl', server_ns, '198.18.0.5/30', '198.18.0.6/30'),
            ]:
                run(['ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right])
                run(['ip', 'link', 'set', right, 'netns', peer_ns])
                run(['ip', 'addr', 'add', local_ip, 'dev', left])
                run(['ip', 'link', 'set', left, 'up'])
                for args in [['link', 'set', 'lo', 'up'], ['addr', 'add', peer_ip, 'dev', right],
                             ['link', 'set', right, 'up'], ['route', 'add', 'default', 'via', local_ip.split('/')[0]]]:
                    run(['ip', '-n', peer_ns] + args)
            run(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
            client_code = '''import http.client,json,sys
c=http.client.HTTPConnection('198.18.0.6',8080,timeout=1)
c.request('GET','/');r=c.getresponse();r.read();port=c.sock.getsockname()[1]
print(json.dumps({'status':r.status,'port':port}),flush=True)
sys.stdin.readline()
try:
 c.request('GET','/');r=c.getresponse();r.read();print(json.dumps({'second_status':r.status}),flush=True)
except Exception as e:print(json.dumps({'second_error':type(e).__name__}),flush=True)
c.close()
'''
            # Force HTTP/1.1 keep-alive at the origin for the revoke probe.
            server_code = 'import http.server; http.server.SimpleHTTPRequestHandler.protocol_version="HTTP/1.1"; http.server.ThreadingHTTPServer(("0.0.0.0",8080),http.server.SimpleHTTPRequestHandler).serve_forever()'
            origin = subprocess.Popen(['ip', 'netns', 'exec', server_ns, 'python3', '-u', '-c', server_code],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(.2)
            probe = subprocess.Popen(['ip', 'netns', 'exec', client_ns, 'python3', '-u', '-c', client_code],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            first = json.loads(probe.stdout.readline())
            check('forwarded_clean_http', first['status'] == 200)
            text = run(['conntrack', '-L', '-p', 'tcp', '-o', 'id']).stdout
            line = next(line for line in text.splitlines() if f'src=198.18.0.2 dst=198.18.0.6 sport={first["port"]} dport=8080 ' in line)
            ct_id = re.search(r'\bid=(\d+)', line).group(1)
            check('forwarded_conntrack_id_exists', bool(ct_id))
            run(['nft', '-f', '-'], data=f'add element inet control revoked {{ {ct_id} }}\n')
            probe.stdin.write('continue\n'); probe.stdin.flush()
            second = json.loads(probe.stdout.readline()); probe.wait(timeout=4)
            check('forwarded_revoke_guard_drops', second.get('second_error') in ['TimeoutError', 'ConnectionResetError'])
            clean = run(['ip', 'netns', 'exec', client_ns, 'python3', '-c', "import urllib.request; print(urllib.request.urlopen('http://198.18.0.6:8080/',timeout=2).status)"])
            check('other_forwarded_session_allowed', clean.stdout.strip() == '200')
            blocked = run(['ip', 'netns', 'exec', client_ns, 'python3', '-c', "import socket; socket.create_connection(('198.18.0.6',8082),timeout=.3)"], ok=False)
            check('forward_default_drop_retained', blocked.returncode != 0)

            for connection in connections:
                connection.close()
            helper('remove'); helper('remove')
            check('remove_idempotent', helper('status', ok=False).returncode != 0)
            _, restored = flow()
            check('tracking_restored_for_new_socket', tracked(restored))
            connections[-1].close()
            run(['nft', '-f', '-'], data='table inet ngfw_api_loopback_notrack {\n comment "foreign-owner"\n}\n')
            foreign_before = run(['nft', 'list', 'table', 'inet', 'ngfw_api_loopback_notrack']).stdout
            check('foreign_apply_refused', helper('apply', ok=False).returncode != 0)
            check('foreign_remove_refused', helper('remove', ok=False).returncode != 0)
            check('foreign_table_preserved', foreign_before == run(['nft', 'list', 'table', 'inet', 'ngfw_api_loopback_notrack']).stdout)
            print(json.dumps({'checks': checks, 'passed': sum(checks.values())}, indent=2))
        finally:
            for connection in connections:
                connection.close()
            for server in servers:
                server.shutdown(); server.server_close()
            if origin is not None:
                origin.terminate(); origin.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inside', nargs=2, metavar=('CLIENT_NS', 'SERVER_NS'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root; tests create disposable network namespaces.')
    repo = Path(__file__).resolve().parents[3]
    if args.inside:
        inside(repo, *args.inside)
        return
    prefix = 'ngfw-notrack-test-' + str(os.getpid())
    namespaces = [prefix, prefix + '-client', prefix + '-server']
    created = []
    try:
        for name in namespaces:
            run(['ip', 'netns', 'add', name]); created.append(name)
        result = run(['ip', 'netns', 'exec', namespaces[0], sys.executable, str(Path(__file__).resolve()), '--inside', *namespaces[1:]], ok=False)
        sys.stdout.write(result.stdout); sys.stderr.write(result.stderr)
        if result.returncode:
            raise SystemExit(result.returncode)
    finally:
        for name in reversed(created):
            run(['ip', 'netns', 'delete', name])


if __name__ == '__main__':
    main()
