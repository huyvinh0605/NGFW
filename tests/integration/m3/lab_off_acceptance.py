#!/usr/bin/env python3
"""M3-02 on the four-node VMware lab; requires NGFW_LAB_PASSWORD.

This runner changes no NGFW config. It validates its policy preconditions before
traffic, records real persistent TCP/TLS/NAT/cache evidence, and removes its
temporary servers, WAN host route, packet capture and nft trace table.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import shlex
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paramiko
import requests

HOSTS = {"ngfw": ("192.168.100.1", "huy"), "lan": ("192.168.10.10", "lan"),
         "wan": ("192.0.2.1", "wan"), "dmz": ("10.20.0.10", "dmz")}
LAN, WAN, DMZ, PUBLIC = "192.168.10.10", "192.0.2.1", "10.20.0.10", "192.0.2.2"
WAN_PORT, DENY_PORT = 18083, 18084


class SetupError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def now():
    return datetime.now(timezone.utc).isoformat()


def tcp_policy(config, source_zone, destination_zone, source, destination, port):
    """Only a setup check for the runner's IPv4 TCP probes, not enforcement."""
    def address_matches(selectors, value):
        return not selectors or any(ipaddress.ip_address(value) in
                                    ipaddress.ip_network(item, strict=False)
                                    for item in selectors)

    def service_matches(services):
        if not services:
            return True
        for service in services:
            protocol, _, ports = service.lower().partition(":")
            if protocol != "tcp" or not ports:
                continue
            ends = [int(part) for part in ports.split("-")]
            if ends[0] <= port <= ends[-1]:
                return True
        return False

    for rule in sorted(config.get("policies") or [], key=lambda rule: rule["priority"]):
        if not rule.get("enabled"):
            continue
        if rule.get("source_zones") and source_zone not in rule["source_zones"]:
            continue
        if rule.get("destination_zones") and destination_zone not in rule["destination_zones"]:
            continue
        if not address_matches(rule.get("source_addresses"), source):
            continue
        if not address_matches(rule.get("destination_addresses"), destination):
            continue
        if not service_matches(rule.get("services")):
            continue
        if (rule.get("applications") or rule.get("security_profile_id") or
                rule.get("minimum_risk") is not None or rule.get("maximum_risk") is not None):
            raise SetupError("probe overlaps an inspection/application policy")
        return rule["action"], rule["id"]
    return ("DROP" if config.get("default_deny") else "ALLOW"), None


def validate_policy_setup(config):
    if (config.get("inspection") or {}).get("enabled"):
        raise SetupError("M3 must be OFF")
    if (config.get("request_gate") or {}).get("enabled"):
        raise SetupError("M4 request gate must be OFF")
    expected = [
        ("lan-wan", ("lan", "wan", LAN, WAN, WAN_PORT), "ALLOW", False),
        ("wan-dmz", ("wan", "dmz", WAN, DMZ, 443), "ALLOW", False),
        ("wan-lan-default-deny", ("wan", "lan", WAN, LAN, DENY_PORT), "DROP", True),
    ]
    result = {}
    for name, args, wanted, must_be_default in expected:
        actual, matched = tcp_policy(config, *args)
        result[name] = {"expected": wanted, "actual": actual, "matched_rule": matched}
        if actual != wanted or (must_be_default and matched is not None):
            raise SetupError(f"{name} expects {wanted}"
                             f"{' from the default policy' if must_be_default else ''}, "
                             f"but config yields {actual} via {matched or 'default'}")
    return result


SERVER = r'''import argparse,json,ssl,time
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
p=argparse.ArgumentParser();p.add_argument('--bind');p.add_argument('--port',type=int)
p.add_argument('--log');p.add_argument('--ready');p.add_argument('--cert');p.add_argument('--key');a=p.parse_args()
class Handler(BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def do_GET(self):
  record={'time_ns':time.time_ns(),'peer_ip':self.client_address[0],
          'peer_port':self.client_address[1],'path':self.path}
  with open(a.log,'a') as f:f.write(json.dumps(record)+'\n');f.flush()
  body=json.dumps(record).encode();self.send_response(200)
  self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);self.wfile.flush()
 def log_message(self,*args):pass
s=ThreadingHTTPServer((a.bind,a.port),Handler);s.daemon_threads=True
if a.cert:
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
 context.load_cert_chain(a.cert,a.key);s.socket=context.wrap_socket(s.socket,server_side=True)
Path(a.ready).write_text('ready\n');s.serve_forever(poll_interval=.1)
'''

CLIENT = r'''import argparse,http.client,json,ssl,sys
p=argparse.ArgumentParser();p.add_argument('--host');p.add_argument('--port',type=int)
p.add_argument('--nonce');p.add_argument('--ca');p.add_argument('--once',action='store_true');a=p.parse_args()
c=(http.client.HTTPSConnection(a.host,a.port,context=ssl.create_default_context(cafile=a.ca),timeout=4)
   if a.ca else http.client.HTTPConnection(a.host,a.port,timeout=4))
try:
 for n in range(1,3):
  c.request('GET','/m3-off/'+a.nonce+'/'+str(n));r=c.getresponse();body=r.read()
  print(json.dumps({'status':r.status,'body':json.loads(body),'local':c.sock.getsockname(),
                    'peer':c.sock.getpeername(),'tls_version':c.sock.version() if a.ca else None}),flush=True)
  if a.once or sys.stdin.readline().strip()!='NEXT':break
finally:c.close()
'''


class Lab:
    def __init__(self, root, password):
        self.root, self.password = root, password
        self.ssh, self.units, self.clients, self.temp_nodes = {}, [], [], []
        self.http = requests.Session()
        self.http.trust_env = False
        self.commands = []
        self.remote = "/tmp/ngfw-m3-off-" + uuid.uuid4().hex[:12]
        self.trace_table = "ngfw_m3_off_" + self.remote.rsplit("-", 1)[1]
        self.route_added = self.trace_added = False

    def connect(self):
        for name, (host, user) in HOSTS.items():
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(host, username=user, password=self.password, timeout=8,
                               look_for_keys=False, allow_agent=False)
            except Exception as error:
                client.close()
                raise SetupError(f"{name} SSH unavailable: {error}") from error
            self.ssh[name] = client
        result = self.command("ngfw", "cat /etc/ngfw/ngfw.env", sudo=True, record=False)
        require(result["exit_code"] == 0, "cannot read lab API credential")
        token = next(line.split("=", 1)[1].strip().strip("\"'")
                     for line in result["stdout"].splitlines()
                     if line.startswith("NGFW_API_TOKEN="))
        self.http.headers["Authorization"] = "Bearer " + token

    def command(self, node, value, sudo=False, evidence=None, timeout=30, record=True):
        issued = "bash -lc " + shlex.quote(value)
        if sudo:
            issued = "sudo -S -p '' " + issued
        started = now()
        stdin, stdout, stderr = self.ssh[node].exec_command(issued, timeout=timeout)
        if sudo:
            stdin.write(self.password + "\n")
            stdin.flush()
            stdin.channel.shutdown_write()
        result = {"node": node, "command": value, "started_at": started,
                  "stdout": stdout.read().decode("utf-8", "replace"),
                  "stderr": stderr.read().decode("utf-8", "replace"),
                  "exit_code": stdout.channel.recv_exit_status(), "finished_at": now()}
        if evidence:
            write_json(self.root / evidence, result)
        if record:
            self.commands.append(result)
        return result

    def api(self, path, params=None, evidence=None):
        response = self.http.get("http://192.168.100.1:8080/api/v1" + path,
                                 params=params, timeout=8)
        result = {"path": path, "query": params, "status": response.status_code,
                  "response": response.json(), "captured_at": now()}
        if evidence:
            write_json(self.root / evidence, result)
        require(response.status_code == 200 and result["response"].get("success"),
                f"API {path} failed: {result}")
        return result["response"]["data"]

    def upload(self, node, name, value):
        with self.ssh[node].open_sftp() as sftp:
            with sftp.file(self.remote + "/" + name, "wb") as target:
                target.write(value if isinstance(value, bytes) else value.encode())
                target.chmod(0o600)

    def unit(self, node, suffix, argv):
        name = "ngfw-m3-off-" + self.remote.rsplit("-", 1)[1] + "-" + suffix
        self.units.append((node, name))
        command = "systemd-run --quiet --collect --unit=" + shlex.quote(name)
        command += " --property=RuntimeMaxSec=180 -- " + shlex.join(argv)
        result = self.command(node, command, sudo=True, evidence=suffix + "-start.json")
        require(result["exit_code"] == 0, f"cannot start {name}")
        return name

    def wait_ready(self, node, path):
        command = "for n in {1..50}; do test -s " + shlex.quote(path)
        command += " && exit 0; sleep .1; done; exit 1"
        require(self.command(node, command)["exit_code"] == 0, node + " fixture not ready")

    def client(self, node, host, port, nonce, ca=False):
        argv = ["python3", "-u", self.remote + "/client.py", "--host", host,
                "--port", str(port), "--nonce", nonce]
        if ca:
            argv += ["--ca", self.remote + "/origin.crt"]
        streams = self.ssh[node].exec_command("exec " + shlex.join(argv), timeout=15)
        self.clients.append(streams)
        return streams

    def observation(self, streams, name):
        line = streams[1].readline()
        if not line:
            raise RuntimeError("client exited before HTTP response: " + streams[2].read().decode())
        result = json.loads(line)
        write_json(self.root / name, result)
        require(result["status"] == 200, "fixture did not return HTTP 200")
        return result

    def session(self, source, destination, port, sport, label, view="original", after=None):
        query = {"source_ip": source, "destination_ip": destination, "protocol": "tcp",
                 "tuple_view": view, "page_size": 100}
        page = {}
        for _ in range(40):
            page = self.api("/sessions", query)
            matches = [item for item in page.get("items") or []
                       if item[view + "_tuple"]["dst_port"] == port
                       and item[view + "_tuple"]["src_port"] == sport]
            advanced = (after is None or (len(matches) == 1 and
                        matches[0]["bytes_original"] > after["bytes_original"] and
                        matches[0]["bytes_reply"] > after["bytes_reply"]))
            if len(matches) == 1 and matches[0].get("kernel_cache_verified") and advanced:
                write_json(self.root / (label + "-page.json"), page)
                return matches[0]
            time.sleep(.15)
        write_json(self.root / (label + "-page.json"), page)
        raise RuntimeError(label + ": no unique session with verified current kernel cache mark")

    def cleanup(self):
        errors = []

        def attempt(node, command):
            try:
                result = self.command(node, command, sudo=True)
            except Exception as error:
                errors.append({"node": node, "command": command, "error": str(error)})
                return
            if result["exit_code"] and "not loaded" not in result["stderr"]:
                errors.append(result)

        for stdin, stdout, stderr in self.clients:
            try:
                stdin.write("CLOSE\n")
                stdin.flush()
                stdin.channel.shutdown_write()
            except Exception:
                pass
        for node, name in reversed(self.units):
            attempt(node, "systemctl stop " + shlex.quote(name))
        if self.trace_added:
            attempt("ngfw", "nft delete table inet " + self.trace_table)
        if self.route_added:
            attempt("wan", "ip route del " + LAN + "/32 via " + PUBLIC)
        for node in self.temp_nodes:
            # The directory is unique to this run and contains only fixtures.
            attempt(node, "rm -f -- " + shlex.quote(self.remote) + "/*; rmdir -- "
                    + shlex.quote(self.remote))
        write_json(self.root / "cleanup.json", {"status": "FAIL" if errors else "PASS", "errors": errors})
        return not errors

    def close(self):
        for client in self.ssh.values():
            client.close()
        self.http.close()


def execute(root):
    if root.exists() and any(root.iterdir()):
        raise SetupError("evidence directory must be empty to preserve previous runs")
    root.mkdir(parents=True, exist_ok=True)
    lab = Lab(root, os.environ["NGFW_LAB_PASSWORD"])
    report = {"id": "M3-02", "status": "NOT_RUN", "started_at": now(), "checks": []}
    setup_done = False
    state = None
    nonce = uuid.uuid4().hex
    try:
        lab.connect()
        state = lab.api("/config", evidence="config-before.json")
        report["generation"] = state["version"]["version"]
        report["setup"] = validate_policy_setup(state["running"])
        health = lab.api("/inspection/health", evidence="inspection-health-before.json")
        if health.get("enabled") or health.get("status") != "disabled":
            raise SetupError("inspection coordinator is not disabled")
        stopped = lab.command("ngfw", "pgrep -x suricata || true; systemctl is-active ngfw-suricata-ids ngfw-suricata-ips || true",
                              sudo=True, evidence="sensor-state.json")
        if any(line.strip().isdigit() for line in stopped["stdout"].splitlines()) or "active\n" in stopped["stdout"].replace("inactive\n", ""):
            raise SetupError("a Suricata process/service is still active")
        for node in HOSTS:
            result = lab.command(node, "date -u +%s; ip -br -4 addr; ip -4 route; ss -H -lnt",
                                 evidence=node + "-state-before.json")
            if abs(int(result["stdout"].splitlines()[0]) - time.time()) > 5:
                raise SetupError(node + " clock differs by more than five seconds")
            created = lab.command(node, "mkdir -m 0700 -- " + shlex.quote(lab.remote))
            if created["exit_code"] != 0:
                raise SetupError(node + ": could not create unique fixture directory")
            lab.temp_nodes.append(node)
            lab.upload(node, "server.py", SERVER)
            lab.upload(node, "client.py", CLIENT)
        for node, port in [("wan", WAN_PORT), ("lan", DENY_PORT), ("dmz", 443)]:
            result = lab.command(node, "ss -H -lnt 'sport = :" + str(port) + "'")
            if result["stdout"].strip():
                raise SetupError(node + ": fixture port already in use: " + str(port))
        lab.command("ngfw", "nft -j list ruleset; conntrack -L -o extended,id; sha256sum /var/lib/ngfw/running.json /var/lib/ngfw/dataplane-applied.json",
                    sudo=True, evidence="kernel-before.json")
        cert = lab.command("dmz", "openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj /CN=m3-off.test "
                           "-addext subjectAltName=IP:" + PUBLIC + ",IP:" + DMZ + " -keyout "
                           + lab.remote + "/origin.key -out " + lab.remote + "/origin.crt",
                           evidence="origin-certificate-create.json")
        if cert["exit_code"] != 0:
            raise SetupError("cannot create synthetic DMZ TLS certificate")
        with lab.ssh["dmz"].open_sftp() as sftp:
            pem = sftp.file(lab.remote + "/origin.crt", "rb").read()
        (root / "origin.crt").write_bytes(pem)
        lab.upload("wan", "origin.crt", pem)
        for node, address, port in [("wan", WAN, WAN_PORT), ("lan", LAN, DENY_PORT), ("dmz", DMZ, 443)]:
            argv = ["python3", lab.remote + "/server.py", "--bind", address, "--port", str(port),
                    "--log", lab.remote + "/server.jsonl", "--ready", lab.remote + "/ready"]
            if node == "dmz":
                argv += ["--cert", lab.remote + "/origin.crt", "--key", lab.remote + "/origin.key"]
            lab.unit(node, node + "-origin", argv)
            lab.wait_ready(node, lab.remote + "/ready")
        trace = "table inet " + lab.trace_table + " { chain forward_trace { type filter hook forward priority -30; policy accept;\n"
        for source, destination, port in [(LAN, WAN, WAN_PORT), (WAN, DMZ, 443), (WAN, LAN, DENY_PORT)]:
            trace += f"ip saddr {source} ip daddr {destination} tcp dport {port} meta nftrace set 1\n"
        trace += "}\n}\n"
        lab.upload("ngfw", "trace.nft", trace)
        lab.unit("ngfw", "nft-trace", ["sh", "-c", "exec nft monitor trace > " + lab.remote + "/trace.txt"])
        rule = lab.command("ngfw", "nft --check -f " + lab.remote + "/trace.nft && nft -f "
                           + lab.remote + "/trace.nft", sudo=True)
        require(rule["exit_code"] == 0, "cannot install diagnostic trace table")
        lab.trace_added = True
        capture_filter = (f"tcp and ((host {WAN} and port {WAN_PORT}) or "
                          f"(host {WAN} and host {PUBLIC} and port 8443) or "
                          f"(host {WAN} and host {DMZ} and port 443) or "
                          f"(host {WAN} and host {LAN} and port {DENY_PORT}))")
        lab.unit("ngfw", "pcap", ["tcpdump", "-ni", "any", "-s", "0", "-U", "-c", "500", "-Z", "root",
                                  "-w", lab.remote + "/traffic.pcap", capture_filter])
        time.sleep(.2)
        setup_done = True
        for label, node, source, destination, port, translated_source, translated_destination, translated_port in [
            ("masquerade", "lan", LAN, WAN, WAN_PORT, PUBLIC, WAN, WAN_PORT),
            ("dnat", "wan", WAN, PUBLIC, 8443, WAN, DMZ, 443),
        ]:
            streams = lab.client(node, destination, port, nonce + "-" + label, ca=(label == "dnat"))
            first = lab.observation(streams, label + "-client-first.json")
            sport = first["local"][1]
            initial = lab.session(source, destination, port, sport, label + "-first")
            require(initial["state"] == "ESTABLISHED" and initial["decision"] == "ALLOW", label + " not established/allowed")
            require(initial["policy_generation"] == report["generation"], label + " policy generation stale")
            nat = initial["nat"]
            require(bool(nat.get("snat")) == (label == "masquerade") and bool(nat.get("dnat")) == (label == "dnat"), label + " NAT flags wrong")
            require(initial["translated_tuple"]["src_ip"] == translated_source and
                    initial["translated_tuple"]["dst_ip"] == translated_destination and
                    initial["translated_tuple"]["dst_port"] == translated_port, label + " translated tuple wrong")
            require(first["body"]["peer_ip"] == translated_source, label + " destination observed wrong source")
            streams[0].write("NEXT\n")
            streams[0].flush()
            second = lab.observation(streams, label + "-client-second.json")
            require(first["local"] == second["local"], label + " reconnected instead of reusing the TCP flow")
            updated = lab.session(source, destination, port, sport, label + "-second", after=initial)
            require(updated["session_id"] == initial["session_id"] and
                    updated["identity"]["conntrack_id"] == initial["identity"]["conntrack_id"], label + " duplicated session/CT ID")
            require(updated["bytes_original"] > initial["bytes_original"] and updated["bytes_reply"] > initial["bytes_reply"], label + " byte counters did not advance both directions")
            alias = lab.session(translated_source, translated_destination, translated_port,
                                updated["translated_tuple"]["src_port"], label + "-translated", "translated")
            require(alias["session_id"] == initial["session_id"], label + " translated alias is a different session")
            lab.command("ngfw", f"conntrack -L -p tcp --orig-src {source} --orig-dst {destination} --sport {sport} --dport {port} -o extended,id",
                        sudo=True, evidence=label + "-conntrack.json")
            report["checks"].append({"name": label, "status": "PASS", "session_id": initial["session_id"],
                                     "conntrack_id": initial["identity"]["conntrack_id"], "kernel_cache_verified": True,
                                     "same_socket": True, "tls_version": first.get("tls_version")})
            streams[0].write("CLOSE\n")
            streams[0].flush()
        control = lab.command("lan", shlex.join(["python3", lab.remote + "/client.py", "--host", LAN,
                              "--port", str(DENY_PORT), "--nonce", nonce + "-control", "--once"]),
                              evidence="deny-listener-positive-control.json")
        require(control["exit_code"] == 0, "LAN deny target is not serving the positive control")
        routes = lab.command("wan", "ip -4 route show exact " + LAN + "/32", evidence="wan-host-route-before.json")
        if not routes["stdout"].strip():
            result = lab.command("wan", "ip route add " + LAN + "/32 via " + PUBLIC, sudo=True,
                                 evidence="wan-host-route-add.json")
            require(result["exit_code"] == 0, "cannot route the WAN probe through NGFW")
            lab.route_added = True
        elif "via " + PUBLIC not in routes["stdout"]:
            raise SetupError("WAN host route does not use the NGFW")
        blocked = lab.command("wan", shlex.join(["python3", lab.remote + "/client.py", "--host", LAN,
                              "--port", str(DENY_PORT), "--nonce", nonce + "-denied", "--once"]),
                              evidence="wan-lan-default-deny-client.json", timeout=10)
        require(blocked["exit_code"] != 0, "WAN-to-LAN unexpectedly reached the server")
        for node in ["wan", "dmz", "lan"]:
            lab.command(node, "cat " + lab.remote + "/server.jsonl", sudo=True,
                        evidence=node + "-server-log.json")
        lanlog = json.loads((root / "lan-server-log.json").read_text())["stdout"]
        require(nonce + "-control" in lanlog and nonce + "-denied" not in lanlog,
                "default-denied request reached LAN application")
        # Flush capture output before retrieving evidence.
        for node, unit in lab.units[-2:]:
            lab.command(node, "systemctl stop " + shlex.quote(unit), sudo=True)
        trace_result = lab.command("ngfw", "cat " + lab.remote + "/trace.txt", sudo=True, evidence="nft-trace.json")
        (root / "nft-trace.txt").write_text(trace_result["stdout"], encoding="utf-8")
        require("inet ngfw forward policy drop" in trace_result["stdout"], "no default DROP verdict in kernel trace")
        require("inet ngfw forward rule ct state established ct mark" in trace_result["stdout"], "no M2 cache acceptance in kernel trace")
        lab.command("ngfw", "chmod 0644 " + lab.remote + "/traffic.pcap", sudo=True)
        with lab.ssh["ngfw"].open_sftp() as sftp:
            sftp.get(lab.remote + "/traffic.pcap", str(root / "traffic.pcap"))
        lab.command("ngfw", "tcpdump -nn -tttt -r " + lab.remote + "/traffic.pcap",
                    sudo=True, evidence="packet-capture-decoded.json")
        report["checks"].append({"name": "default-deny", "status": "PASS", "positive_control": True,
                                 "kernel_default_drop_trace": True, "denied_nonce_at_server": False})
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "NOT_RUN" if isinstance(error, SetupError) or not setup_done else "FAIL"
        report["error"] = str(error)
    finally:
        if setup_done and report["status"] != "PASS":
            try:
                lab.api("/health", evidence="failure-health.json")
                lab.api("/sessions", {"page_size": 100}, evidence="failure-sessions.json")
                lab.command("ngfw", "conntrack -L -o extended,id; cat " + lab.remote + "/trace.txt",
                            sudo=True, evidence="failure-kernel-and-trace.json")
                for node in ["wan", "dmz", "lan"]:
                    lab.command(node, "cat " + lab.remote + "/server.jsonl", sudo=True,
                                evidence=node + "-server-log-at-failure.json")
                for node, unit in lab.units[-2:]:
                    lab.command(node, "systemctl stop " + shlex.quote(unit), sudo=True)
                lab.command("ngfw", "chmod 0644 " + lab.remote + "/traffic.pcap", sudo=True)
                with lab.ssh["ngfw"].open_sftp() as sftp:
                    sftp.get(lab.remote + "/traffic.pcap", str(root / "traffic-at-failure.pcap"))
            except Exception as error:
                report["diagnostic_error"] = str(error)
        try:
            if not lab.cleanup():
                report.update(status="FAIL", cleanup_error="temporary state cleanup failed")
            if state is not None:
                final = lab.api("/config", evidence="config-after.json")
                require(final == state, "Running/Candidate/config state changed during test")
                check = lab.command("ngfw", "set -e; /usr/local/lib/ngfw/ngfw-engine --verify-network --state-dir /var/lib/ngfw; "
                                    "systemctl is-active ngfw-engine ngfw-api ngfw-proxy; "
                                    "sha256sum /var/lib/ngfw/running.json /var/lib/ngfw/dataplane-applied.json; nft -j list ruleset",
                                    sudo=True, evidence="kernel-after-cleanup.json")
                require(check["exit_code"] == 0, "final network/service verification failed")
                report["config_unchanged"] = True
        except Exception as error:
            report.update(status="FAIL", cleanup_error=str(error))
        report["finished_at"] = now()
        report["source_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        write_json(root / "result.json", report)
        write_json(root / "commands.json", lab.commands)
        lab.close()
        print(json.dumps(report), flush=True)
    return 0 if report["status"] == "PASS" else (2 if report["status"] == "NOT_RUN" else 1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    arguments = parser.parse_args()
    raise SystemExit(execute(arguments.evidence_dir))
