#!/usr/bin/env python3
"""Reversible Ubuntu VM acceptance runner for M4 HTTPS/TLS cases.

Requires NGFW_LAB_PASSWORD, Paramiko, Requests and a local Go toolchain.
Health counters are observed after the request's engine timestamp, allowing
the next periodic heartbeat to arrive without accepting another generation.
The tls-continuation suite covers M4-09 onward and stops on the first failure.
"""

import argparse
import copy
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko
import requests

from health_poll import HealthObservationError, wait_for_health_counters


HOSTS = {
    "ngfw": ("192.168.100.1", "huy"),
    "lan": ("192.168.10.10", "lan"),
    "dmz": ("10.20.0.10", "dmz"),
}
API = "http://192.168.100.1:8080/api/v1"
REPO_ROOT = Path(__file__).resolve().parents[3]


def json_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class Lab:
    def __init__(self, evidence, password):
        self.evidence = evidence
        self.password = password
        self.commands = []
        self.ssh = {}
        self.http = requests.Session()
        self.http.trust_env = False
        try:
            for name, (host, user) in HOSTS.items():
                client = paramiko.SSHClient()
                self.ssh[name] = client
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, username=user, password=password, timeout=8,
                               look_for_keys=False, allow_agent=False)
        except Exception:
            self.close()
            raise

    def close(self):
        for client in self.ssh.values():
            client.close()
        self.http.close()

    def command(self, host, command, *, sudo=False, timeout=30, evidence=None, save=True):
        issued = ("sudo -S -p '' " if sudo else "") + command
        stdin, stdout, stderr = self.ssh[host].exec_command(issued, timeout=timeout)
        if sudo:
            stdin.write(self.password + "\n")
            stdin.flush()
            stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        result = {
            "command": command,
            "sudo": sudo,
            "exit_code": stdout.channel.recv_exit_status(),
            "stdout": out,
            "stderr": err,
        }
        if evidence:
            json_write(self.evidence / evidence, result)
        if save:
            self.commands.append({"host": host, **result})
        return result

    def api(self, method, path, *, payload=None, evidence=None, timeout=90):
        response = self.http.request(method, API + path, json=payload, timeout=timeout)
        try:
            body = response.json()
        except ValueError:
            body = {"body": response.text[:2000]}
        result = {"method": method, "path": path, "status": response.status_code, "response": body}
        if evidence:
            json_write(self.evidence / evidence, result)
        return result

    def upload_bytes(self, host, path, value, mode):
        sftp = self.ssh[host].open_sftp()
        try:
            with sftp.file(path, "wb") as target:
                target.write(value)
                target.chmod(mode)
        finally:
            sftp.close()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def server_source():
    return '''#!/usr/bin/env python3
import argparse, hashlib, json, logging, socket, ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

parser = argparse.ArgumentParser()
parser.add_argument("--cert", required=True)
parser.add_argument("--key", required=True)
parser.add_argument("--log", required=True)
parser.add_argument("--require-client-cert", action="store_true")
parser.add_argument("--ca")
parser.add_argument("--client-auth", choices=("none", "optional", "required"), default="none")
parser.add_argument("--tls-version", choices=("auto", "1.2", "1.3"), default="auto")
parser.add_argument("--close-after-handshake", action="store_true")
args = parser.parse_args()
logging.basicConfig(filename=args.log, level=logging.INFO, format="%(message)s")

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self): self.respond()
    def do_POST(self): self.respond()
    def respond(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []; total = 0
            while True:
                line = self.rfile.readline(64)
                size = int(line.split(b";", 1)[0].strip(), 16)
                if size == 0:
                    while self.rfile.readline(8192).strip(): pass
                    break
                total += size
                if total > 1048576: raise ValueError("fixture body limit")
                chunk = self.rfile.read(size)
                if len(chunk) != size or self.rfile.read(2) != b"\\r\\n": raise ValueError("invalid fixture chunk")
                chunks.append(chunk)
            data = b"".join(chunks)
        else:
            length = int(self.headers.get("Content-Length", "0"))
            data = self.rfile.read(min(length, 1048576)) if length else b""
        path = urlsplit(self.path).path
        marker = path.rsplit("/", 1)[-1]
        logging.info(json.dumps({"method": self.command, "path": path,
                                 "marker": marker, "body_bytes": len(data),
                                 "body_sha256": hashlib.sha256(data).hexdigest(),
                                 "http_version": self.request_version,
                                 "tls_version": self.connection.version(),
                                 "client_certificate": bool(self.connection.getpeercert())}))
        body = json.dumps({"origin": "m4-https-acceptance", "marker": marker}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args): pass

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
if args.tls_version != "auto":
    version = ssl.TLSVersion.TLSv1_2 if args.tls_version == "1.2" else ssl.TLSVersion.TLSv1_3
    context.minimum_version = context.maximum_version = version
context.set_alpn_protocols(["http/1.1"])
context.load_cert_chain(args.cert, args.key)
if args.require_client_cert or args.client_auth != "none":
    context.load_verify_locations(args.ca)
    context.verify_mode = ssl.CERT_REQUIRED if args.require_client_cert or args.client_auth == "required" else ssl.CERT_OPTIONAL
class Server(ThreadingHTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        if args.close_after_handshake:
            connection.shutdown(socket.SHUT_RDWR)
            connection.close()
            raise OSError("synthetic connection close after completed TLS handshake")
        return connection, address
server = Server(("0.0.0.0", 443), Handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
'''


def client_source():
    return '''package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type result struct {
	Method string `json:"method"`
	Path string `json:"path"`
	Status int `json:"status"`
	ResponseBody string `json:"response_body"`
	TLSVerified bool `json:"tls_verified"`
	VerifiedChainCount int `json:"verified_chain_count"`
	TLSVersion string `json:"tls_version"`
	ALPN string `json:"alpn"`
	HTTPProtocol string `json:"http_protocol"`
	PeerCommonName string `json:"peer_common_name"`
	PeerDNSNames []string `json:"peer_dns_names"`
	PeerNotBefore time.Time `json:"peer_not_before"`
	PeerNotAfter time.Time `json:"peer_not_after"`
	PeerSHA256 string `json:"peer_sha256"`
	BodySHA256 string `json:"body_sha256"`
	LocalAddress string `json:"local_address"`
	ClientHelloChunks int `json:"client_hello_chunks"`
}

func main() {
	ip := flag.String("ip", "10.20.0.10", "original destination IP")
	host := flag.String("host", "dmz-m4.test", "TLS hostname and HTTP Host")
	port := flag.Int("port", 443, "original destination port")
	path := flag.String("path", "/", "request path")
	method := flag.String("method", "GET", "HTTP method")
	body := flag.String("body", "", "synthetic request body")
	marker := flag.String("marker", "", "synthetic request marker")
	caPath := flag.String("ca", "", "trusted test CA certificate")
	verifyUnix := flag.Int64("verify-unix", 0, "UTC time used for certificate validity checks")
	splitHello := flag.Bool("split-hello", false, "split first TLS write across TCP writes")
	pin := flag.String("pin-sha256", "", "require this DER leaf fingerprint in addition to CA/SAN")
	useHTTP2 := flag.Bool("http2", false, "negotiate and require HTTP/2")
	flag.Parse()

	pem, err := os.ReadFile(*caPath)
	if err != nil { fail(err) }
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) { failString("test CA certificate could not be loaded") }
	verifyTime := time.Unix(*verifyUnix, 0).UTC()
	protocols := []string{"http/1.1"}
	if *useHTTP2 { protocols = []string{"h2", "http/1.1"} }
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: *host,
		NextProtos: protocols}
	if *verifyUnix != 0 { tlsConfig.Time = func() time.Time { return verifyTime } }
	if *pin != "" {
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || fmt.Sprintf("%x", sha256.Sum256(state.PeerCertificates[0].Raw)) != *pin {
				return fmt.Errorf("TLS_PIN_MISMATCH")
			}
			return nil
		}
	}
	var localAddress string
	var split *splitConn
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		ForceAttemptHTTP2: *useHTTP2,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(*ip, strconv.Itoa(*port)))
			if err == nil {
				localAddress = conn.LocalAddr().String()
				if *splitHello { split = &splitConn{Conn: conn}; return split, nil }
			}
			return conn, err
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	req, err := http.NewRequest(*method, "https://" + *host + *path, strings.NewReader(*body))
	if err != nil { fail(err) }
	req.Header.Set("X-M4-Marker", *marker)
	if *method == "POST" { req.Header.Set("Content-Type", "application/x-www-form-urlencoded") }
	resp, err := client.Do(req)
	if err != nil { fail(err) }
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil { fail(err) }
	r := result{Method: *method, Path: *path, Status: resp.StatusCode, ResponseBody: string(responseBody), HTTPProtocol: resp.Proto}
	r.LocalAddress = localAddress
	r.BodySHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(*body)))
	if split != nil { r.ClientHelloChunks = split.chunks }
	if resp.TLS != nil {
		r.TLSVerified = len(resp.TLS.VerifiedChains) > 0
		r.VerifiedChainCount = len(resp.TLS.VerifiedChains)
		r.TLSVersion = tls.VersionName(resp.TLS.Version)
		r.ALPN = resp.TLS.NegotiatedProtocol
		if len(resp.TLS.PeerCertificates) > 0 {
			leaf := resp.TLS.PeerCertificates[0]
			r.PeerSHA256 = fmt.Sprintf("%x", sha256.Sum256(leaf.Raw))
			r.PeerCommonName = leaf.Subject.CommonName
			r.PeerDNSNames = leaf.DNSNames
			r.PeerNotBefore = leaf.NotBefore
			r.PeerNotAfter = leaf.NotAfter
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil { fail(err) }
}

type splitConn struct { net.Conn; first bool; chunks int }
func (c *splitConn) Write(data []byte) (int, error) {
	if c.first { return c.Conn.Write(data) }
	c.first = true
	written := 0
	for _, limit := range []int{2, 5, 11, 37, 113, 271, len(data)} {
		if limit > len(data) { limit = len(data) }
		if limit <= written { continue }
		n, err := c.Conn.Write(data[written:limit]); written += n; c.chunks++
		if err != nil { return written, err }
		time.Sleep(30*time.Millisecond)
	}
	return written, nil
}

func fail(err error) { failString(err.Error()) }
func failString(message string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": message})
	os.Exit(1)
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--suite", choices=("https", "tls-continuation", "mtls-recheck", "h2-clean", "h2-isolation", "body-limits"), default="https")
    args = parser.parse_args()
    password = os.environ.get("NGFW_LAB_PASSWORD")
    require(bool(password), "NGFW_LAB_PASSWORD is required")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ").lower()
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    remote_dir = "/var/lib/ngfw/ca/m4-acceptance-" + run_id
    remote_dmz_dir = "/tmp/ngfw-m4-https-" + run_id
    remote_lan_dir = "/tmp/ngfw-m4-https-" + run_id
    origin_unit = "ngfw-m4-https-" + run_id.replace("z", "")
    dropin_dir = "/run/systemd/system/ngfw-proxy.service.d"
    dropin_path = dropin_dir + "/90-m4-acceptance-" + run_id + ".conf"
    local_dropin = "/tmp/ngfw-proxy-acceptance-" + run_id + ".conf"
    runtime_envfile = "/run/ngfw-proxy-acceptance-" + run_id + ".env"
    local_envfile = "/tmp/ngfw-proxy-acceptance-" + run_id + ".env"
    ca_cert = remote_dir + "/ca.crt"
    ca_key = remote_dir + "/ca.key"
    origin_key = remote_dir + "/origin.key"
    origin_csr = remote_dir + "/origin.csr"
    origin_cert = remote_dir + "/origin.crt"
    origin_ext = remote_dir + "/origin.ext"
    serial_file = remote_dir + "/origin.srl"
    dmz_log = remote_dmz_dir + "/origin.jsonl"
    lan_ca = remote_lan_dir + "/ca.crt"
    lan_client = remote_lan_dir + "/m4-https-client"
    env_names = ["NGFW_PROXY_CA_CERT", "NGFW_PROXY_CA_KEY", "NGFW_PROXY_UPSTREAM_CA"]
    report = {
        "run_id": run_id,
        "started_at": utc_now(),
        "scenarios": {},
        "status": "RUNNING",
        "restored": False,
    }
    json_write(evidence / "run-start.json", report)
    lab = None
    token = None
    baseline = None
    original_candidate = None
    original_version = None
    ca_created = False
    dropin_set = False
    runtime_envfile_set = False
    dropin_dir_existed = False
    profile_id = "m4-lab-https-" + run_id[-6:]
    policy_id = "m4-lab-https-policy-" + run_id[-6:]

    try:
        lab = Lab(evidence, password)

        env = lab.command("ngfw", "cat /etc/ngfw/ngfw.env", sudo=True, save=False)
        require(env["exit_code"] == 0, "SETUP: could not read NGFW management env")
        for line in env["stdout"].splitlines():
            if line.startswith("NGFW_API_TOKEN="):
                token = line.split("=", 1)[1].strip().strip("\"'")
                break
        require(bool(token), "SETUP: NGFW_API_TOKEN is absent")
        lab.http.headers["Authorization"] = "Bearer " + token

        services = lab.command("ngfw", "systemctl is-active ngfw-engine ngfw-api ngfw-proxy", evidence="preflight-services.json")
        require(services["exit_code"] == 0 and services["stdout"].splitlines() == ["active", "active", "active"],
                "SETUP: required NGFW services are not all active")
        config_reply = lab.api("GET", "/config", evidence="pretest-config.json")
        require(config_reply["status"] == 200, "SETUP: authenticated /config query failed")
        state = config_reply["response"]["data"]
        baseline = copy.deepcopy(state["running"])
        original_candidate = copy.deepcopy(state["candidate"])
        original_version = state["version"]["version"]
        require(not (baseline.get("request_gate") or {}).get("enabled", False), "SETUP: M4 is already enabled")
        require(state.get("candidate_valid") is True, "SETUP: the pre-existing Candidate is invalid")
        health = lab.api("GET", "/request-gate/health", evidence="pretest-health.json")
        require(health["status"] == 200 and health["response"]["data"].get("enabled") is False,
                "SETUP: M4 health is not disabled before the test")

        clock_snapshot = {}
        for name in HOSTS:
            clock = lab.command(name, "date -u +%Y-%m-%dT%H:%M:%S.%NZ", save=False)
            clock_snapshot[name] = clock["stdout"].strip()
        report["vm_utc_clocks"] = clock_snapshot
        json_write(evidence / "pretest-clock-snapshot.json", clock_snapshot)

        for name, command in [
            ("installed-binary-sha256.json", "sha256sum /usr/local/lib/ngfw/ngfw-engine /usr/local/lib/ngfw/ngfw-api /usr/local/lib/ngfw/ngfw-proxy"),
            ("kernel-version.json", "uname -r"),
            ("nft-version.json", "nft --version"),
            ("suricata-version.json", "suricata -V"),
            ("go-version-vm.json", "go version"),
        ]:
            lab.command("ngfw", command, sudo=True, evidence=name)
        source_files = [
            "go.mod", "go.sum", "internal/proxy/runtime.go", "internal/proxy/runtime_factory.go",
            "internal/proxy/gate_connection.go", "internal/proxy/gate_stats.go", "internal/proxy/http1_gate.go",
            "internal/engine/gate_runtime.go", "internal/engine/request_gate_runtime.go",
            "tests/integration/m4/lab_https_acceptance.py", "tests/integration/m4/health_poll.py",
            "tests/integration/m4/lab_tls_cases.py", "internal/proxy/clienthello.go",
            "internal/proxy/upstream_tls.go", "internal/engine/gate_service.go",
            "internal/proxy/request_result.go", "internal/engine/gate_result.go",
            "internal/domain/request_gate.go", "tests/integration/m4/lab_mtls_cases.py",
        ]
        json_write(evidence / "source-sha256.json", {
            path: hashlib.sha256((REPO_ROOT / path).read_bytes()).hexdigest() for path in source_files})

        if args.suite == "body-limits":
            from lab_body_cases import body_client_source
            binary = evidence / "m4-body-client.py"
            binary.write_bytes(body_client_source().encode("utf-8"))
            source_files.append("tests/integration/m4/lab_body_cases.py")
            json_write(evidence / "source-sha256.json", {
                path: hashlib.sha256((REPO_ROOT / path).read_bytes()).hexdigest() for path in source_files})
            json_write(evidence / "client-build.json", {"command": "Python stdlib verified TLS wire client", "exit_code": 0})
        else:
            go_source = evidence / "m4_https_client.go"
            if args.suite == "h2-isolation":
                from lab_h2_cases import h2_client_source
                source = h2_client_source()
                source_files.append("tests/integration/m4/lab_h2_cases.py")
                json_write(evidence / "source-sha256.json", {
                    path: hashlib.sha256((REPO_ROOT / path).read_bytes()).hexdigest() for path in source_files})
            else:
                source = client_source()
            go_source.write_text(source, encoding="utf-8")
            binary = evidence / "m4-https-client-linux-amd64"
            build_env = dict(os.environ)
            build_env.update({"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"})
            build = subprocess.run(["go", "build", "-trimpath", "-o", str(binary), str(go_source)],
                                   cwd=str(REPO_ROOT), env=build_env,
                                   capture_output=True, text=True, timeout=90)
            json_write(evidence / "client-build.json", {"command": "GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath",
                                                          "exit_code": build.returncode,
                                                          "stdout": build.stdout, "stderr": build.stderr})
            require(build.returncode == 0, "SETUP: could not build the Linux HTTPS trust client")

        manager_env = lab.command("ngfw", "systemctl show-environment", save=False)
        require(manager_env["exit_code"] == 0, "SETUP: could not inspect systemd manager environment")
        existing_overrides = [line.split("=", 1)[0] for line in manager_env["stdout"].splitlines()
                              if any(line.startswith(name + "=") for name in env_names)]
        json_write(evidence / "pretest-ca-overrides.json", {"m4_ca_variables_present": existing_overrides})
        require(not existing_overrides, "SETUP: an M4 CA override already exists in systemd manager environment")
        proxy_env = lab.command("ngfw", "grep -nE '^NGFW_PROXY_(CA_CERT|CA_KEY|UPSTREAM_CA)=' /etc/ngfw/proxy.env", sudo=True, save=False)
        require(proxy_env["exit_code"] in (0, 1), "SETUP: could not inspect /etc/ngfw/proxy.env")
        existing_proxy_vars = [line.split("=", 1)[0].split(":", 1)[-1] for line in proxy_env["stdout"].splitlines()]
        json_write(evidence / "pretest-proxy-ca-variable-names.json", {"variables_already_configured": existing_proxy_vars})
        dropin_exists = lab.command("ngfw", "test ! -e " + shlex.quote(dropin_path), sudo=True)
        require(dropin_exists["exit_code"] == 0, "SETUP: unique proxy systemd drop-in path already exists")
        envfile_exists = lab.command("ngfw", "test ! -e " + shlex.quote(runtime_envfile), sudo=True)
        require(envfile_exists["exit_code"] == 0, "SETUP: unique proxy runtime environment file already exists")
        dropin_dir_probe = lab.command("ngfw", "test -d " + shlex.quote(dropin_dir), sudo=True)
        dropin_dir_existed = dropin_dir_probe["exit_code"] == 0
        for path in [remote_dir, ca_cert, ca_key]:
            result = lab.command("ngfw", "test ! -e " + shlex.quote(path), sudo=True)
            require(result["exit_code"] == 0, "SETUP: unique CA path already exists: " + path)
        dmz_port = lab.command("dmz", "ss -lntp sport = :443", sudo=True, save=False)
        require(dmz_port["exit_code"] == 0 and len(dmz_port["stdout"].splitlines()) <= 1,
                "SETUP: DMZ TCP/443 is already occupied")

        made_dir = lab.command("ngfw", "install -d -o ngfw-proxy -g ngfw-proxy -m 0700 " + shlex.quote(remote_dir), sudo=True)
        require(made_dir["exit_code"] == 0, "SETUP: could not create isolated temporary CA directory")
        ca_created = True
        init_cmd = "-u ngfw-proxy env NGFW_PROXY_CA_CERT=" + shlex.quote(ca_cert) + " NGFW_PROXY_CA_KEY=" + shlex.quote(ca_key) + " /usr/local/lib/ngfw/ngfw-proxy ca init"
        init = lab.command("ngfw", init_cmd, sudo=True, evidence="ca-init.json")
        require(init["exit_code"] == 0 and re.fullmatch(r"[0-9a-fA-F]{64}\s*", init["stdout"]), "SETUP: temporary M4 CA initialization failed")
        ca_created = True
        fingerprint = init["stdout"].strip()
        report["ca_fingerprint_sha256"] = fingerprint

        req_cmd = ("-u ngfw-proxy openssl req -newkey rsa:2048 -nodes -keyout " + shlex.quote(origin_key) +
                   " -out " + shlex.quote(origin_csr) + " -subj /CN=dmz-m4.test")
        req = lab.command("ngfw", req_cmd + " >/dev/null 2>&1", sudo=True)
        require(req["exit_code"] == 0, "SETUP: could not generate HTTPS origin key/CSR")
        ext_contents = "subjectAltName=DNS:dmz-m4.test,DNS:api.dmz-m4.test,IP:10.20.0.10\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n"
        ext_command = "-u ngfw-proxy sh -c " + shlex.quote("printf %s " + shlex.quote(ext_contents) + " > " + shlex.quote(origin_ext))
        ext_result = lab.command("ngfw", ext_command, sudo=True)
        require(ext_result["exit_code"] == 0, "SETUP: could not write origin certificate extensions")
        sign_cmd = ("-u ngfw-proxy openssl x509 -req -in " + shlex.quote(origin_csr) +
                    " -CA " + shlex.quote(ca_cert) + " -CAkey " + shlex.quote(ca_key) +
                    " -CAcreateserial -CAserial " + shlex.quote(serial_file) +
                    " -days 2 -sha256 -extfile " + shlex.quote(origin_ext) + " -out " + shlex.quote(origin_cert))
        signed = lab.command("ngfw", sign_cmd + " >/dev/null 2>&1", sudo=True)
        require(signed["exit_code"] == 0, "SETUP: could not sign HTTPS origin certificate")

        ca_result = lab.command("ngfw", "cat " + shlex.quote(ca_cert), sudo=True, save=False)
        cert_result = lab.command("ngfw", "cat " + shlex.quote(origin_cert), sudo=True, save=False)
        key_result = lab.command("ngfw", "-u ngfw-proxy cat " + shlex.quote(origin_key), sudo=True, save=False)
        require(ca_result["exit_code"] == cert_result["exit_code"] == key_result["exit_code"] == 0,
                "SETUP: could not read public CA/origin certificate artifacts")
        ca_bytes = ca_result["stdout"].encode()
        cert_bytes = cert_result["stdout"].encode()
        key_bytes = key_result["stdout"].encode()
        (evidence / "ca.crt").write_bytes(ca_bytes)
        server_file = evidence / "https_origin.py"
        server_file.write_text(server_source(), encoding="utf-8")
        lab.command("dmz", "mkdir -p " + shlex.quote(remote_dmz_dir))
        lab.command("lan", "mkdir -p " + shlex.quote(remote_lan_dir))
        lab.upload_bytes("dmz", remote_dmz_dir + "/origin.crt", cert_bytes, 0o644)
        lab.upload_bytes("dmz", remote_dmz_dir + "/origin.key", key_bytes, 0o600)
        lab.upload_bytes("dmz", remote_dmz_dir + "/origin.py", server_file.read_bytes(), 0o644)
        lab.upload_bytes("lan", lan_ca, ca_bytes, 0o644)
        lab.upload_bytes("lan", lan_client, binary.read_bytes(), 0o755)

        start_cmd = ("systemd-run --unit=" + shlex.quote(origin_unit) + " --collect "
                     "--property=RuntimeMaxSec=1200 /usr/bin/python3 " + shlex.quote(remote_dmz_dir + "/origin.py") +
                     " --cert " + shlex.quote(remote_dmz_dir + "/origin.crt") +
                     " --key " + shlex.quote(remote_dmz_dir + "/origin.key") +
                     " --log " + shlex.quote(dmz_log))
        start = lab.command("dmz", start_cmd, sudo=True, evidence="origin-start.json")
        require(start["exit_code"] == 0, "SETUP: could not start temporary HTTPS origin")
        listening = False
        for _ in range(20):
            check = lab.command("dmz", "ss -lntp sport = :443", sudo=True, save=False)
            if check["exit_code"] == 0 and len(check["stdout"].splitlines()) > 1:
                listening = True
                break
            time.sleep(0.25)
        require(listening, "SETUP: temporary HTTPS origin did not listen on TCP/443")

        upstream_probe = ("curl --noproxy '*' --silent --show-error --include --max-time 8 --cacert " +
                          shlex.quote(ca_cert) + " --resolve dmz-m4.test:443:10.20.0.10 " +
                          "https://dmz-m4.test/preflight-" + run_id)
        probe = lab.command("ngfw", upstream_probe, sudo=True, timeout=12, evidence="origin-tls-preflight.json")
        require(probe["exit_code"] == 0 and "HTTP/1.1 200" in probe["stdout"] and "marker" in probe["stdout"],
                "SETUP: DMZ HTTPS origin failed CA/SAN verification before interception")
        lab.command("dmz", "truncate -s 0 " + shlex.quote(dmz_log), sudo=True, save=False)

        env_contents = ("NGFW_PROXY_CA_CERT=" + ca_cert + "\n"
                        "NGFW_PROXY_CA_KEY=" + ca_key + "\n"
                        "NGFW_PROXY_UPSTREAM_CA=" + ca_cert + "\n")
        dropin_contents = "[Service]\nEnvironmentFile=" + runtime_envfile + "\n"
        (evidence / "proxy-acceptance.conf").write_text(dropin_contents, encoding="utf-8")
        (evidence / "proxy-acceptance.env").write_text(env_contents, encoding="utf-8")
        lab.upload_bytes("ngfw", local_envfile, env_contents.encode(), 0o600)
        lab.upload_bytes("ngfw", local_dropin, dropin_contents.encode(), 0o600)
        mkdir_dropin = lab.command("ngfw", "install -d -m 0755 " + shlex.quote(dropin_dir), sudo=True)
        require(mkdir_dropin["exit_code"] == 0, "SETUP: could not prepare temporary runtime drop-in directory")
        install_envfile = lab.command("ngfw", "install -o root -g root -m 0644 " + shlex.quote(local_envfile) + " " + shlex.quote(runtime_envfile), sudo=True, evidence="proxy-runtime-env-install.json")
        require(install_envfile["exit_code"] == 0, "SETUP: could not install temporary proxy environment file")
        runtime_envfile_set = True
        install_dropin = lab.command("ngfw", "install -o root -g root -m 0644 " + shlex.quote(local_dropin) + " " + shlex.quote(dropin_path), sudo=True, evidence="proxy-ca-dropin-install.json")
        require(install_dropin["exit_code"] == 0, "SETUP: could not install temporary proxy CA drop-in")
        dropin_set = True
        lab.command("ngfw", "rm -f -- " + shlex.quote(local_dropin) + " " + shlex.quote(local_envfile), sudo=True, save=False)
        reload_systemd = lab.command("ngfw", "systemctl daemon-reload", sudo=True, evidence="proxy-dropin-daemon-reload.json")
        require(reload_systemd["exit_code"] == 0, "SETUP: systemd did not reload the proxy drop-in")
        restart = lab.command("ngfw", "systemctl restart ngfw-proxy.service", sudo=True, evidence="proxy-restart-for-ca.json", timeout=40)
        require(restart["exit_code"] == 0, "SETUP: proxy restart with temporary CA paths failed")
        active = lab.command("ngfw", "systemctl is-active ngfw-proxy.service", evidence="proxy-active-for-ca.json")
        require(active["exit_code"] == 0 and active["stdout"].strip() == "active", "SETUP: proxy did not recover after CA environment update")

        candidate = copy.deepcopy(baseline)
        candidate["request_gate"] = {"enabled": True}
        if args.suite == "h2-isolation":
            candidate["request_gate"]["request_timeout_ms"] = 10000
        candidate["security_profiles"] = (candidate.get("security_profiles") or []) + [{
            "id": profile_id,
            "name": "Temporary HTTPS DECRYPT acceptance",
            "tls_mode": "DECRYPT",
            "request_gate": {"enabled": True, "fail_mode": "CLOSE", "oversize_action": "BLOCK",
                             "unsupported_encoding_action": "BLOCK"},
        }]
        candidate["policies"] = (candidate.get("policies") or []) + [{
            "id": policy_id,
            "name": "Temporary LAN to DMZ HTTPS gate acceptance",
            "priority": 50,
            "source_zones": ["lan"],
            "destination_zones": ["dmz"],
            "source_addresses": ["192.168.10.10/32"],
            "destination_addresses": ["10.20.0.10/32"],
            "services": ["tcp:443"],
            "security_profile_id": profile_id,
            "action": "ALLOW",
            "scope": "SESSION",
            "log_start": False,
            "log_end": False,
            "enabled": True,
        }]
        candidate_touched = True
        stage = lab.api("PUT", "/config/candidate", payload=candidate, evidence="candidate-stage-https.json")
        require(stage["status"] == 200, "M4-07 FAIL: valid HTTPS DECRYPT Candidate was rejected")
        commit = lab.api("POST", "/policies/commit", payload={
            "expected_version": original_version,
            "author": "m4-https-acceptance",
            "comment": "Temporary M4-07/08 HTTPS acceptance",
        }, evidence="commit-https.json")
        require(commit["status"] == 200, "M4-07 FAIL: HTTPS DECRYPT activation was rejected")

        healthy = None
        for _ in range(40):
            healthy = lab.api("GET", "/request-gate/health")
            data = healthy.get("response", {}).get("data", {})
            if data.get("status") == "healthy" and data.get("https_listener_ready") and data.get("ca_loaded") and data.get("workers_ready", 0) > 0:
                break
            time.sleep(0.5)
        json_write(evidence / "active-health.json", healthy)
        hdata = healthy.get("response", {}).get("data", {})
        require(hdata.get("status") == "healthy" and hdata.get("https_listener_ready") is True and
                hdata.get("ca_loaded") is True and hdata.get("workers_ready", 0) > 0,
                "M4-07 FAIL: HTTPS listener, CA, or request workers did not become ready")
        lab.command("ngfw", "nft -a list ruleset", sudo=True, evidence="active-nft.txt")
        lab.command("ngfw", "ip -4 rule show", sudo=True, evidence="active-ip-rules.txt")
        lab.command("ngfw", "ip -4 route show table 140", sudo=True, evidence="active-route-140.txt")

        if args.suite == "mtls-recheck":
            from lab_mtls_cases import run_mtls_cases
            run_mtls_cases(lab=lab, evidence=evidence, report=report, healthy=healthy,
                           lan_client=lan_client, lan_ca=lan_ca, dmz_log=dmz_log,
                           remote_dmz_dir=remote_dmz_dir, origin_unit=origin_unit,
                           remote_dir=remote_dir, ca_cert=ca_cert)
        elif args.suite == "tls-continuation":
            from lab_tls_cases import run_tls_cases
            run_tls_cases(lab=lab, evidence=evidence, report=report, candidate=candidate,
                          profile_id=profile_id, policy_id=policy_id, healthy=healthy,
                          lan_client=lan_client, lan_ca=lan_ca, dmz_log=dmz_log,
                          remote_dmz_dir=remote_dmz_dir, origin_unit=origin_unit,
                          remote_dir=remote_dir, origin_cert=origin_cert, ca_cert=ca_cert)
        elif args.suite == "body-limits":
            from lab_body_cases import run_body_cases
            run_body_cases(lab=lab, evidence=evidence, report=report, healthy=healthy,
                           lan_client=lan_client, lan_ca=lan_ca, dmz_log=dmz_log, profile_id=profile_id)
        elif args.suite == "h2-isolation":
            from lab_h2_cases import run_h2_cases
            run_h2_cases(lab=lab, evidence=evidence, report=report, healthy=healthy,
                         lan_client=lan_client, lan_ca=lan_ca, dmz_log=dmz_log)
        elif args.suite == "h2-clean":
            marker = "m4-16-h2-" + secrets.token_hex(8)
            command = " ".join(shlex.quote(part) for part in [
                lan_client, "--ip", "10.20.0.10", "--host", "dmz-m4.test", "--port", "443",
                "--path", "/" + marker, "--method", "GET", "--marker", marker,
                "--ca", lan_ca, "--http2",
            ])
            client = lab.command("lan", command, timeout=30, evidence="M4-16-client.json")
            try:
                client_result = json.loads(client["stdout"].splitlines()[-1])
            except (ValueError, IndexError):
                client_result = {"unparsed_output": client["stdout"]}
            report["scenarios"]["M4-16"] = {
                "marker": marker,
                "client_exit": client["exit_code"],
                "client": client_result,
            }
            require(client["exit_code"] == 0, "M4-16 FAIL: H2 client request failed")
            require(client_result.get("status") == 200 and
                    client_result.get("http_protocol") == "HTTP/2.0" and
                    client_result.get("alpn") == "h2" and
                    client_result.get("tls_verified") is True and
                    client_result.get("verified_chain_count", 0) > 0 and
                    "dmz-m4.test" in client_result.get("peer_dns_names", []),
                    "M4-16 FAIL: client did not complete verified HTTP/2 over negotiated h2 TLS")

            origin = lab.command("dmz", "cat " + shlex.quote(dmz_log), sudo=True,
                                 evidence="M4-16-origin.json")
            require(origin["exit_code"] == 0, "M4-16 FAIL: could not read HTTPS origin log")
            origin_items = [json.loads(line) for line in origin["stdout"].splitlines() if line.strip()]
            matches = [item for item in origin_items if item.get("marker") == marker]
            report["scenarios"]["M4-16"]["origin_matches"] = matches
            require(len(matches) == 1 and matches[0].get("http_version") == "HTTP/1.1" and
                    matches[0].get("tls_version") in ("TLSv1.2", "TLSv1.3"),
                    "M4-16 FAIL: exact clean request did not reach the verified HTTPS origin")

            matched_item = None
            evidence_samples = []
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                reply = lab.api("GET", "/request-gate/evidence?limit=128",
                                evidence="M4-16-request-evidence-latest.json", timeout=8)
                evidence_samples.append({"status": reply["status"], "sampled_at": utc_now()})
                items = reply.get("response", {}).get("data", {}).get("items", [])
                candidates = [item for item in items if item.get("context", {}).get("path") == "/" + marker]
                if len(candidates) == 1:
                    matched_item = candidates[0]
                    if matched_item.get("forward") is not None:
                        break
                time.sleep(0.25)
            json_write(evidence / "M4-16-evidence-poll.json", evidence_samples)
            require(matched_item is not None, "M4-16 FAIL: no unique engine request evidence for H2 request")
            json_write(evidence / "M4-16-request-evidence.json", matched_item)
            context = matched_item.get("context", {})
            inspection = matched_item.get("inspection", {})
            decision = matched_item.get("decision", {})
            forward = matched_item.get("forward", {})
            authoritative = (
                context.get("scheme") == "https" and context.get("http_version") == "HTTP/2.0" and
                bool(context.get("connection_id")) and bool(context.get("request_id")) and
                inspection.get("completed") is True and inspection.get("coverage") == "COMPLETE" and
                decision.get("verdict") == "ALLOW" and
                decision.get("reason_code") == "GATE_INSPECTION_COMPLETE" and
                forward.get("http_status") == 200 and
                forward.get("reason_code") == "UPSTREAM_RESPONSE_RECEIVED"
            )
            report["scenarios"]["M4-16"].update({
                "request_id": context.get("request_id"),
                "connection_id": context.get("connection_id"),
                "decision_id": decision.get("decision_id"),
                "authoritative_check": authoritative,
                "result": "PASS" if authoritative else "FAIL",
            })
            require(authoritative, "M4-16 FAIL: engine did not record complete ALLOW and successful forward for HTTP/2")
            report["M4-16"] = "PASS"
            report["status"] = "PASS_M4_16"
        else:
            def request(label, body=None):
                marker = label + "-" + secrets.token_hex(6)
                clock = lab.command("ngfw", "date +%s", save=False)
                require(clock["exit_code"] == 0, "SETUP: could not read NGFW verification clock")
                verify_unix = int(clock["stdout"].strip()) + 300
                parts = [lan_client, "--ip", "10.20.0.10", "--host", "dmz-m4.test", "--port", "443",
                         "--path", "/" + marker, "--method", "POST" if body is not None else "GET",
                         "--body", body or "", "--marker", marker, "--ca", lan_ca,
                         "--verify-unix", str(verify_unix)]
                command = " ".join(shlex.quote(part) for part in parts)
                result = lab.command("lan", command, timeout=25, evidence="client-" + label + ".json")
                client_result = {}
                if result["stdout"].strip():
                    try:
                        client_result = json.loads(result["stdout"].splitlines()[-1])
                    except ValueError:
                        client_result = {"unparsed_output": result["stdout"]}
                report["scenarios"][label] = {"marker": marker, "path": "/" + marker,
                                               "client_exit": result["exit_code"],
                                               "client_result": client_result,
                                               "verify_time_unix": verify_unix}
                origin = lab.command("dmz", "cat " + shlex.quote(dmz_log), sudo=True, evidence="origin-" + label + ".json")
                log_lines = [json.loads(line) for line in origin["stdout"].splitlines() if line.strip()]
                report["scenarios"][label]["origin_requests"] = log_lines
                matches = [line for line in log_lines if line.get("marker") == marker]
                check = {
                    "client_exit": result["exit_code"],
                    "status_200": client_result.get("status") == 200,
                    "trusted_tls": result["exit_code"] == 0 and client_result.get("tls_verified") is True and
                                   client_result.get("verified_chain_count", 0) > 0 and
                                   "dmz-m4.test" in client_result.get("peer_dns_names", []),
                    "origin_seen": len(matches) == 1,
                    "origin_not_seen": len(matches) == 0,
                }
                report["scenarios"][label]["transport_checks"] = check
                report["scenarios"][label]["result"] = "PENDING"
                json_write(evidence / "progress.json", report)
                return marker, check

            def observe_counters(label, item, previous_health):
                row = "M4-07" if label == "clean" else "M4-08"
                verdict_counter = "request_allowed" if label == "clean" else "request_blocked"
                baseline_counters = previous_health["response"]["data"]["counters"]
                minimum = {name: baseline_counters.get(name, 0) + 1
                           for name in ("decrypted", "intercepted", verdict_counter)}
                observation = {"request_observed_at": item["observed_at"],
                               "generation": item["decision"]["config_generation"],
                               "minimum_counters": minimum}
                try:
                    observed, samples = wait_for_health_counters(
                        lambda timeout: lab.api("GET", "/request-gate/health", timeout=timeout),
                        generation=observation["generation"], after=observation["request_observed_at"],
                        minimum_counters=minimum)
                except HealthObservationError as error:
                    observation["samples"] = error.observations
                    json_write(evidence / (row + "-health-observations-" + label + ".json"), observation)
                    raise RuntimeError(row + " FAIL: " + str(error)) from error
                observation["samples"] = samples
                json_write(evidence / (row + "-health-observations-" + label + ".json"), observation)
                json_write(evidence / (row + "-health-after-" + label + ".json"), observed)
                report["scenarios"][label]["health_counters"] = observed["response"]["data"]["counters"]
                report["scenarios"][label]["health_updated_at"] = observed["response"]["data"]["updated_at"]
                report["scenarios"][label]["health_observation_count"] = len(samples)
                return observed

            clean_marker, clean_transport = request("clean")
            require(clean_transport["client_exit"] == 0 and clean_transport["status_200"] and clean_transport["trusted_tls"] and clean_transport["origin_seen"],
                    "M4-07 FAIL: clean HTTPS request/certificate verification/upstream evidence did not all pass")
            clean_evidence = lab.api("GET", "/request-gate/evidence?limit=128", evidence="M4-07-request-evidence.json")
            items = clean_evidence.get("response", {}).get("data", {}).get("items", [])
            clean_items = [item for item in items if item.get("context", {}).get("path") == "/" + clean_marker]
            require(len(clean_items) == 1, "M4-07 FAIL: no unique authoritative request evidence for clean HTTPS")
            clean_item = clean_items[0]
            clean_decision = clean_item.get("decision", {})
            clean_check = (clean_item.get("context", {}).get("scheme") == "https" and
                           clean_decision.get("verdict") == "ALLOW" and
                           clean_decision.get("reason_code") == "GATE_INSPECTION_COMPLETE" and
                           clean_decision.get("coverage") == "COMPLETE" and
                           clean_item.get("inspection", {}).get("completed") is True)
            report["scenarios"]["clean"]["request_id"] = clean_item.get("context", {}).get("request_id")
            report["scenarios"]["clean"]["session_id"] = clean_decision.get("session_id")
            report["scenarios"]["clean"]["authoritative_check"] = clean_check
            require(clean_check, "M4-07 FAIL: HTTPS clean request was not authoritatively inspected with complete coverage")
            clean_health = observe_counters("clean", clean_item, healthy)
            report["scenarios"]["clean"]["result"] = "PASS"
            report["scenarios"]["M4-07"] = "PASS"
            json_write(evidence / "progress.json", report)

            # Isolate each attack from prior origin traffic.
            lab.command("dmz", "truncate -s 0 " + shlex.quote(dmz_log), sudo=True, save=False)
            sqli_marker, sqli_transport = request("sqli", "UNION SELECT")
            require(sqli_transport["client_exit"] == 0 and report["scenarios"]["sqli"]["client_result"].get("status") == 403 and sqli_transport["trusted_tls"] and
                    sqli_transport["origin_not_seen"],
                    "M4-08 FAIL: HTTPS SQLi was not blocked before the upstream")
            sqli_evidence = lab.api("GET", "/request-gate/evidence?limit=128", evidence="M4-08-sqli-evidence.json")
            items = sqli_evidence.get("response", {}).get("data", {}).get("items", [])
            sqli_items = [item for item in items if item.get("context", {}).get("path") == "/" + sqli_marker]
            require(len(sqli_items) == 1, "M4-08 FAIL: no unique HTTPS SQLi request evidence")
            sqli_item = sqli_items[0]
            sqli_decision = sqli_item.get("decision", {})
            sqli_alerts = sqli_item.get("inspection", {}).get("alerts", [])
            sqli_check = (sqli_item.get("context", {}).get("scheme") == "https" and
                          sqli_decision.get("verdict") == "BLOCK" and
                          sqli_decision.get("reason_code") == "GATE_SIGNATURE_BLOCK" and
                          sqli_decision.get("coverage") == "COMPLETE" and
                          sqli_item.get("inspection", {}).get("completed") is True and
                          any(str(alert.get("signature_id")) == "9904003" for alert in sqli_alerts))
            report["scenarios"]["sqli"]["authoritative_check"] = sqli_check
            report["scenarios"]["sqli"]["request_id"] = sqli_item.get("context", {}).get("request_id")
            report["scenarios"]["sqli"]["session_id"] = sqli_decision.get("session_id")
            require(sqli_check, "M4-08 FAIL: HTTPS SQLi decision/EVE SID/coverage assertion failed")
            sqli_health = observe_counters("sqli", sqli_item, clean_health)
            report["scenarios"]["sqli"]["result"] = "PASS"
            report["scenarios"]["M4-08-SQLi"] = "PASS"
            json_write(evidence / "progress.json", report)

            lab.command("dmz", "truncate -s 0 " + shlex.quote(dmz_log), sudo=True, save=False)
            xss_marker, xss_transport = request("xss", "<script>alert(1)</script>")
            require(xss_transport["client_exit"] == 0 and report["scenarios"]["xss"]["client_result"].get("status") == 403 and xss_transport["trusted_tls"] and
                    xss_transport["origin_not_seen"],
                    "M4-08 FAIL: HTTPS XSS was not blocked before the upstream")
            xss_evidence = lab.api("GET", "/request-gate/evidence?limit=128", evidence="M4-08-xss-evidence.json")
            items = xss_evidence.get("response", {}).get("data", {}).get("items", [])
            xss_items = [item for item in items if item.get("context", {}).get("path") == "/" + xss_marker]
            require(len(xss_items) == 1, "M4-08 FAIL: no unique HTTPS XSS request evidence")
            xss_item = xss_items[0]
            xss_decision = xss_item.get("decision", {})
            xss_alerts = xss_item.get("inspection", {}).get("alerts", [])
            xss_check = (xss_item.get("context", {}).get("scheme") == "https" and
                         xss_decision.get("verdict") == "BLOCK" and
                         xss_decision.get("reason_code") == "GATE_SIGNATURE_BLOCK" and
                         xss_decision.get("coverage") == "COMPLETE" and
                         xss_item.get("inspection", {}).get("completed") is True and
                         any(str(alert.get("signature_id")) == "9904004" for alert in xss_alerts))
            report["scenarios"]["xss"]["authoritative_check"] = xss_check
            report["scenarios"]["xss"]["request_id"] = xss_item.get("context", {}).get("request_id")
            report["scenarios"]["xss"]["session_id"] = xss_decision.get("session_id")
            require(xss_check, "M4-08 FAIL: HTTPS XSS decision/EVE SID/coverage assertion failed")
            observe_counters("xss", xss_item, sqli_health)
            report["scenarios"]["xss"]["result"] = "PASS"
            report["scenarios"]["M4-08-XSS"] = "PASS"
            report["scenarios"]["M4-08"] = "PASS"

            lab.api("GET", "/request-gate/health", evidence="post-traffic-health.json")
            report["status"] = "PASS_M4-07_M4-08"

    except Exception as error:
        report["status"] = "FAIL" if "FAIL:" in str(error) else "SETUP_BLOCKED"
        report["error"] = str(error)
        report["failed_at"] = utc_now()

    finally:
        if lab is not None:
            try:
                lab.command("ngfw", "journalctl -u ngfw-proxy -n 150 --no-pager", sudo=True, evidence="proxy-journal-active.json")
                lab.command("ngfw", "journalctl -u ngfw-engine -n 150 --no-pager", sudo=True, evidence="engine-journal-active.json")
                lab.api("GET", "/request-gate/health", evidence="health-before-restore.json")
                current = lab.api("GET", "/config", evidence="config-before-restore.json")
                if baseline is not None and current.get("status") == 200:
                    state = current["response"]["data"]
                    if state["running"] != baseline:
                        stage = lab.api("PUT", "/config/candidate", payload=baseline, evidence="restore-stage-baseline.json")
                        require(stage["status"] == 200, "RESTORE FAILED: could not stage baseline Running")
                        restore = lab.api("POST", "/policies/commit", payload={
                            "expected_version": state["version"]["version"],
                            "author": "m4-https-acceptance",
                            "comment": "Restore pretest Running after HTTPS acceptance",
                        }, evidence="restore-running.json")
                        require(restore["status"] == 200, "RESTORE FAILED: baseline Running commit failed")
                    final_config = lab.api("GET", "/config", evidence="config-after-running-restore.json")
                    state2 = final_config["response"]["data"]
                    if original_candidate is not None and state2["candidate"] != original_candidate:
                        draft = lab.api("PUT", "/config/candidate", payload=original_candidate, evidence="restore-original-candidate.json")
                        require(draft["status"] == 200, "RESTORE FAILED: original Candidate could not be restored")
                    final_config = lab.api("GET", "/config", evidence="final-config.json")
                    final_state = final_config["response"]["data"]
                    report["config_restored"] = (final_state["running"] == baseline and
                                                  final_state["candidate"] == original_candidate)
                    require(report["config_restored"], "RESTORE FAILED: Running or Candidate differs from its snapshot")

                lab.command("dmz", "systemctl stop " + shlex.quote(origin_unit), sudo=True, save=False)
                lab.command("dmz", "rm -f -- " + " ".join(shlex.quote(x) for x in [
                    remote_dmz_dir + "/origin.crt", remote_dmz_dir + "/origin.key",
                    remote_dmz_dir + "/origin.py", dmz_log]), sudo=True, save=False)
                lab.command("dmz", "rmdir -- " + shlex.quote(remote_dmz_dir), save=False)
                lab.command("lan", "rm -f -- " + shlex.quote(lan_ca) + " " + shlex.quote(lan_client), save=False)
                lab.command("lan", "rmdir -- " + shlex.quote(remote_lan_dir), save=False)

                if dropin_set or runtime_envfile_set:
                    if dropin_set:
                        unset = lab.command("ngfw", "rm -f -- " + shlex.quote(dropin_path), sudo=True,
                                            evidence="proxy-ca-dropin-remove.json")
                        require(unset["exit_code"] == 0, "RESTORE FAILED: could not remove temporary CA systemd drop-in")
                    if runtime_envfile_set:
                        unset_env = lab.command("ngfw", "rm -f -- " + shlex.quote(runtime_envfile), sudo=True,
                                                evidence="proxy-runtime-env-remove.json")
                        require(unset_env["exit_code"] == 0, "RESTORE FAILED: could not remove temporary proxy environment file")
                    reload_systemd = lab.command("ngfw", "systemctl daemon-reload", sudo=True,
                                                 evidence="proxy-dropin-daemon-reload-after-restore.json")
                    require(reload_systemd["exit_code"] == 0, "RESTORE FAILED: systemd reload after drop-in removal failed")
                    restart = lab.command("ngfw", "systemctl restart ngfw-proxy.service", sudo=True,
                                          evidence="proxy-restart-after-restore.json", timeout=40)
                    require(restart["exit_code"] == 0, "RESTORE FAILED: proxy restart after CA cleanup failed")
                    dropin_set = False
                    runtime_envfile_set = False
                    if not dropin_dir_existed:
                        lab.command("ngfw", "rmdir -- " + shlex.quote(dropin_dir), sudo=True, save=False)
                    lab.command("ngfw", "rm -f -- " + shlex.quote(local_dropin) + " " + shlex.quote(local_envfile), sudo=True, save=False)

                if ca_created:
                    cleanup = [ca_cert, ca_key, origin_key, origin_csr, origin_cert, origin_ext, serial_file]
                    lab.command("ngfw", "rm -f -- " + " ".join(shlex.quote(x) for x in cleanup), sudo=True, save=False)
                    lab.command("ngfw", "rmdir -- " + shlex.quote(remote_dir), sudo=True, save=False)
                    ca_created = False

                temporary_cleanup = {}
                for host, path in [("ngfw", remote_dir), ("ngfw", dropin_path), ("ngfw", runtime_envfile),
                                   ("dmz", remote_dmz_dir), ("lan", remote_lan_dir)]:
                    check = lab.command(host, "test ! -e " + shlex.quote(path), sudo=host == "ngfw")
                    temporary_cleanup[host + ":" + path] = check["exit_code"] == 0
                report["temporary_files_removed"] = all(temporary_cleanup.values())
                json_write(evidence / "temporary-cleanup.json", temporary_cleanup)
                final_services = lab.command("ngfw", "systemctl is-active ngfw-engine ngfw-api ngfw-proxy", evidence="final-services.json")
                final_health = lab.api("GET", "/request-gate/health", evidence="final-health.json")
                journal = lab.command("ngfw", "test ! -e /var/lib/ngfw/dataplane-applied.json.activation", sudo=True, evidence="final-journal-absent.json")
                selector = lab.command("ngfw", "nft -j list table inet ngfw_proxy", sudo=True, evidence="final-selector.json")
                routes = lab.command("ngfw", "ip -j -4 rule show", sudo=True, evidence="final-routing-rules.json")
                selector_objects = json.loads(selector["stdout"]).get("nftables", []) if selector["exit_code"] == 0 else []
                route_rules = json.loads(routes["stdout"]) if routes["exit_code"] == 0 else []
                report["kernel_cleanup_check"] = (journal["exit_code"] == 0 and selector["exit_code"] == 0 and
                    routes["exit_code"] == 0 and not any(entry.get("chain", {}).get("hook") == "prerouting" for entry in selector_objects) and
                    not any(entry.get("table") == 140 for entry in route_rules))
                report["services_active"] = final_services["exit_code"] == 0 and final_services["stdout"].splitlines() == ["active", "active", "active"]
                report["health_disabled"] = final_health.get("status") == 200 and final_health.get("response", {}).get("data", {}).get("enabled") is False
                report["restored"] = bool(report.get("config_restored") and report["kernel_cleanup_check"] and
                                          report["services_active"] and report["health_disabled"] and
                                          report["temporary_files_removed"])
                if not report["restored"] and report["status"].startswith("PASS"):
                    report["status"] = "RESTORE_FAILED"
            except Exception as restore_error:
                report["restore_error"] = str(restore_error)
                report["restored"] = False
                if report["status"].startswith("PASS"):
                    report["status"] = "RESTORE_FAILED"
            finally:
                (evidence / "commands.jsonl").write_text(
                    "\n".join(json.dumps(row, ensure_ascii=False) for row in lab.commands) + "\n",
                    encoding="utf-8")
                lab.close()
        report["finished_at"] = utc_now()
        json_write(evidence / "result.json", report)

    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["status"].startswith("PASS_") and report.get("restored") else 1


if __name__ == "__main__":
    sys.exit(main())
