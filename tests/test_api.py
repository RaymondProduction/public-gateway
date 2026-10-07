"""Offline tests only. wg, the live interface and the Caddy admin API are mocked."""
import base64
import http.client
import importlib.util
import json
import os
import socket
import socketserver
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gateway_api", SOURCE / "api/gateway_api.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

# Intentionally dummy strings, not deployment keys.
DUMMY_KEYS = ("A" * 43 + "=", "B" * 43 + "=", "C" * 43 + "=")
CLIENT_PUB = base64.b64encode(bytes(range(32))).decode()
TOKEN = "unit-test-token-0123456789"


def state_fixture():
    return {"version": 2, "server_ip": "1.2.3.4", "subnet": "10.77.0.0/24",
            "gateway_ip": "10.77.0.1", "mtu": 1380, "next_host": 3,
            "server_private": "SERVER_PRIVATE_TEST_ONLY", "server_public": "SERVER_PUBLIC_TEST_ONLY",
            "peers": {"laptop": {"address": "10.77.0.2", "private_key": "CLIENT_PRIVATE_TEST_ONLY",
                                  "public_key": "CLIENT_PUBLIC_TEST_ONLY", "preshared_key": "PSK_TEST_ONLY"}},
            "sites": {}, "ports": {}}


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data.upper())


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
        self.echo.daemon_threads = True
        threading.Thread(target=self.echo.serve_forever, daemon=True).start()
        self.relay = g.Relay()

    def tearDown(self):
        for listen in list(self.relay.listening()):
            self.relay.stop(listen)
        self.echo.shutdown(); self.echo.server_close()

    def talk(self, port, payload=b"hello relay"):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(payload)
            return sock.recv(65536)

    def test_forward_and_stop(self):
        listen = free_port()
        self.relay.start(listen, "127.0.0.1", self.echo.server_address[1])
        self.assertEqual(self.talk(listen), b"HELLO RELAY")
        self.assertEqual(self.talk(listen, b"x" * 200000)[:5], b"XXXXX")
        self.assertEqual(self.relay.listening(), {listen: ("127.0.0.1", self.echo.server_address[1])})
        self.relay.stop(listen)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", listen), timeout=2)

    def test_busy_port_is_reported_not_saved(self):
        with self.assertRaises(g.GatewayError) as ctx:
            self.relay.start(self.echo.server_address[1], "127.0.0.1", 1)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(self.relay.listening(), {})

    def test_unreachable_target_closes_client(self):
        listen = free_port()
        self.relay.start(listen, "127.0.0.1", free_port())
        with socket.create_connection(("127.0.0.1", listen), timeout=5) as sock:
            self.assertEqual(sock.recv(10), b"")

    def test_sync_matches_state(self):
        state = state_fixture()
        a, b = free_port(), free_port()
        state["ports"] = {str(a): {"peer": "laptop", "port": 1}, str(b): {"peer": "ghost", "port": 1}}
        state["peers"]["laptop"]["address"] = "127.0.0.1"
        self.assertEqual(self.relay.sync(state), {})
        self.assertEqual(set(self.relay.listening()), {a})
        state["ports"] = {}
        self.relay.sync(state)
        self.assertEqual(self.relay.listening(), {})


class ValidationTests(unittest.TestCase):
    def test_valid_names(self):
        for value in ("laptop", "laptop-2", "phone_1"):
            self.assertEqual(g.name_ok(value), value)

    def test_reject_unsafe_names(self):
        for value in ("../x", "x/../../y", "a b", "a\nx", "1phone", "", "a" * 33, None, 5):
            with self.subTest(value=value), self.assertRaises(g.GatewayError):
                g.name_ok(value)

    def test_normalize_domain(self):
        self.assertEqual(g.host_ok("APP.Example.com."), "app.example.com")

    def test_injection_and_urls_rejected(self):
        for value in ("https://app.example.com", "app.example.com:443", "*.example.com", "foo\n{",
                      "{$ENV}", "app.example.com/x", "x#y.example.com", 'x".example.com', None):
            with self.subTest(value=value), self.assertRaises(g.GatewayError):
                g.host_ok(value)

    def test_bad_domains(self):
        for value in ("localhost", "foo.local", "x.test", "-bad.example.com", "a..example.com",
                      "999.999.999.999", "a" * 64 + ".com"):
            with self.subTest(value=value), self.assertRaises(g.GatewayError):
                g.host_ok(value)

    def test_endpoint(self):
        self.assertEqual(g.endpoint_ok("1.2.3.4"), "1.2.3.4")
        self.assertEqual(g.endpoint_ok("vps.example.com"), "vps.example.com")
        for value in ("10.0.0.1", "127.0.0.1", "", "http://x.example.com"):
            with self.subTest(value=value), self.assertRaises(g.GatewayError):
                g.endpoint_ok(value)

    def test_ports(self):
        for port in (1, 3000, 65535):
            self.assertEqual(g.port_ok(port), port)
        for port in (0, -1, 65536, "3000", True, None):
            with self.subTest(port=port), self.assertRaises(g.GatewayError):
                g.port_ok(port)

    def test_subnets_and_mtu(self):
        for value in ("10.77.0.0/24", "172.20.20.0/24", "192.168.50.0/24"):
            self.assertEqual(str(g.subnet_ok(value)), value)
        for value in ("0.0.0.0/24", "1.2.3.0/24", "10.77.0.2/24", "10.0.0.0/8", "::/0"):
            with self.subTest(value=value), self.assertRaises(g.GatewayError):
                g.subnet_ok(value)
        self.assertEqual(g.mtu_ok("1380"), 1380)
        for value in ("abc", 1000, 1500):
            with self.subTest(value=value), self.assertRaises(g.GatewayError):
                g.mtu_ok(value)

    def test_pubkey(self):
        self.assertEqual(g.key_ok(CLIENT_PUB), CLIENT_PUB)
        for value in ("short", "A" * 44, "A" * 43 + "=" + "x", base64.b64encode(bytes(31)).decode(), 7):
            with self.subTest(value=value), self.assertRaises(g.GatewayError):
                g.key_ok(value)

    def test_port_range(self):
        with patch.dict(os.environ, {"PORT_RANGE": "3000-3002"}):
            self.assertEqual(g.port_range_from_env(), {80, 443, 3000, 3001, 3002})
        with patch.dict(os.environ, {"PORT_RANGE": ""}):
            self.assertEqual(g.port_range_from_env(), {80, 443})
        with patch.dict(os.environ, {"PORT_RANGE": "8000-8100"}):
            self.assertNotIn(8080, g.port_range_from_env())
        for bad in ("abc", "3000", "4000-3000", "1-2000"):
            with self.subTest(bad=bad), patch.dict(os.environ, {"PORT_RANGE": bad}), self.assertRaises(g.GatewayError):
                g.port_range_from_env()

    def test_token_policy(self):
        with patch.dict(os.environ, {"API_TOKEN": "short"}), self.assertRaises(g.GatewayError):
            g.token_from_env()
        with patch.dict(os.environ, {"API_TOKEN": "CHANGE_ME_to_a_long_random_secret"}), self.assertRaises(g.GatewayError):
            g.token_from_env()
        with patch.dict(os.environ, {"API_TOKEN": TOKEN}):
            self.assertEqual(g.token_from_env(), TOKEN)


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.state = state_fixture()

    def test_client_config_with_server_generated_key(self):
        text = g.render_client(self.state, self.state["peers"]["laptop"])
        self.assertIn("PrivateKey = CLIENT_PRIVATE_TEST_ONLY", text)
        self.assertIn("AllowedIPs = 10.77.0.1/32", text)
        self.assertNotIn("0.0.0.0/0", text)
        self.assertIn("Endpoint = 1.2.3.4:51820", text)
        self.assertIn("PersistentKeepalive = 25", text)

    def test_client_config_with_client_key_has_no_private_key(self):
        self.state["peers"]["laptop"]["private_key"] = None
        text = g.render_client(self.state, self.state["peers"]["laptop"])
        self.assertNotIn("PrivateKey", text)
        self.assertIn("[Interface]\n", text)
        self.assertIn("PresharedKey = PSK_TEST_ONLY", text)

    def test_server_and_sync_configs(self):
        server = g.render_server(self.state)
        self.assertIn("AllowedIPs = 10.77.0.2/32", server)
        self.assertIn("vpn-firewall.sh up %i", server)
        self.assertNotIn("CLIENT_PRIVATE_TEST_ONLY", server)
        sync = g.render_sync(self.state)
        self.assertNotIn("PostUp", sync)
        self.assertNotIn("Address", sync)
        self.assertIn("ListenPort = 51820", sync)
        self.assertIn("PublicKey = CLIENT_PUBLIC_TEST_ONLY", sync)

    def test_caddy_default_and_routes(self):
        text = g.render_caddy(self.state)
        self.assertIn("http://1.2.3.4", text)
        self.assertNotIn("reverse_proxy", text)
        self.state["sites"]["app.example.com"] = {"peer": "laptop", "port": 3000, "http": False}
        text = g.render_caddy(self.state)
        self.assertIn("\napp.example.com {", text)
        self.assertIn("reverse_proxy 10.77.0.2:3000", text)
        self.assertNotIn("PSK_TEST_ONLY", text)
        # Unreachable device: maintenance page with 503 instead of a bare proxy error.
        self.assertIn("handle_errors 502 503 504 {", text)
        self.assertIn("Ведуться технічні роботи", text)
        self.assertIn("        HTML 503", text)
        self.assertEqual(text.count("handle_errors"), 1)
        self.assertNotIn("lb_policy", text)  # single device: no failover block

    def test_caddy_failover_upstreams(self):
        self.state["peers"]["desk"] = {**self.state["peers"]["laptop"], "address": "10.77.0.3"}
        self.state["sites"]["app.example.com"] = {"peer": "laptop", "backups": ["desk"], "port": 3000, "http": False}
        text = g.render_caddy(self.state)
        self.assertIn("reverse_proxy 10.77.0.2:3000 10.77.0.3:3000 {", text)
        self.assertIn("        lb_policy first", text)
        self.assertIn("        lb_retries 1", text)
        self.assertIn(f"        fail_duration {g.FAILOVER_HOLD}", text)
        self.assertIn("        max_fails 1", text)


class Sandbox(unittest.TestCase):
    """Temp dirs, dummy keys, no live wg/caddy."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [patch.object(g, "STATE", root / "state/gateway.json"),
                        patch.object(g, "WG_CONF", root / "wireguard/wg_confs/wg0.conf"),
                        patch.object(g, "CADDYFILE", root / "caddy/Caddyfile"),
                        patch.object(g, "keyset", return_value=DUMMY_KEYS),
                        patch.object(g, "wg_running", return_value=False),
                        patch.object(g, "caddy_running", return_value=False),
                        patch.object(g, "handshakes", return_value={})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()


class OperationTests(Sandbox):
    def setUp(self):
        super().setUp()
        g.commit(state_fixture(), apply=False)

    def test_secret_permissions_and_generated_files(self):
        self.assertEqual(g.STATE.stat().st_mode & 0o777, 0o600)
        self.assertEqual(g.WG_CONF.stat().st_mode & 0o777, 0o600)
        self.assertTrue(g.CADDYFILE.exists())

    def test_provision_new_peer_with_client_key(self):
        state = g.load()
        peer, created, _ = g.provision(state, "phone", CLIENT_PUB)
        self.assertTrue(created)
        self.assertEqual(peer["address"], "10.77.0.3")
        self.assertIsNone(peer["private_key"])
        self.assertEqual(peer["public_key"], CLIENT_PUB)
        self.assertEqual(g.load()["next_host"], 4)
        self.assertIn(CLIENT_PUB, g.WG_CONF.read_text())

    def test_provision_is_idempotent(self):
        state = g.load()
        g.provision(state, "phone", CLIENT_PUB)
        before = g.STATE.read_text()
        peer, created, _ = g.provision(g.load(), "phone", CLIENT_PUB)
        self.assertFalse(created)
        self.assertEqual(peer["address"], "10.77.0.3")
        self.assertEqual(before, g.STATE.read_text())

    def test_provision_without_pubkey_uses_server_keys(self):
        peer, created, _ = g.provision(g.load(), "phone", None)
        self.assertTrue(created)
        self.assertEqual(peer["private_key"], DUMMY_KEYS[0])
        text = g.render_client(g.load(), peer)
        self.assertIn(f"PrivateKey = {DUMMY_KEYS[0]}", text)

    def test_client_key_replaces_server_key(self):
        peer, _, _ = g.provision(g.load(), "laptop", CLIENT_PUB)
        self.assertIsNone(peer["private_key"])
        self.assertEqual(peer["public_key"], CLIENT_PUB)
        self.assertNotIn("CLIENT_PRIVATE_TEST_ONLY", g.STATE.read_text())
        with self.assertRaises(g.GatewayError) as ctx:
            g.provision(g.load(), "laptop", None)
        self.assertEqual(ctx.exception.status, 409)

    def test_ip_publication_requires_opt_in(self):
        with self.assertRaises(g.GatewayError):
            g.site_put(g.load(), "1.2.3.4", "laptop", 3000, False)
        with self.assertRaises(g.GatewayError):
            g.site_put(g.load(), "8.8.8.8", "laptop", 3000, True)
        g.site_put(g.load(), "1.2.3.4", "laptop", 3000, True)
        self.assertTrue(g.load()["sites"]["1.2.3.4"]["http"])
        self.assertNotIn("No application published", g.CADDYFILE.read_text())

    def test_site_backups(self):
        g.provision(g.load(), "second", CLIENT_PUB)
        with self.assertRaises(g.GatewayError):  # backup must be a different, existing device
            g.site_put(g.load(), "app.example.com", "laptop", 3000, False, ["laptop"])
        with self.assertRaises(g.GatewayError):
            g.site_put(g.load(), "app.example.com", "laptop", 3000, False, ["ghost"])
        with self.assertRaises(g.GatewayError):
            g.site_put(g.load(), "app.example.com", "laptop", 3000, False, "second")
        g.site_put(g.load(), "app.example.com", "laptop", 3000, False, ["second"])
        self.assertEqual(g.load()["sites"]["app.example.com"]["backups"], ["second"])
        self.assertIn("reverse_proxy 10.77.0.2:3000 10.77.0.3:3000 {", g.CADDYFILE.read_text())
        self.assertEqual(g.peer_public(g.load(), "second", g.load()["peers"]["second"])["backup_sites"], ["app.example.com"])
        # Revoking a backup device only drops it from the list; the route stays on the primary.
        g.revoke(g.load(), "second", False)
        self.assertEqual(g.load()["sites"]["app.example.com"]["backups"], [])
        self.assertNotIn("10.77.0.3", g.CADDYFILE.read_text())
        self.assertNotIn("lb_policy", g.CADDYFILE.read_text())

    def test_site_switch_and_remove(self):
        g.provision(g.load(), "second", CLIENT_PUB)
        g.site_put(g.load(), "app.example.com", "laptop", 3000, False)
        g.site_put(g.load(), "app.example.com", "second", 8080, False)
        self.assertEqual(g.load()["sites"]["app.example.com"]["peer"], "second")
        self.assertIn("reverse_proxy 10.77.0.3:8080", g.CADDYFILE.read_text())
        g.site_remove(g.load(), "app.example.com")
        self.assertEqual(g.load()["sites"], {})
        self.assertIn("laptop", g.load()["peers"])

    def test_revoke_requires_explicit_site_removal_and_never_reuses_address(self):
        g.site_put(g.load(), "app.example.com", "laptop", 3000, False)
        with self.assertRaises(g.GatewayError):
            g.revoke(g.load(), "laptop", False)
        g.revoke(g.load(), "laptop", True)
        state = g.load()
        self.assertNotIn("laptop", state["peers"])
        self.assertEqual(state["sites"], {})
        self.assertNotIn("CLIENT_PUBLIC_TEST_ONLY", g.WG_CONF.read_text())
        peer, _, _ = g.provision(state, "replacement", CLIENT_PUB)
        self.assertEqual(peer["address"], "10.77.0.3")

    def test_ports_lifecycle(self):
        with patch.dict(os.environ, {"PORT_RANGE": "3000-3009"}):
            with self.assertRaises(g.GatewayError):
                g.port_put(g.load(), 4000, "laptop", 4000)
            with self.assertRaises(g.GatewayError):
                g.port_put(g.load(), 3001, "nobody", 3001)
            with patch.object(g, "caddy_running", return_value=True), self.assertRaises(g.GatewayError) as ctx:
                g.port_put(g.load(), 443, "laptop", 443)
            self.assertEqual(ctx.exception.status, 409)
            g.port_put(g.load(), 443, "laptop", 8443)
            g.port_put(g.load(), 3001, "laptop", 3001)
            state = g.load()
            self.assertEqual(state["ports"], {"443": {"peer": "laptop", "port": 8443}, "3001": {"peer": "laptop", "port": 3001}})
            self.assertEqual(g.peer_public(state, "laptop", state["peers"]["laptop"])["ports"], [443, 3001])
            with self.assertRaises(g.GatewayError):
                g.revoke(g.load(), "laptop", False)
            g.port_remove(g.load(), 443)
            with self.assertRaises(g.GatewayError):
                g.port_remove(g.load(), 443)
            g.revoke(g.load(), "laptop", True)
            self.assertEqual(g.load()["ports"], {})

    def test_validation_failure_preserves_state(self):
        before = g.STATE.read_text()
        with patch.object(g, "caddy_running", return_value=True), \
                patch.object(g, "caddy_validate", side_effect=g.GatewayError("invalid", 500)):
            with self.assertRaises(g.GatewayError):
                g.site_put(g.load(), "app.example.com", "laptop", 3000, False)
        self.assertEqual(g.STATE.read_text(), before)

    def test_apply_reports_what_was_touched(self):
        with patch.object(g, "wg_running", return_value=True), patch.object(g, "wg_sync") as sync, \
                patch.object(g, "caddy_running", return_value=True), patch.object(g, "caddy_load") as load, \
                patch.object(g, "caddy_validate"):
            applied = g.site_put(g.load(), "app.example.com", "laptop", 3000, False)
            self.assertEqual(applied, {"wireguard": False, "caddy": True})
            load.assert_called_once()
            sync.assert_not_called()
            applied = g.revoke(g.load(), "laptop", True)
            self.assertEqual(applied, {"wireguard": True, "caddy": True})
            sync.assert_called_once()

    def test_apply_failure_is_reported_not_hidden(self):
        with patch.object(g, "wg_running", return_value=True), \
                patch.object(g, "wg_sync", side_effect=g.GatewayError("boom", 500)):
            with self.assertRaises(g.GatewayError) as ctx:
                g.revoke(g.load(), "laptop", False)
        self.assertIn("НЕ підтверджено", str(ctx.exception))
        self.assertNotIn("laptop", g.load()["peers"])


class InitTests(Sandbox):
    ENV = {"SERVER_ENDPOINT": "1.2.3.4", "API_TOKEN": TOKEN, "VPN_SUBNET": "10.88.20.0/24", "WG_MTU": "1300"}

    def test_init_creates_state_and_is_idempotent(self):
        with patch.dict(os.environ, self.ENV):
            g.initialize()
            state = g.load()
            self.assertEqual(state["server_public"], DUMMY_KEYS[1])
            self.assertEqual(state["gateway_ip"], "10.88.20.1")
            self.assertEqual(state["mtu"], 1300)
            self.assertEqual(state["peers"], {})
            g.initialize()
            self.assertEqual(g.load()["server_private"], DUMMY_KEYS[0])
        self.assertIn("ListenPort = 51820", g.WG_CONF.read_text())
        self.assertIn("http://1.2.3.4", g.CADDYFILE.read_text())

    def test_init_rejects_bad_env(self):
        for bad in ({"SERVER_ENDPOINT": "10.0.0.1"}, {"API_TOKEN": "short"}, {"VPN_SUBNET": "10.0.0.0/8"}):
            with self.subTest(bad=bad), patch.dict(os.environ, {**self.ENV, **bad}), \
                    self.assertRaises(g.GatewayError):
                g.initialize()
        self.assertFalse(g.STATE.exists())

    def test_subnet_change_blocked_when_peers_exist(self):
        with patch.dict(os.environ, self.ENV):
            g.initialize()
            g.provision(g.load(), "laptop", CLIENT_PUB)
        with patch.dict(os.environ, {**self.ENV, "VPN_SUBNET": "10.99.0.0/24"}), self.assertRaises(g.GatewayError):
            g.initialize()
        with patch.dict(os.environ, {**self.ENV, "SERVER_ENDPOINT": "vps.example.com"}):
            g.initialize()
        self.assertEqual(g.load()["server_ip"], "vps.example.com")
        self.assertIn("Endpoint = vps.example.com:51820", g.render_client(g.load(), g.load()["peers"]["laptop"]))


class HttpTests(Sandbox):
    def setUp(self):
        super().setUp()
        g.commit(state_fixture(), apply=False)
        g.Handler.token = TOKEN
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), g.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def call(self, method, path, body=None, token=TOKEN):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-API-Token"] = token
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = conn.getresponse()
        data = json.loads(response.read())
        conn.close()
        return response.status, data

    def test_health_is_public_everything_else_needs_token(self):
        self.assertEqual(self.call("GET", "/health", token=None), (200, {"ok": True}))
        self.assertEqual(self.call("GET", "/status", token=None)[0], 401)
        self.assertEqual(self.call("GET", "/status", token="wrong")[0], 401)
        self.assertEqual(self.call("GET", "/status")[0], 200)

    def test_bearer_token_accepted(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        conn.request("GET", "/peers", headers={"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(conn.getresponse().status, 200)
        conn.close()

    def test_provision_with_client_key(self):
        status, data = self.call("POST", "/provision", {"name": "phone", "pubkey": CLIENT_PUB})
        self.assertEqual(status, 200)
        self.assertTrue(data["created"])
        self.assertTrue(data["client_keys"])
        self.assertEqual(data["address"], "10.77.0.3")
        self.assertEqual(data["endpoint"], "1.2.3.4")
        self.assertEqual(data["port"], 51820)
        self.assertNotIn("PrivateKey", data["config"])
        self.assertIn("PublicKey = SERVER_PUBLIC_TEST_ONLY", data["config"])

    def test_provision_without_key_returns_private_key(self):
        status, data = self.call("POST", "/provision", {"name": "phone"})
        self.assertEqual(status, 200)
        self.assertFalse(data["client_keys"])
        self.assertIn(f"PrivateKey = {DUMMY_KEYS[0]}", data["config"])

    def test_provision_rejects_bad_input(self):
        self.assertEqual(self.call("POST", "/provision", {"name": "Bad Name"})[0], 400)
        self.assertEqual(self.call("POST", "/provision", {"name": "phone", "pubkey": "nope"})[0], 400)
        self.assertEqual(self.call("POST", "/provision", ["list"])[0], 400)

    def test_sites_and_peers_lifecycle(self):
        status, data = self.call("PUT", "/sites/app.example.com", {"peer": "laptop", "port": 3000})
        self.assertEqual(status, 200)
        self.assertEqual(data["scheme"], "https")
        self.assertEqual(self.call("PUT", "/sites/1.2.3.4", {"peer": "laptop", "port": 3000})[0], 400)
        status, data = self.call("PUT", "/sites/1.2.3.4", {"peer": "laptop", "port": 3000, "allow_http": True})
        self.assertEqual((status, data["scheme"]), (200, "http"))
        self.assertEqual(len(self.call("GET", "/sites")[1]["sites"]), 2)
        self.assertEqual(self.call("DELETE", "/peers/laptop")[0], 409)
        status, data = self.call("DELETE", "/peers/laptop?remove_sites=1")
        self.assertEqual(status, 200)
        self.assertEqual(self.call("GET", "/sites")[1]["sites"], [])
        self.assertEqual(self.call("GET", "/peers/laptop")[0], 404)
        self.assertEqual(self.call("DELETE", "/sites/app.example.com")[0], 404)

    def test_ports_api(self):
        with patch.dict(os.environ, {"PORT_RANGE": "3000-3009"}):
            status, data = self.call("PUT", "/ports/3001", {"peer": "laptop"})
            self.assertEqual(status, 200)
            self.assertEqual((data["listen"], data["port"], data["target"]), (3001, 3001, "10.77.0.2:3001"))
            self.assertEqual(self.call("PUT", "/ports/3002", {"peer": "laptop", "port": 80})[1]["target"], "10.77.0.2:80")
            self.assertEqual(self.call("PUT", "/ports/9999", {"peer": "laptop"})[0], 400)
            self.assertEqual(self.call("PUT", "/ports/abc", {"peer": "laptop"})[0], 400)
            self.assertEqual([p["listen"] for p in self.call("GET", "/ports")[1]["ports"]], [3001, 3002])
            self.assertEqual(self.call("GET", "/status")[1]["port_range"], "3000-3009")
            self.assertEqual(self.call("DELETE", "/peers/laptop")[0], 409)
            self.assertEqual(self.call("DELETE", "/ports/3001")[0], 200)
            self.assertEqual(self.call("DELETE", "/ports/3001")[0], 404)

    def test_status_never_contains_secrets(self):
        status, data = self.call("GET", "/status")
        text = json.dumps(data)
        self.assertEqual(status, 200)
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn("PSK_TEST_ONLY", text)
        self.assertEqual(data["peers"][0]["online"], False)

    def test_check_uses_vpn_address(self):
        with patch.object(g.urllib.request, "urlopen", side_effect=g.urllib.error.URLError("timed out")):
            status, data = self.call("POST", "/peers/laptop/check", {"port": 3000})
        self.assertEqual(status, 200)
        self.assertFalse(data["ok"])
        self.assertEqual(data["url"], "http://10.77.0.2:3000/")

    def test_web_ui_is_served_without_token(self):
        for path, kind in (("/", "text/html"), ("/index.html", "text/html"), ("/wg-keys.js", "application/javascript")):
            conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
            conn.request("GET", path)
            response = conn.getresponse()
            body = response.read()
            conn.close()
            self.assertEqual(response.status, 200, path)
            self.assertIn(kind, response.getheader("Content-Type"))
            self.assertIn("default-src 'self'", response.getheader("Content-Security-Policy"))
            self.assertNotIn(b"PRIVATE_TEST_ONLY", body)
        self.assertIn("Public Gateway", (SOURCE / "api/static/index.html").read_text())
        self.assertEqual(self.call("GET", "/static/../gateway_api.py", token=None)[0], 401)
        self.assertEqual(self.call("GET", "/gateway_api.py")[0], 404)

    def test_unknown_route_and_oversized_body(self):
        self.assertEqual(self.call("GET", "/nope")[0], 404)
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        conn.request("POST", "/provision", body=b"{" + b" " * (g.MAX_BODY + 1) + b"}",
                     headers={"X-API-Token": TOKEN, "Content-Type": "application/json"})
        self.assertEqual(conn.getresponse().status, 413)
        conn.close()


if __name__ == "__main__":
    unittest.main()
