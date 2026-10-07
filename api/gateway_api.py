#!/usr/bin/env python3
"""Public Gateway API. Runs INSIDE the WireGuard container network namespace.

Python 3.10+, standard library only. Two modes:

  init   one-shot: create server keys from env on first run, regenerate the
         generated files (wg0.conf, Caddyfile) from state, then exit.
  serve  HTTP API on 0.0.0.0:8080 protected by the X-API-Token header.

Keys (read before editing)
--------------------------
Preferred flow: the client generates its own WireGuard pair and sends only
the public key (`pubkey` in POST /provision). The server never sees the
private key and returns a config WITHOUT a PrivateKey line; the client
inserts its own. The response then contains topology (addresses, server
public key, preshared key), not the client's identity.

Compatibility flow: a request without `pubkey` makes the server generate
the pair and return the full config including PrivateKey. That secret then
travels over whatever transport the API is exposed on (plain HTTP by
default), so prefer client-generated keys. Responses mark this with
`client_keys: false`.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import textwrap
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

STATE = Path(os.environ.get("PGW_STATE_FILE", "/state/gateway.json"))
WG_CONF = Path(os.environ.get("PGW_WG_CONF", "/wireguard/wg_confs/wg0.conf"))
CADDYFILE = Path(os.environ.get("PGW_CADDYFILE", "/etc/caddy/Caddyfile"))
CADDY_ADMIN = os.environ.get("PGW_CADDY_ADMIN", "http://127.0.0.1:2019")
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_FILES = {"": ("index.html", "text/html; charset=utf-8"),
                "index.html": ("index.html", "text/html; charset=utf-8"),
                "wg-keys.js": ("wg-keys.js", "application/javascript; charset=utf-8")}
WG_IFACE = "wg0"
WG_PORT = 51820
LISTEN_PORT = 8080
MAX_BODY = 64 * 1024
HANDSHAKE_ONLINE_SECONDS = 180
FAILOVER_HOLD = "30s"  # how long Caddy skips a device that failed before probing it again
MAX_BACKUPS = 4


def site_peers(site: dict[str, Any]) -> list[str]:
    """Primary device first, then backups in the order they were given."""
    return [site["peer"], *site.get("backups", [])]
API_VERSION = 2
RESERVED_PORTS = {LISTEN_PORT, 2019, WG_PORT}


def port_range_from_env() -> set[int]:
    """TCP ports published by compose for forwarding (PORT_RANGE=3000-3019), plus 80/443."""
    raw = os.environ.get("PORT_RANGE", "").strip()
    ports = {80, 443}
    if raw:
        match = re.fullmatch(r"(\d{1,5})-(\d{1,5})", raw)
        if not match:
            raise GatewayError("PORT_RANGE має вигляд 3000-3019.", 500)
        low, high = int(match.group(1)), int(match.group(2))
        if not 1 <= low <= high <= 65535 or high - low > 999:
            raise GatewayError("PORT_RANGE: початок <= кінець, не більше 1000 портів.", 500)
        ports |= set(range(low, high + 1))
    return ports - RESERVED_PORTS

LOCK = threading.Lock()


class GatewayError(Exception):
    """Client-facing error; `status` becomes the HTTP status code."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# --------------------------------------------------------------------------- files

def atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            os.fchmod(out.fileno(), mode)
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def log(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------------- validation

def name_ok(name: Any) -> str:
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name):
        raise GatewayError("Назва пристрою: 1–32 символи a-z, 0-9, _ або -; початок — літера.")
    return name


def host_ok(host: Any) -> str:
    # Reject Caddy tokens, URLs, paths, wildcard hosts and control characters.
    if not isinstance(host, str) or not host or any(c.isspace() for c in host) \
            or any(c in host for c in '/\\:{}$#*"\''):
        raise GatewayError("Вкажи лише домен або IPv4, без схеми, шляху чи порту.")
    host = host.rstrip(".").lower()
    try:
        return str(ipaddress.IPv4Address(host))
    except ipaddress.AddressValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise GatewayError("Некоректний домен.") from exc
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or labels[-1].isdigit():
        raise GatewayError("Потрібен повний домен, наприклад app.example.com.")
    if labels[-1] in {"local", "localhost", "test", "invalid"}:
        raise GatewayError("Ця зона не підходить для публічного HTTPS.")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels):
        raise GatewayError("Некоректний домен.")
    return host


def endpoint_ok(value: Any) -> str:
    """Public IPv4 or domain that clients use as WireGuard Endpoint."""
    host = host_ok(value)
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        return host
    if not address.is_global:
        raise GatewayError("SERVER_ENDPOINT має бути публічною IPv4-адресою або доменом.")
    return host


def port_ok(port: Any) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise GatewayError("Порт має бути цілим числом у межах 1–65535.")
    return port


def subnet_ok(value: Any) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.IPv4Network(str(value), strict=True)
    except ValueError as exc:
        raise GatewayError("Потрібна приватна IPv4-підмережа /24, наприклад 10.77.0.0/24.") from exc
    private = [ipaddress.IPv4Network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if net.prefixlen != 24 or not any(net.subnet_of(parent) for parent in private):
        raise GatewayError("Використай приватну RFC1918-підмережу /24.")
    return net


def mtu_ok(value: Any) -> int:
    try:
        mtu = int(value)
    except (TypeError, ValueError) as exc:
        raise GatewayError("WG_MTU має бути числом.") from exc
    if not 1280 <= mtu <= 1420:
        raise GatewayError("WG_MTU має бути в межах 1280–1420.")
    return mtu


def key_ok(value: Any) -> str:
    """A WireGuard key is exactly 32 bytes in base64 (44 characters)."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", value):
        raise GatewayError("pubkey має бути base64 від 32 байтів (44 символи).")
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise GatewayError("pubkey має бути base64 від 32 байтів (44 символи).")
    except (binascii.Error, ValueError) as exc:
        raise GatewayError("pubkey має бути base64 від 32 байтів (44 символи).") from exc
    return value


def token_from_env() -> str:
    token = os.environ.get("API_TOKEN", "")
    if len(token) < 16 or token.upper().startswith("CHANGE_ME"):
        raise GatewayError("API_TOKEN у .env має містити щонайменше 16 символів і не бути заглушкою.", 500)
    return token


# --------------------------------------------------------------------------- state

def load() -> dict[str, Any]:
    if not STATE.exists():
        raise GatewayError("Немає state. Сервіс init ще не виконувався.", 500)
    try:
        state = json.loads(STATE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise GatewayError(f"Не вдалося прочитати {STATE}: {exc}", 500) from exc
    if state.get("version") not in (1, 2):
        raise GatewayError("Непідтримувана версія state.", 500)
    state["version"] = 2
    for peer in state["peers"].values():
        peer.setdefault("private_key", None)
    state.setdefault("ports", {})
    for site in state["sites"].values():
        site.setdefault("backups", [])
    return state


def save(state: dict[str, Any]) -> None:
    atomic_write(STATE, json.dumps(state, ensure_ascii=False, indent=2) + "\n")


# --------------------------------------------------------------------------- wg / caddy

def wg(*args: str, stdin: str | None = None, timeout: int = 20) -> str:
    try:
        result = subprocess.run(["wg", *args], input=stdin, text=True, capture_output=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GatewayError(f"Не вдалося виконати wg: {exc}", 500) from exc
    if result.returncode:
        # stdout is never included: it may carry key material.
        raise GatewayError(f"wg {args[0]} завершився з кодом {result.returncode}: "
                           f"{result.stderr.strip()[-500:]}", 500)
    return result.stdout.strip()


def keyset() -> tuple[str, str, str]:
    private = wg("genkey")
    public = wg("pubkey", stdin=private + "\n")
    psk = wg("genpsk")
    for key in (private, public, psk):
        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", key):
            raise GatewayError("Генератор WireGuard повернув некоректні ключі.", 500)
    return private, public, psk


def wg_running() -> bool:
    try:
        subprocess.run(["wg", "show", WG_IFACE], capture_output=True, timeout=10, check=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def wg_sync(state: dict[str, Any]) -> None:
    """Apply peer list to the live interface without dropping it."""
    fd, name = tempfile.mkstemp(prefix=".sync-", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(render_sync(state))
        wg("syncconf", WG_IFACE, name)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def handshakes() -> dict[str, int]:
    try:
        output = wg("show", WG_IFACE, "latest-handshakes")
    except GatewayError:
        return {}
    result: dict[str, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            result[parts[0]] = int(parts[1])
    return result


def caddy_request(path: str, body: bytes | None = None, timeout: int = 10) -> tuple[int, bytes]:
    request = urllib.request.Request(CADDY_ADMIN + path, data=body, method="POST" if body else "GET")
    if body is not None:
        request.add_header("Content-Type", "text/caddyfile")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def caddy_running() -> bool:
    try:
        return caddy_request("/config/", timeout=3)[0] == 200
    except (urllib.error.URLError, OSError):
        return False


def caddy_validate(text: str) -> None:
    """Adapt the Caddyfile through the admin API; raises on syntax/semantic errors."""
    try:
        status, body = caddy_request("/adapt", text.encode())
    except (urllib.error.URLError, OSError) as exc:
        raise GatewayError(f"Caddy admin API недоступний: {exc}", 503) from exc
    if status != 200:
        raise GatewayError("Caddyfile не пройшов перевірку: " + body.decode(errors="replace")[:500], 500)


def caddy_load(text: str) -> None:
    try:
        status, body = caddy_request("/load", text.encode(), timeout=30)
    except (urllib.error.URLError, OSError) as exc:
        raise GatewayError(f"Caddy admin API недоступний: {exc}", 503) from exc
    if status != 200:
        raise GatewayError("Caddy не прийняв конфігурацію: " + body.decode(errors="replace")[:500], 500)


# --------------------------------------------------------------------------- tcp relay

class Relay:
    """Userspace TCP forwarder: VPS:listen -> peer_ip:port through wg0. Runs an asyncio loop in a thread."""

    CHUNK = 64 * 1024

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.servers: dict[int, asyncio.AbstractServer] = {}
        self.targets: dict[int, tuple[str, int]] = {}
        self.tasks: dict[int, set[asyncio.Task]] = {}
        self.thread = threading.Thread(target=self.loop.run_forever, name="relay", daemon=True)
        self.thread.start()

    def _call(self, coro: Any, timeout: int = 15) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def listening(self) -> dict[int, tuple[str, int]]:
        return dict(self.targets)

    def start(self, listen: int, ip: str, port: int) -> None:
        if self.targets.get(listen) == (ip, port):
            return
        if listen in self.servers:
            self.stop(listen)
        try:
            self._call(self._start(listen, ip, port))
        except OSError as exc:
            raise GatewayError(f"Порт {listen} зайнятий або недоступний у контейнері: {exc.strerror or exc}", 409) from exc
        self.targets[listen] = (ip, port)

    def stop(self, listen: int) -> None:
        if listen in self.servers:
            self._call(self._stop(listen))
        self.targets.pop(listen, None)

    def sync(self, state: dict[str, Any]) -> dict[int, str]:
        """Make listeners match state['ports']; returns {port: error} for listeners that failed."""
        desired = {int(k): (state["peers"][v["peer"]]["address"], v["port"])
                   for k, v in state["ports"].items() if v["peer"] in state["peers"]}
        errors: dict[int, str] = {}
        for listen in list(self.targets):
            if listen not in desired:
                self.stop(listen)
        for listen, (ip, port) in desired.items():
            try:
                self.start(listen, ip, port)
            except GatewayError as exc:
                errors[listen] = str(exc)
        return errors

    async def _start(self, listen: int, ip: str, port: int) -> None:
        self.tasks[listen] = set()

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = asyncio.current_task()
            self.tasks[listen].add(task)
            try:
                upstream = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=10)
            except (OSError, asyncio.TimeoutError, asyncio.CancelledError):
                writer.close()
                self.tasks.get(listen, set()).discard(task)
                return
            up_reader, up_writer = upstream
            try:
                await asyncio.gather(self._pump(reader, up_writer), self._pump(up_reader, writer))
            finally:
                for w in (writer, up_writer):
                    w.close()
                self.tasks.get(listen, set()).discard(task)

        self.servers[listen] = await asyncio.start_server(handle, "0.0.0.0", listen, reuse_address=True)

    async def _stop(self, listen: int) -> None:
        server = self.servers.pop(listen)
        server.close()
        for task in list(self.tasks.pop(listen, ())):
            task.cancel()
        await asyncio.sleep(0)

    async def _pump(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await reader.read(self.CHUNK)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
            if writer.can_write_eof():
                writer.write_eof()
        except (OSError, asyncio.CancelledError, ConnectionError):
            pass


RELAY: Relay | None = None


def relay() -> Relay:
    global RELAY
    if RELAY is None:
        RELAY = Relay()
    return RELAY


# --------------------------------------------------------------------------- rendering

def render_server(state: dict[str, Any]) -> str:
    lines = ["# Managed by the gateway API. Do not edit generated files.", "[Interface]",
             f"Address = {state['gateway_ip']}/24", f"ListenPort = {WG_PORT}",
             f"PrivateKey = {state['server_private']}", f"MTU = {state['mtu']}",
             "PostUp = /bin/sh /opt/gateway/vpn-firewall.sh up %i",
             "PostDown = /bin/sh /opt/gateway/vpn-firewall.sh down %i", ""]
    for name, peer in sorted(state["peers"].items()):
        lines.extend(["[Peer]", f"# {name}", f"PublicKey = {peer['public_key']}",
                      f"PresharedKey = {peer['preshared_key']}", f"AllowedIPs = {peer['address']}/32", ""])
    return "\n".join(lines)


def render_sync(state: dict[str, Any]) -> str:
    """wg(8)-only fields, suitable for `wg syncconf`."""
    lines = ["[Interface]", f"ListenPort = {WG_PORT}", f"PrivateKey = {state['server_private']}", ""]
    for name, peer in sorted(state["peers"].items()):
        lines.extend(["[Peer]", f"PublicKey = {peer['public_key']}",
                      f"PresharedKey = {peer['preshared_key']}", f"AllowedIPs = {peer['address']}/32", ""])
    return "\n".join(lines)


def render_client(state: dict[str, Any], peer: dict[str, Any]) -> str:
    if peer.get("private_key"):
        key_line = f"PrivateKey = {peer['private_key']}"
        header = "# PRIVATE: never share or commit this file. One device per config.\n"
    else:
        # Deliberately without the word "PrivateKey": clients detect this layout by its absence.
        key_line = "# приватний ключ підставляє клієнт — сервер його не знає"
        header = "# One device per config. Add your own private key under [Interface].\n"
    return (header +
            f"[Interface]\n{key_line}\nAddress = {peer['address']}/32\n"
            f"MTU = {state['mtu']}\n\n[Peer]\nPublicKey = {state['server_public']}\n"
            f"PresharedKey = {peer['preshared_key']}\nEndpoint = {state['server_ip']}:{WG_PORT}\n"
            f"AllowedIPs = {state['gateway_ip']}/32\nPersistentKeepalive = 25\n")


MAINTENANCE_HTML = """<!doctype html>
<html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60"><title>Ведуться технічні роботи</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;background:#f5f6f8;color:#1f2933;text-align:center}
main{padding:2rem;max-width:32rem}h1{font-size:1.6rem;margin:0 0 .75rem}p{margin:0;color:#52606d;line-height:1.5}</style></head>
<body><main><h1>Ведуться технічні роботи</h1><p>Сервіс тимчасово недоступний. Спробуй оновити сторінку за хвилину.</p></main></body></html>"""


def render_caddy(state: dict[str, Any]) -> str:
    lines = ["# Managed by the gateway API. Edit routes through PUT/DELETE /sites/<host>.",
             "{", "    admin localhost:2019", "    servers {", "        protocols h1 h2", "    }", "}", ""]
    if state["server_ip"] not in state["sites"]:
        lines.extend([f"http://{state['server_ip']} {{", "    header -Server",
                      '    respond "Gateway ready. No application published on this host." 404', "}", ""])
    for host, site in sorted(state["sites"].items()):
        upstreams = " ".join(f"{state['peers'][name]['address']}:{site['port']}" for name in site_peers(site))
        address = f"http://{host}" if site["http"] else host
        lines.extend([f"{address} {{", "    header -Server", "    encode zstd gzip",
                      f"    reverse_proxy {upstreams} {{"])
        if site.get("backups"):
            # Failover: upstreams are tried in order; one that cannot be reached is skipped for
            # FAILOVER_HOLD and the request is retried on the next one. Traffic returns to the
            # primary device by itself once it answers again. No assumptions about HTTP codes.
            lines.extend(["        lb_policy first", f"        lb_retries {len(site['backups'])}",
                          f"        fail_duration {FAILOVER_HOLD}", "        max_fails 1"])
        lines.extend(["        transport http {", "            dial_timeout 5s", "        }",
                      "    }",
                      # Device offline or app not listening: a maintenance page instead of a bare 502.
                      "    handle_errors 502 503 504 {", "        header -Server",
                      '        header Content-Type "text/html; charset=utf-8"',
                      "        header Retry-After 60", "        header Cache-Control no-store",
                      "        respond <<HTML", textwrap.indent(MAINTENANCE_HTML, " " * 8), "        HTML 503",
                      "    }", "}", ""])
    # Access logging is intentionally not enabled. Operational errors can still contain metadata.
    return "\n".join(lines)


def write_generated(state: dict[str, Any]) -> None:
    atomic_write(WG_CONF, render_server(state))
    atomic_write(CADDYFILE, render_caddy(state), 0o644)


# --------------------------------------------------------------------------- commit

def apply_running(state: dict[str, Any], *, wireguard: bool = True, caddy: bool = True) -> dict[str, bool]:
    applied = {"wireguard": False, "caddy": False}
    try:
        if wireguard and wg_running():
            wg_sync(state)
            applied["wireguard"] = True
        if caddy and caddy_running():
            caddy_load(render_caddy(state))
            applied["caddy"] = True
        if RELAY is not None:
            errors = RELAY.sync(state)
            applied["ports"] = not errors
            if errors:
                raise GatewayError("порти: " + "; ".join(f"{k}: {v}" for k, v in errors.items()), 500)
    except GatewayError as exc:
        raise GatewayError("Конфігурацію збережено, але НЕ підтверджено її застосування. "
                           "Зокрема, відкликаний peer може ще діяти. Виконай POST /apply або "
                           "перезапусти проєкт. " + str(exc), 500) from exc
    return applied


def commit(state: dict[str, Any], *, wireguard: bool = True, caddy: bool = True,
           apply: bool = True) -> dict[str, bool]:
    caddyfile = render_caddy(state)
    if apply and caddy and caddy_running():
        caddy_validate(caddyfile)
    # State is authoritative. A crash between writes is repaired with POST /apply.
    save(state)
    write_generated(state)
    if not apply:
        return {"wireguard": False, "caddy": False}
    return apply_running(state, wireguard=wireguard, caddy=caddy)


# --------------------------------------------------------------------------- operations

def peer_public(state: dict[str, Any], name: str, peer: dict[str, Any],
                hs: dict[str, int] | None = None) -> dict[str, Any]:
    info = {"name": name, "address": peer["address"], "client_keys": not peer.get("private_key"),
            "sites": sorted(h for h, s in state["sites"].items() if s["peer"] == name),
            "backup_sites": sorted(h for h, s in state["sites"].items() if name in s.get("backups", [])),
            "ports": sorted(int(k) for k, v in state["ports"].items() if v["peer"] == name)}
    if hs is not None:
        stamp = hs.get(peer["public_key"], 0)
        info["last_handshake"] = stamp or None
        info["online"] = bool(stamp) and time.time() - stamp < HANDSHAKE_ONLINE_SECONDS
    return info


def site_public(host: str, site: dict[str, Any]) -> dict[str, Any]:
    return {"host": host, "peer": site["peer"], "backups": list(site.get("backups", [])), "port": site["port"],
            "scheme": "http" if site["http"] else "https"}


def port_public(state: dict[str, Any], listen: str, entry: dict[str, Any]) -> dict[str, Any]:
    active = RELAY is not None and int(listen) in RELAY.listening()
    return {"listen": int(listen), "peer": entry["peer"], "port": entry["port"],
            "target": f"{state['peers'][entry['peer']]['address']}:{entry['port']}", "active": active}


def provision(state: dict[str, Any], name: str, pubkey: str | None) -> tuple[dict[str, Any], bool, dict[str, bool]]:
    """Create or return a peer. Returns (peer, created, applied)."""
    created, changed = False, False
    peer = state["peers"].get(name)
    if peer is None:
        index = state["next_host"]
        if index > 254:
            raise GatewayError("Адреси /24 вичерпано; повторне використання адрес вимкнено.", 409)
        address = str(subnet_ok(state["subnet"])[index])
        private, public, psk = keyset()
        peer = {"address": address, "public_key": public, "private_key": private, "preshared_key": psk}
        if pubkey:
            peer["public_key"], peer["private_key"] = pubkey, None
        state["peers"][name] = peer
        state["next_host"] += 1
        created = changed = True
    elif pubkey:
        if peer["public_key"] != pubkey or peer.get("private_key"):
            # Client (re)generated its pair: adopt it and forget any server-side private key.
            peer["public_key"], peer["private_key"] = pubkey, None
            changed = True
    elif not peer.get("private_key"):
        raise GatewayError(f"Пристрій {name} використовує власний ключ; передай pubkey у запиті.", 409)
    applied = commit(state, caddy=False) if changed else {"wireguard": False, "caddy": False}
    return peer, created, applied


def revoke(state: dict[str, Any], name: str, remove_sites: bool) -> dict[str, bool]:
    if name not in state["peers"]:
        raise GatewayError("Немає такого пристрою.", 404)
    sites = [host for host, site in state["sites"].items() if site["peer"] == name]
    ports = [k for k, v in state["ports"].items() if v["peer"] == name]
    if (sites or ports) and not remove_sites:
        raise GatewayError("На пристрій є маршрути/порти: " + ", ".join(sites + ports) +
                           ". Спочатку перемкни їх або додай ?remove_sites=1.", 409)
    for host in sites:
        del state["sites"][host]
    for site in state["sites"].values():
        site["backups"] = [b for b in site.get("backups", []) if b != name]
    for key in ports:
        del state["ports"][key]
    del state["peers"][name]
    return commit(state)


def port_put(state: dict[str, Any], listen: int, peer: str, port: int) -> dict[str, bool]:
    if peer not in state["peers"]:
        raise GatewayError("Спочатку створи пристрій через POST /provision.", 404)
    allowed = port_range_from_env()
    if listen not in allowed:
        raise GatewayError(f"Порт {listen} не опублікований. Дозволені: 80, 443 і PORT_RANGE з .env "
                           f"({os.environ.get('PORT_RANGE') or 'не задано'}); зміни .env і виконай docker compose up -d.")
    if listen in (80, 443) and caddy_running():
        raise GatewayError(f"Порт {listen} зайнятий Caddy. Щоб прокинути його на пристрій, встанови "
                           "CADDY_REPLICAS=0 у .env і виконай docker compose up -d.", 409)
    address = state["peers"][peer]["address"]
    if RELAY is not None:
        RELAY.start(listen, address, port)  # validates that the port can be bound before saving
    state["ports"][str(listen)] = {"peer": peer, "port": port}
    save(state)
    return {"wireguard": False, "caddy": False, "ports": RELAY is not None}


def port_remove(state: dict[str, Any], listen: int) -> dict[str, bool]:
    if str(listen) not in state["ports"]:
        raise GatewayError("Немає такого прокинутого порту.", 404)
    del state["ports"][str(listen)]
    save(state)
    if RELAY is not None:
        RELAY.stop(listen)
    return {"wireguard": False, "caddy": False, "ports": RELAY is not None}


def backups_ok(value: Any, peer: str, state: dict[str, Any]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_BACKUPS:
        raise GatewayError(f"backups має бути списком щонайбільше з {MAX_BACKUPS} назв пристроїв.")
    backups: list[str] = []
    for item in value:
        name = name_ok(item)
        if name == peer or name in backups:
            raise GatewayError("Резервний пристрій має відрізнятися від основного і не повторюватися.")
        if name not in state["peers"]:
            raise GatewayError(f"Немає резервного пристрою {name}.", 404)
        backups.append(name)
    return backups


def site_put(state: dict[str, Any], host: str, peer: str, port: int, allow_http: bool,
             backups: Any = None) -> dict[str, bool]:
    if peer not in state["peers"]:
        raise GatewayError("Спочатку створи пристрій через POST /provision.", 404)
    backups = backups_ok(backups, peer, state)
    try:
        ipaddress.IPv4Address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip and (host != state["server_ip"] or not allow_http):
        raise GatewayError("IP-маршрут дозволено лише для адреси цього VPS і лише з allow_http=true.")
    state["sites"][host] = {"peer": peer, "backups": backups, "port": port, "http": is_ip}
    return commit(state, wireguard=False)


def site_remove(state: dict[str, Any], host: str) -> dict[str, bool]:
    if host not in state["sites"]:
        raise GatewayError("Немає такого маршруту.", 404)
    del state["sites"][host]
    return commit(state, wireguard=False)


def check_peer(state: dict[str, Any], name: str, port: int) -> dict[str, Any]:
    """HTTP GET to the device through the VPN; any HTTP response means the tunnel works."""
    if name not in state["peers"]:
        raise GatewayError("Немає такого пристрою.", 404)
    url = f"http://{state['peers'][name]['address']}:{port}/"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=8) as response:
            return {"ok": True, "url": url, "http_status": response.status}
    except urllib.error.HTTPError as exc:
        return {"ok": True, "url": url, "http_status": exc.code,
                "note": "HTTP-відповідь отримано; код може бути нормальною відповіддю програми на /."}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"ok": False, "url": url, "error": str(getattr(exc, "reason", exc))}


# --------------------------------------------------------------------------- init

def initialize() -> None:
    endpoint = endpoint_ok(os.environ.get("SERVER_ENDPOINT", ""))
    net = subnet_ok(os.environ.get("VPN_SUBNET", "10.77.0.0/24"))
    mtu = mtu_ok(os.environ.get("WG_MTU", "1380"))
    token_from_env()
    for path in (STATE.parent, WG_CONF.parent):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.chmod(0o700)
    if STATE.exists():
        state = load()
        if state["subnet"] != str(net):
            if state["peers"]:
                raise GatewayError(f"VPN_SUBNET у .env ({net}) не збігається зі state ({state['subnet']}), "
                                   "а пристрої вже є. Поверни попереднє значення або видали data/state.", 500)
            state["subnet"], state["gateway_ip"], state["next_host"] = str(net), str(net[1]), 2
        state["server_ip"], state["mtu"] = endpoint, mtu
        commit(state, apply=False)
        log(f"State існує: {len(state['peers'])} пристроїв, {len(state['sites'])} маршрутів. "
            "Згенеровані файли оновлено.")
        return
    private, public, _ = keyset()
    state = {"version": 2, "server_ip": endpoint, "subnet": str(net), "gateway_ip": str(net[1]),
             "mtu": mtu, "next_host": 2, "server_private": private, "server_public": public,
             "peers": {}, "sites": {}}
    commit(state, apply=False)
    log(f"Ініціалізовано. Endpoint {endpoint}:{WG_PORT}, VPN {net}, шлюз {net[1]}.")


# --------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "public-gateway"
    sys_version = ""
    token: str = ""

    def log_message(self, fmt: str, *args: Any) -> None:  # paths never carry secrets
        log("%s %s" % (self.address_string(), fmt % args))

    # -- helpers
    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = (json.dumps(payload, ensure_ascii=False) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_static(self, key: str) -> None:
        filename, content_type = STATIC_FILES[key]
        try:
            body = (STATIC_DIR / filename).read_bytes()
        except OSError:
            self.send_json(404, {"ok": False, "error": "Вебінтерфейс не знайдено в образі."})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
                         "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
                         "frame-ancestors 'none'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def authorized(self) -> bool:
        provided = self.headers.get("X-API-Token", "")
        auth = self.headers.get("Authorization", "")
        if not provided and auth.startswith("Bearer "):
            provided = auth[7:].strip()
        return bool(provided) and hmac.compare_digest(provided.encode(), self.token.encode())

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise GatewayError("Завеликий запит.", 413)
        raw = self.rfile.read(length) if length else b""
        if not raw.strip():
            return {}
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GatewayError(f"Очікується JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise GatewayError("Очікується JSON-об'єкт.")
        return data

    def split(self) -> tuple[list[str], dict[str, str]]:
        path, _, query = self.path.partition("?")
        parts = [p for p in path.split("/") if p]
        params: dict[str, str] = {}
        for item in query.split("&"):
            key, _, value = item.partition("=")
            if key:
                params[key] = value
        return parts, params

    # -- dispatch
    def do_GET(self) -> None:
        self.dispatch()

    def do_HEAD(self) -> None:
        self.dispatch()

    def do_POST(self) -> None:
        self.dispatch()

    def do_PUT(self) -> None:
        self.dispatch()

    def do_DELETE(self) -> None:
        self.dispatch()

    def dispatch(self) -> None:
        parts, params = self.split()
        if parts == ["health"] and self.command == "GET":
            self.send_json(200, {"ok": True})
            return
        if self.command == "GET" and "/".join(parts) in STATIC_FILES:
            self.send_static("/".join(parts))
            return
        if not self.authorized():
            self.send_json(401, {"ok": False, "error": "Bad API token"})
            return
        try:
            with LOCK:
                status, payload = self.route(parts, params)
        except GatewayError as exc:
            self.send_json(exc.status, {"ok": False, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - report, never leak a traceback with secrets
            log(f"Внутрішня помилка: {type(exc).__name__}: {exc}")
            self.send_json(500, {"ok": False, "error": f"Внутрішня помилка: {type(exc).__name__}"})
        else:
            self.send_json(status, payload)

    def route(self, parts: list[str], params: dict[str, str]) -> tuple[int, dict[str, Any]]:
        method = self.command
        state = load()
        if parts == ["status"] and method == "GET":
            hs = handshakes()
            return 200, {"ok": True, "api_version": API_VERSION, "endpoint": f"{state['server_ip']}:{WG_PORT}",
                         "subnet": state["subnet"], "gateway_ip": state["gateway_ip"], "mtu": state["mtu"],
                         "wireguard_running": wg_running(), "caddy_running": caddy_running(),
                         "port_range": os.environ.get("PORT_RANGE", ""),
                         "peers": [peer_public(state, n, p, hs) for n, p in sorted(state["peers"].items())],
                         "sites": [site_public(h, s) for h, s in sorted(state["sites"].items())],
                         "ports": [port_public(state, k, v) for k, v in sorted(state["ports"].items(), key=lambda kv: int(kv[0]))]}
        if parts == ["provision"] and method == "POST":
            body = self.read_json()
            name = name_ok(body.get("name"))
            pubkey = body.get("pubkey")
            if pubkey is not None:
                pubkey = key_ok(pubkey)
            peer, created, applied = provision(state, name, pubkey)
            return 200, {"ok": True, "api_version": API_VERSION, "name": name, "created": created,
                         "address": peer["address"], "network": state["subnet"],
                         "gateway_ip": state["gateway_ip"], "endpoint": state["server_ip"], "port": WG_PORT,
                         "client_keys": not peer.get("private_key"),
                         "config": render_client(state, peer), "applied": applied}
        if parts == ["peers"] and method == "GET":
            hs = handshakes()
            return 200, {"ok": True, "peers": [peer_public(state, n, p, hs) for n, p in sorted(state["peers"].items())]}
        if len(parts) >= 2 and parts[0] == "peers":
            name = name_ok(parts[1])
            if len(parts) == 2 and method == "GET":
                if name not in state["peers"]:
                    raise GatewayError("Немає такого пристрою.", 404)
                return 200, {"ok": True, **peer_public(state, name, state["peers"][name], handshakes())}
            if len(parts) == 2 and method == "DELETE":
                applied = revoke(state, name, params.get("remove_sites", "") in ("1", "true", "yes"))
                return 200, {"ok": True, "deleted": name, "applied": applied,
                             "note": "Адреса не буде видана повторно."}
            if len(parts) == 3 and parts[2] == "check" and method == "POST":
                body = self.read_json()
                return 200, check_peer(state, name, port_ok(body.get("port")))
        if parts == ["sites"] and method == "GET":
            return 200, {"ok": True, "sites": [site_public(h, s) for h, s in sorted(state["sites"].items())]}
        if len(parts) == 2 and parts[0] == "sites":
            host = host_ok(parts[1])
            if method == "PUT":
                body = self.read_json()
                applied = site_put(state, host, name_ok(body.get("peer")), port_ok(body.get("port")),
                                   body.get("allow_http") is True, body.get("backups"))
                site = site_public(host, state["sites"][host])
                note = ("УВАГА: браузер -> VPS незашифрований. HTTP за IP — лише для тесту."
                        if site["scheme"] == "http" else
                        f"DNS: A {host} -> {state['server_ip']}; відкрий 80/TCP і 443/TCP. "
                        "Сертифікат видається після перевірки домену.")
                return 200, {"ok": True, **site, "applied": applied, "note": note}
            if method == "DELETE":
                return 200, {"ok": True, "deleted": host, "applied": site_remove(state, host)}
        if parts == ["ports"] and method == "GET":
            return 200, {"ok": True, "ports": [port_public(state, k, v) for k, v in sorted(state["ports"].items(), key=lambda kv: int(kv[0]))]}
        if len(parts) == 2 and parts[0] == "ports":
            if not parts[1].isdigit():
                raise GatewayError("Порт має бути числом.")
            listen = port_ok(int(parts[1]))
            if method == "PUT":
                body = self.read_json()
                peer = name_ok(body.get("peer"))
                target = port_ok(body.get("port", listen))
                applied = port_put(state, listen, peer, target)
                return 200, {"ok": True, **port_public(state, str(listen), state["ports"][str(listen)]), "applied": applied,
                             "note": f"TCP {state['server_ip']}:{listen} -> {peer}:{target}. Трафік передається як є, без TLS на VPS; "
                                     "програма бачить з'єднання з адреси шлюзу."}
            if method == "DELETE":
                return 200, {"ok": True, "deleted": listen, "applied": port_remove(state, listen)}
        if parts == ["apply"] and method == "POST":
            if caddy_running():
                caddy_validate(render_caddy(state))
            write_generated(state)
            return 200, {"ok": True, "applied": apply_running(state)}
        raise GatewayError("Немає такого маршруту API.", 404)


def serve() -> None:
    Handler.token = token_from_env()
    state = load()  # fail fast if init never ran
    port_range_from_env()
    errors = relay().sync(state)
    for listen, error in errors.items():
        log(f"УВАГА: порт {listen} не піднято: {error}")
    if state["ports"]:
        log(f"Прокинуті TCP-порти: {', '.join(sorted(state['ports']))}.")
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    server.daemon_threads = True
    log(f"API слухає 0.0.0.0:{LISTEN_PORT} у мережевому просторі WireGuard.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "serve"
    os.umask(0o077)
    try:
        if mode == "init":
            initialize()
        elif mode == "serve":
            serve()
        else:
            raise GatewayError(f"Невідомий режим {mode}; доступні: init, serve.")
    except GatewayError as exc:
        print(f"ПОМИЛКА: {exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
