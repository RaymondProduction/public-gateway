# Public Gateway — WireGuard + Caddy + API

Version 0.2.0. A project for a Linux VPS with a public IPv4 address. The examples target Ubuntu 24.04; the server address `203.0.113.10` used in the examples is a placeholder, substitute your own.

Getting started takes two steps: fill in `.env` and run `docker compose up -d --build`. Everything else is managed through the web interface on port `8080` or through HTTP requests to the same API with the `X-API-Token` header: a device sends its WireGuard public key and receives a ready-to-use configuration. Keys are created on the first start on your VPS; the repository contains no ready-made secrets.

## What it does

A laptop or any other device establishes a WireGuard connection to the VPS. Caddy on the VPS receives a web request and forwards it to the right device through the VPN. The public address does not depend on the laptop's current external address.

```text
Browser -> HTTPS on VPS:443 -> Caddy -> WireGuard -> laptop:3000
                                          |
                           another domain -> another device:8080

Browser -> http://VPS:8080 (web interface) --\
                                              +-> API -> creates peer / route,
curl -> VPS:8080 (X-API-Token) ---------------/          applies to the live wg0 and Caddy
```

Several devices, several domains, HTTP applications/APIs and WebSocket are supported through the standard Caddy reverse proxy [2]. A route can be switched to another device with a single request. Access by IP is limited to explicitly allowed test HTTP, with no encryption between the browser and the VPS.

This version has no web panel beyond the built-in interface, no database/file synchronisation, no TCP/UDP proxy for arbitrary protocols, no IPv6 publishing, no TLS passthrough, no DNS API and no automatic deployment of the application itself. A single VPS remains the only entry point. An application on a switched-off laptop does not become reachable through the gateway: the visitor sees a "maintenance in progress" page unless the route has a backup device.

## Requirements

On the VPS: Linux with WireGuard support in the kernel, Docker Engine and the Docker Compose plugin 2.20+. Python is not needed on the host: all logic runs in containers. The WireGuard container needs `NET_ADMIN`; `privileged`, `SYS_MODULE`, host networking and the Docker socket are not given to any container. Kernel modules are loaded by a separate script on the host [1, 4].

VPS ports: `51820/UDP` for WireGuard, `80/TCP` and `443/TCP` for web access, `8080/TCP` for the API (changed through `API_PORT`). Do not close SSH. The Caddy Admin API port `2019` is not published externally.

If your provider has an external firewall/security group, allow the required ports there. **Do not rely on UFW alone to filter published Docker ports**: Docker can route this traffic past UFW rules [5]. The scripts do not change SSH or the host firewall.

A domain needs a correct DNS A record pointing to the VPS and reachable ports for the certificate check. Caddy automates HTTPS for domains [3]. Do not create an AAAA record for this gateway without separately configured IPv6.

## 1. Start on the VPS

Copy the project directory to the VPS (for example `scp -r public-gateway root@203.0.113.10:/opt/`). Then on the **VPS** as root:

```bash
apt update && apt install -y kmod
cd /opt/public-gateway
chmod +x scripts/*.sh
./scripts/prepare-host.sh            # wireguard/iptables kernel modules + autoload

cp .env.example .env
nano .env                            # SERVER_ENDPOINT and API_TOKEN are required
# API_TOKEN can be generated with: openssl rand -hex 24

docker compose up -d --build --wait
docker compose ps
```

`.env` variables:

| Variable | Purpose |
|---|---|
| `SERVER_ENDPOINT` | Public IPv4 or domain of the VPS; goes into `Endpoint` of client configs |
| `API_TOKEN` | Secret for the `X-API-Token` header, at least 16 characters |
| `VPN_SUBNET` | Private /24 for the VPN, default `10.77.0.0/24`; change only before the first start |
| `WG_MTU` | Tunnel MTU, default 1380 |
| `PORT_RANGE` | TCP ports that can be forwarded 1:1 to a device, default `3000-3019`; published at start |
| `CADDY_REPLICAS` | `0` disables Caddy and frees 80/443 for forwarding to a device |
| `API_BIND` | `0.0.0.0` (default, API reachable from the internet) or `127.0.0.1` (only from the VPS) |
| `API_PORT` | API port on the VPS, default 8080 |
| `WIREGUARD_IMAGE`, `CADDY_IMAGE` | Optional pinning of images by digest |

What happens during `up`: the one-shot `init` service creates the server WireGuard keys (on the first start only), writes `data/state/gateway.json` and generates `wg0.conf` and the `Caddyfile`. Then `wireguard`, `caddy` and `api` start. Repeated `up` runs do not overwrite the keys; a change of `SERVER_ENDPOINT` or `WG_MTU` in `.env` is applied on the next `up`, a change of `VPN_SUBNET` is blocked while devices exist.

While there are no routes, the IP address answers only with a plain-text HTTP 404 stub: no application is published automatically.

If a route exists but the device is switched off, offline, or the application on it is not listening on the port, Caddy shows a "maintenance in progress" page with status 503 and a `Retry-After` header instead of a bare error. The page reloads itself once a minute, so once the device is back online the application appears without any action by the visitor.

**About the API transport.** By default the API listens on all interfaces over **plain HTTP**, like the reference provisioning service. The token and the responses (addresses, server public key, preshared key) travel in clear text. If a device sends its own `pubkey`, the client private key never crosses the network at all. For a tighter setup set `API_BIND=127.0.0.1` and reach the API through an SSH tunnel from the laptop: `ssh -L 8080:127.0.0.1:8080 root@203.0.113.10`, then send requests to `http://127.0.0.1:8080`.

## 2. Connect a device

### Web interface

Open `http://203.0.113.10:8080` in a browser and enter `API_TOKEN` from `.env`. The interface is in Ukrainian; the sections are:

- **Connect device** («Підключити пристрій») — enter a name and click "Get configuration". The WireGuard key pair is generated **in the browser**; only the public key goes to the server and the private key is inserted into the config locally. Then "Download .conf", "Copy" or "Show QR for phone" (the QR code is scanned by the WireGuard app on Android/iOS). Save the file right away: after a page reload the private key cannot be recovered, and a repeated request with the same name issues a new key and replaces the old one.
- The "let the server generate" option returns a full config including the private key, for devices without `wg`. The key then travels over whatever transport the API is reachable on.
- **Devices** («Пристрої») — the list with VPN addresses, online state based on the last handshake and a "Revoke" button. "online" only means the WireGuard tunnel is alive, not that the application is running.
- **Public routes** («Публічні маршрути») — add a domain or test HTTP by IP, switch a domain to another device, set a backup device. The "Application state" column shows whether the application answers on the port of each device of the route through the VPN: the gateway sends an HTTP request to it on every page refresh. "available via backup" means the primary device does not answer and traffic goes to the backup; "unavailable" means visitors currently see the maintenance page.

The page and `wg-keys.js` are served without a token but contain no secrets; every action calls the API with the `X-API-Token` header. By default the token is kept only for the lifetime of the tab; the "remember in this browser" checkbox stores it in `localStorage`. The QR code is drawn by a library from cdnjs; without CDN access, download and copy still work.

### Linux: script

On the **laptop**, in the project directory:

```bash
sudo apt install -y wireguard-tools curl python3
sudo API_TOKEN='your_token' ./scripts/connect-client.sh http://203.0.113.10:8080 laptop
```

The script generates a private key in `/etc/wireguard/pgw0.key` (only if it does not exist yet), sends the public key to `POST /provision`, inserts the private key into the response, saves `/etc/wireguard/pgw0.conf` and enables `wg-quick@pgw0`. Running it again with the same name returns the same address. Run it on the client device, **not on the VPS**.

Check on the laptop:

```bash
sudo wg show pgw0
ping -c 3 10.77.0.1
```

### Any OS: manually

```bash
# on the device: your own key pair
wg genkey | tee private.key | wg pubkey > public.key

curl -X POST http://203.0.113.10:8080/provision \
  -H "X-API-Token: your_token" -H "Content-Type: application/json" \
  -d "{\"name\":\"phone\",\"pubkey\":\"$(cat public.key)\"}"
```

The `config` field of the response holds a configuration without the `PrivateKey` line: add `PrivateKey = <contents of private.key>` to the `[Interface]` section and import it into the WireGuard client [7]. Every device must have its own name and its own key. Do not run one config on two devices at the same time.

A request **without** `pubkey` makes the server generate the pair itself and return the full config together with `PrivateKey` (`"client_keys": false`). This is convenient for a phone without `wg`, but the secret then travels over whatever transport the API is reachable on. For that case prefer `API_BIND=127.0.0.1` plus an SSH tunnel.

The client `AllowedIPs` contains only `10.77.0.1/32`: the device's regular internet traffic and DNS are not routed through the VPS. `PersistentKeepalive = 25` keeps the NAT mapping alive for inbound traffic [6].

## 3. Test with the safe demo application

On the **laptop**:

```bash
python3 examples/demo_app.py --bind 10.77.0.2 --port 3000
```

If UFW is enabled on the laptop, add a narrow rule **on the laptop**: `sudo ufw allow in on pgw0 from 10.77.0.1 to any port 3000 proto tcp`.

On the **VPS** or through the SSH tunnel:

```bash
A=http://203.0.113.10:8080; T="X-API-Token: your_token"

curl -X POST $A/peers/laptop/check -H "$T" -d '{"port":3000}'
curl -X PUT $A/sites/203.0.113.10 -H "$T" \
  -d '{"peer":"laptop","port":3000,"allow_http":true}'
```

Open `http://203.0.113.10` in a browser. The expected result is the text "Public Gateway працює!" produced by the laptop. **Do not enter passwords or send private data through this HTTP test.**

## 4. Connect a real application and a domain

The application must accept HTTP connections on its VPN address and the required port. Listening only on `127.0.0.1:3000` gives the VPS no access. The narrowest option is `10.77.0.2:3000`. For an application in Docker on the laptop: `ports: ["10.77.0.2:3000:3000"]`, and listen on `0.0.0.0:3000` inside the container; bring up WireGuard first, then the container.

Create a DNS record `A app.example.com 203.0.113.10` (your real domain), then:

```bash
curl -X PUT $A/sites/app.example.com -H "$T" -d '{"peer":"laptop","port":3000}'
docker compose logs -f caddy      # Ctrl+C only leaves the log view
```

Check `https://app.example.com`. After HTTPS works, remove the temporary IP route:

```bash
curl -X DELETE $A/sites/203.0.113.10 -H "$T"
```

The gateway does not add authentication automatically. Before publishing real data the application must have its own login and access control. Configure allowed hosts, CORS and `X-Forwarded-*` handling in it, trusting only the gateway address. Do not publish debug panels, databases or the Docker API.

## 4a. Forward a port as is (TCP)

When `203.0.113.10:3001` should lead to port 3001 of the laptop without a domain and without an HTTP proxy:

```bash
# on the laptop the application listens on the VPN address (or 0.0.0.0), e.g. 10.77.0.3:3001
curl -X PUT $A/ports/3001 -H "$T" -d '{"peer":"laptop"}'
# a different port on the device: -d '{"peer":"laptop","port":8080}'
curl -X DELETE $A/ports/3001 -H "$T"
```

The same is available in the web interface under "Forwarded ports" («Прокинуті порти»). Available ports: 80, 443 and the `PORT_RANGE` from `.env`; a different range needs `docker compose up -d` (the WireGuard container is recreated, the tunnel drops for a few seconds). Ports 80/443 can be forwarded only when Caddy is disabled (`CADDY_REPLICAS=0`): HTTPS and domains are then handled by whatever listens on the device, or by your own proxy on the VPS that talks to `127.0.0.1:<port>`.

The relay runs in user space inside the `api` container and passes bytes through unchanged: it suits any TCP protocol, TLS passes end to end. The application on the device sees the connection coming from the gateway address `10.77.0.1`, not from the real client address. UDP is not forwarded. These ports are not reachable from VPN addresses, only from the internet.

## 5. API

Every request except `GET /health` needs the `X-API-Token: <API_TOKEN>` header (`Authorization: Bearer <API_TOKEN>` is accepted as well). The body is JSON. Responses contain `"ok"` and, for changes, `"applied": {"wireguard": bool, "caddy": bool}` showing what was applied to the running containers.

| Method and path | Purpose |
|---|---|
| `GET /`, `GET /wg-keys.js` | No token; web interface |
| `GET /health` | No token; for the healthcheck |
| `GET /status` | Endpoint, subnet, wg/caddy state, devices with `online`, routes. No secrets |
| `POST /provision` `{"name","pubkey"?}` | Create or return a device; `config` is the client configuration |
| `GET /peers`, `GET /peers/{name}` | List/one device, `online` based on the last handshake (< 180 s) |
| `DELETE /peers/{name}?remove_sites=1` | Revoke the key; without `remove_sites` it refuses if routes or ports exist |
| `POST /peers/{name}/check` `{"port"}` | HTTP GET to the application FROM INSIDE the VPN; any HTTP response means the tunnel works |
| `GET /sites` | Routes |
| `PUT /sites/{host}` `{"peer","port","allow_http"?,"backups"?}` | Add or switch a route; IP only for the VPS address with `allow_http: true`; `backups` is a list of up to 4 backup devices |
| `DELETE /sites/{host}` | Remove the route, keep the device |
| `GET /ports` | Forwarded TCP ports |
| `PUT /ports/{n}` `{"peer","port"?}` | Forward `VPS:n` to `device:port` (same port by default) |
| `DELETE /ports/{n}` | Remove the forwarding |
| `POST /apply` | Regenerate files from state and apply to the running containers |

Switching a domain to another device is the same `PUT /sites/{host}` with a different `peer`. It is a route change, **not a copy of the application, database or sessions**; current connections/WebSockets may drop.

### Automatic failover

A route can have backup devices: the "Backup device" («Резервний пристрій») field in the web interface, `backups` in the API:

```bash
curl -X PUT $A/sites/app.example.com -H "$T" -d '{"peer":"laptop","port":3000,"backups":["desktop"]}'
```

Caddy keeps all devices of the route as upstream addresses in the given order and always sends traffic to the first one it can connect to. If the connection to the primary fails (device offline, port not listening), the request is retried on the backup at that very moment, and the primary is not tried again for the next 30 s. After that Caddy probes the primary again, and as soon as it answers, traffic returns to it without manual action. Only when all devices of the route are unreachable does the visitor see the maintenance page. Failover relies only on the ability to connect, so the application's response codes (401, 404 and so on) do not affect it.

Things to know: all devices of the route must run the same application on the same port; the gateway does not synchronise data between devices, so after a failover visitors see the application state on the other device; while the primary device is offline, one request every 30 s is delayed by up to 5 s for the connection attempt to it. Revoking a backup device simply removes it from the list, the route stays on the primary.

An apply error (`HTTP 500` with the text «НЕ підтверджено її застосування», "application not confirmed") means that the desired state was saved but the actual state may differ: check `GET /status`, run `POST /apply` or `docker compose restart`. In particular, do not consider a key revoked after such a message.

New addresses are allocated sequentially and never reused after revocation. For a /24 the limit is 253 issued addresses over the lifetime of the configuration.

## Managing the containers

```bash
docker compose ps
docker compose logs -f api            # API requests, apply errors
docker compose logs -f wireguard      # tunnel bring-up
docker compose logs -f caddy          # certificates, proxy
docker compose exec wireguard wg show wg0
docker compose down                   # stop without deleting data
docker compose up -d --wait           # start; init regenerates files from state
```

## How it is built and what is stored

Caddy and the API use `network_mode: service:wireguard`, so they see the `wg0` interface and the device addresses in the same network namespace. External ports are published on the WireGuard container [4]. The API applies changes without restarts: `wg syncconf` for peers, Caddy Admin API `/load` for routes [10], and forwarded ports are listened on by the `api` container itself in the same network namespace. Packet forwarding between peers and internet egress through the VPS are disabled. The `vpn-firewall.sh` rules allow replies to outbound requests and diagnostic ping, but block new inbound VPN connections to the gateway services; in particular, the API is not reachable from a VPN address.

LSIO runs the `wg0.conf` we provide, without its own `PEERS` generator. The `Client mode selected` line in the image logs is expected [1].

```text
compose.yaml                  init (one-shot), wireguard, caddy, api
api/                          Dockerfile + gateway_api.py (stdlib, no dependencies)
api/static/                   web interface: index.html, wg-keys.js (X25519 in the browser)
.env                          SERVER_ENDPOINT, API_TOKEN and the rest; DO NOT commit
data/state/gateway.json       source of the configuration; CONTAINS SECRETS
data/wireguard/wg_confs/      active server WireGuard configuration
data/caddy-data/              TLS certificates, keys, ACME data
data/caddy-config/            Caddy internal configuration
caddy/Caddyfile               generated routes, do not edit by hand
scripts/                      host preparation, in-container firewall, client
examples/demo_app.py          safe test HTTP server
tests/                        offline API tests
```

Directories with secrets have mode 700, files 600. Do not add them to Git, do not paste the working directory into a chat. When a device sends its own `pubkey`, its private key is not stored on the VPS; only for devices created without `pubkey` does it live in the state.

**HTTPS terminates on the VPS.** WireGuard protects the leg to the laptop, but an administrator or a compromised VPS can see request contents [2, 3]. The access log is disabled, but service logs may contain domains, addresses or device names. Container logs are rotated.

## Troubleshooting

**`init` exits with an error.** See `docker compose logs init`: most often it is an empty or short `API_TOKEN`, a private address in `SERVER_ENDPOINT` or a changed `VPN_SUBNET` while devices exist.

**`401 Bad API token`.** The token in the request does not match `API_TOKEN` in `.env`. After changing `.env` run `docker compose up -d`.

**No handshake.** Check `GET /peers/{name}`, `Endpoint`, reachability of `51820/UDP` at the provider and whether UDP is allowed in the client network. Make sure one configuration is not used on two devices and that the client inserted exactly the private key whose public key it sent.

**Handshake exists but 502 or timeout.** Is the laptop awake, is the application running and listening on the VPN address? Run `POST /peers/{name}/check`. Check the local firewall. `curl 10.77.0.2:3000` directly on the VPS host is not a valid test: the VPN interface lives in the container network.

**`check` returns 404/401.** This can be the application's normal response on `/`, not a broken tunnel.

**Containers are healthy but HTTPS does not work.** Check A/AAAA/CAA, access to 80/443, `docker compose logs caddy`. Do not add `tls_insecure_skip_verify` as a workaround.

**Port already in use.** Check `ss -lntup` and `docker ps`. The API port can be changed through `API_PORT`.

**Files diverged from state.** `data/state/gateway.json` is the source of the configuration. `POST /apply` or `docker compose up -d` (init) restore the generated files.

## Backup and updates

Back up the working directory **encrypted**, including `data/state`, `.env` and `data/caddy-data`. For a consistent copy stop the project with `docker compose down`, make the copy, then `up`. Restoring an old state may re-activate previously revoked keys; check `GET /peers` after the start.

Planned image update, after a backup:

```bash
docker compose pull
docker compose build --pull
docker compose up -d --wait
docker compose ps
```

To avoid unexpected updates, pin the images by digest in `.env` (`WIREGUARD_IMAGE`, `CADDY_IMAGE`); an example command is in `.env.example`. Do not enable automatic updates of this gateway without a recovery procedure.

## Code checks

```bash
./scripts/test.sh
```

Performed and not performed checks are described in `docs/VALIDATION.md`. Official sources are listed in `docs/SOURCES.md`.
