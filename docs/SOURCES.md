# Офіційні джерела

Перевірено під час підготовки проєкту 6–7 жовтня 2026 року. Код цього проєкту — власна реалізація MVP, а не продукт чи офіційно підтримана інтеграція цих постачальників.

[1] LinuxServer WireGuard: образ, вимоги ядра, власні конфігурації у `/config/wg_confs`, `NET_ADMIN`, завантаження модулів на хості:
`https://docs.linuxserver.io/images/docker-wireguard/`

[2] Caddy reverse_proxy: HTTP-проксіювання, WebSocket, transport, заголовки:
`https://caddyserver.com/docs/caddyfile/directives/reverse_proxy`

[3] Caddy Automatic HTTPS: домени, автоматичні сертифікати, вимоги доступності:
`https://caddyserver.com/docs/automatic-https`

[4] Docker Compose services: network_mode service, depends_on, healthcheck, volumes, ports:
`https://docs.docker.com/reference/compose-file/services/`

[5] Docker packet filtering / UFW:
`https://docs.docker.com/engine/network/packet-filtering-firewalls/`

[6] WireGuard quick start: ключі, AllowedIPs, NAT та PersistentKeepalive:
`https://www.wireguard.com/quickstart/`

[7] WireGuard installation / клієнти:
`https://www.wireguard.com/install/`

[8] Caddy Docker / persistent state / configuration reload:
`https://caddyserver.com/docs/running`

[9] Caddy global options: локальний admin endpoint, протоколи:
`https://caddyserver.com/docs/caddyfile/options`

[10] Caddy Admin API: `POST /load` і `POST /adapt` з `Content-Type: text/caddyfile`, перевірка Origin/Host для loopback:
`https://caddyserver.com/docs/api`
