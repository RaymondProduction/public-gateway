#!/usr/bin/env bash
# Ubuntu/Linux VPS preparation. Does NOT change SSH or host firewall rules.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Запусти під root." >&2; exit 1; }
command -v docker >/dev/null || { echo "Спочатку встанови Docker Engine та Compose plugin." >&2; exit 1; }
command -v modprobe >/dev/null || { echo "Встанови: apt install -y kmod" >&2; exit 1; }
docker info >/dev/null
docker compose version
for module in wireguard ip_tables iptable_filter nf_conntrack; do
  modprobe "$module" || { echo "Не вдалося завантажити $module. Перевір ядро/підтримку VPS." >&2; exit 1; }
done
install -d -m 0755 /etc/modules-load.d
printf '%s\n' wireguard ip_tables iptable_filter nf_conntrack > /etc/modules-load.d/public-gateway.conf
printf '%s\n' 'Модулі завантажено. SSH та firewall хоста не змінювалися.'
printf '%s\n' 'Зовні потрібні 51820/UDP, 80/TCP, 443/TCP і порт API (типово 8080/TCP). Збережи доступ до SSH.'
