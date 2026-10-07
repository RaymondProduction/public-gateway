#!/usr/bin/env bash
# Linux client: generate a local WireGuard key, request the config from the gateway API,
# install it as /etc/wireguard/pgw0.conf and start wg-quick@pgw0. Run on the CLIENT device.
#
#   sudo API_TOKEN=... ./connect-client.sh http://203.0.113.10:8080 laptop
#
# The private key is created here and never leaves this device; only the public key is sent.
set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: sudo API_TOKEN=<token> $0 <api-url> <device-name>" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "Запусти через sudo на КЛІЄНТСЬКОМУ Linux-пристрої." >&2; exit 1; }
[[ -n "${API_TOKEN:-}" ]] || { echo "Передай токен через змінну середовища API_TOKEN." >&2; exit 1; }
for tool in wg wg-quick curl python3; do
  command -v "$tool" >/dev/null || { echo "Потрібен $tool (apt install -y wireguard-tools curl python3)." >&2; exit 1; }
done

API_URL="${1%/}"
NAME="$2"
WG_NAME="pgw0"
WG_DIR="/etc/wireguard"
KEY_FILE="$WG_DIR/$WG_NAME.key"
CONF_FILE="$WG_DIR/$WG_NAME.conf"

install -d -m 0700 "$WG_DIR"
if [[ ! -s "$KEY_FILE" ]]; then
  echo "[1/4] Генерую приватний ключ у $KEY_FILE"
  (umask 077 && wg genkey > "$KEY_FILE.tmp") && mv "$KEY_FILE.tmp" "$KEY_FILE"
else
  echo "[1/4] Використовую наявний ключ $KEY_FILE"
fi
chmod 600 "$KEY_FILE"
PUB_KEY="$(wg pubkey < "$KEY_FILE")"

TMP_JSON="$(mktemp)"
TMP_CONF="$(mktemp)"
trap 'rm -f "$TMP_JSON" "$TMP_CONF"' EXIT

echo "[2/4] Запит конфігурації для пристрою '$NAME' з $API_URL"
# Token goes through a header file, not argv, so it does not show in `ps`.
curl -fsS -X POST "$API_URL/provision" \
  -H @<(printf 'X-API-Token: %s\n' "$API_TOKEN") \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$NAME\",\"pubkey\":\"$PUB_KEY\"}" \
  -o "$TMP_JSON"

python3 - "$TMP_JSON" "$TMP_CONF" "$KEY_FILE" <<'PY'
import json, re, sys
json_path, conf_path, key_path = sys.argv[1:4]
data = json.load(open(json_path))
if not data.get("ok"):
    raise SystemExit(f"Сервер відповів помилкою: {data.get('error')}")
config = data["config"]
if re.search(r"(?im)^\s*PrivateKey\s*=", config):
    raise SystemExit("Сервер повернув PrivateKey, хоча ми надсилали pubkey. Зупиняюся.")
private_key = open(key_path).read().strip()
config, count = re.subn(r"(?im)^(\[Interface\][ \t]*)$", lambda m: f"{m.group(1)}\nPrivateKey = {private_key}",
                        config, count=1)
if count != 1:
    raise SystemExit("У конфігурації немає секції [Interface].")
with open(conf_path, "w") as out:
    out.write(config if config.endswith("\n") else config + "\n")
print(f"      VPN-адреса пристрою: {data['address']}, шлюз: {data['gateway_ip']}, endpoint: {data['endpoint']}:{data['port']}")
PY

echo "[3/4] Встановлюю $CONF_FILE"
systemctl stop "wg-quick@$WG_NAME" 2>/dev/null || true
install -m 0600 "$TMP_CONF" "$CONF_FILE"

echo "[4/4] Запускаю wg-quick@$WG_NAME"
systemctl enable --now "wg-quick@$WG_NAME"
systemctl restart "wg-quick@$WG_NAME"
wg show "$WG_NAME"
echo "Готово. Перевір: ping -c 3 $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["gateway_ip"])' "$TMP_JSON")"
