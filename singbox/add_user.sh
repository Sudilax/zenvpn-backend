#!/bin/bash
# =============================================================================
# ZenVPN — Add User Script
# Usage: bash add_user.sh <username> <plan>
# Plans: basic (50 Mbps, 2 devices) | pro (100 Mbps, 5 devices)
# Example: bash add_user.sh john basic
# =============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${GREEN}[✔]${NC} $1"; }
error() { echo -e "${RED}[✘]${NC} $1"; exit 1; }

# ── Config ────────────────────────────────────────────────────────────────────
SERVER_IP="129.150.32.96"
SNI="m.zoom.us"
CONFIG_DIR="/etc/sing-box"
USER_DB="$CONFIG_DIR/users.json"
CREDENTIALS_FILE="$CONFIG_DIR/credentials.txt"

PORT_VLESS=443
PORT_TROJAN=8443
PORT_VMESS=80
PORT_SS=8388
PORT_HYSTERIA=5443

# ── Plans ─────────────────────────────────────────────────────────────────────
# basic   → 50 Mbps,  2 devices, 200 LKR/month
# pro     → 100 Mbps, 5 devices, 500 LKR/month
# premium → unlimited, 99 devices (admin only)

# ── Args ──────────────────────────────────────────────────────────────────────
USERNAME="${1:-}"
PLAN="${2:-basic}"

[[ -z "$USERNAME" ]] && error "Usage: bash add_user.sh <username> <plan>\nPlans: basic | pro"
[[ $EUID -ne 0 ]] && error "Run as root"

# ── Plan settings ─────────────────────────────────────────────────────────────
case "$PLAN" in
  basic)   BW=50;  DEVICE_LIMIT=2;  PRICE="200 LKR/month" ;;
  pro)     BW=100; DEVICE_LIMIT=5;  PRICE="500 LKR/month" ;;
  premium) BW=0;   DEVICE_LIMIT=99; PRICE="Admin"         ;;
  *) error "Invalid plan. Use: basic | pro" ;;
esac

# ── Check duplicate ───────────────────────────────────────────────────────────
EXISTS=$(jq -r --arg name "$USERNAME" '.users[] | select(.name == $name) | .name' "$USER_DB")
[[ -n "$EXISTS" ]] && error "User '$USERNAME' already exists."

# ── Generate UUIDs ────────────────────────────────────────────────────────────
VLESS_UUID=$(uuidgen)
TROJAN_UUID=$(uuidgen)
VMESS_UUID=$(uuidgen)

# ── Expiry (30 days from now) ─────────────────────────────────────────────────
EXPIRY=$(date -u -d "+30 days" +%Y-%m-%dT%H:%M:%SZ)

# ── Add user to DB ────────────────────────────────────────────────────────────
UPDATED=$(jq \
  --arg name "$USERNAME" \
  --arg plan "$PLAN" \
  --argjson bw "$BW" \
  --argjson dl "$DEVICE_LIMIT" \
  --arg price "$PRICE" \
  --arg expiry "$EXPIRY" \
  --arg vu "$VLESS_UUID" \
  --arg tu "$TROJAN_UUID" \
  --arg mu "$VMESS_UUID" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '.users += [{
    "name": $name,
    "plan": $plan,
    "bandwidth_mbps": $bw,
    "device_limit": $dl,
    "price": $price,
    "status": "active",
    "created": $ts,
    "expiry": $expiry,
    "devices": [{
      "device": "device-1",
      "vless_uuid": $vu,
      "trojan_uuid": $tu,
      "vmess_uuid": $mu,
      "last_ip": "",
      "last_seen": "",
      "registered": $ts,
      "status": "active"
    }]
  }]' "$USER_DB")

echo "$UPDATED" > "$USER_DB"
log "User '$USERNAME' added — Plan: $PLAN | Speed: ${BW} Mbps | Devices: $DEVICE_LIMIT | Expiry: $EXPIRY"

# ── Rebuild sing-box config ───────────────────────────────────────────────────
VLESS_USERS=$(jq '[.users[] | select(.status == "active") | .devices[] | select(.status == "active") | {"uuid": .vless_uuid, "flow": ""}]' "$USER_DB")
TROJAN_USERS=$(jq '[.users[] | select(.status == "active") | .devices[] | select(.status == "active") | {"password": .trojan_uuid}]' "$USER_DB")
VMESS_USERS=$(jq '[.users[] | select(.status == "active") | .devices[] | select(.status == "active") | {"uuid": .vmess_uuid, "alterId": 0}]' "$USER_DB")
HY2_USERS=$(jq '[.users[] | select(.status == "active") | .devices[] | select(.status == "active") | {"password": .vless_uuid}]' "$USER_DB")

jq --argjson vu "$VLESS_USERS" \
   --argjson tu "$TROJAN_USERS" \
   --argjson mu "$VMESS_USERS" \
   --argjson hu "$HY2_USERS" \
   '(.inbounds[] | select(.tag == "vless-in") | .users) = $vu |
    (.inbounds[] | select(.tag == "trojan-in") | .users) = $tu |
    (.inbounds[] | select(.tag == "vmess-in") | .users) = $mu |
    (.inbounds[] | select(.tag == "hysteria2-in") | .users) = $hu' \
   /etc/sing-box/config.json > /tmp/config_new.json

mv /tmp/config_new.json /etc/sing-box/config.json
log "sing-box config updated"

# ── Reload sing-box ───────────────────────────────────────────────────────────
sing-box check -c /etc/sing-box/config.json || error "Config validation failed"
systemctl reload-or-restart sing-box
sleep 1
systemctl is-active --quiet sing-box && log "sing-box reloaded" || error "sing-box failed to reload"

# ── Generate URIs ─────────────────────────────────────────────────────────────
VLESS_URI="vless://${VLESS_UUID}@${SERVER_IP}:${PORT_VLESS}?encryption=none&security=tls&sni=${SNI}&type=ws&host=${SNI}&path=%2Fzen&allowInsecure=1#ZenVPN-${USERNAME}"
TROJAN_URI="trojan://${TROJAN_UUID}@${SERVER_IP}:${PORT_TROJAN}?security=tls&sni=${SNI}&type=ws&host=${SNI}&path=%2Ftrojan&allowInsecure=1#ZenVPN-Trojan-${USERNAME}"
VMESS_JSON="{\"v\":\"2\",\"ps\":\"ZenVPN-VMess-${USERNAME}\",\"add\":\"${SERVER_IP}\",\"port\":\"${PORT_VMESS}\",\"id\":\"${VMESS_UUID}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${SNI}\",\"path\":\"/vmess\",\"tls\":\"none\"}"
VMESS_URI="vmess://$(echo -n "$VMESS_JSON" | base64 -w 0)"
SS_PASSWORD=$(python3 -c "import json; c=json.load(open('/etc/sing-box/config.json')); [print(i['password']) for i in c['inbounds'] if i['tag']=='ss-in']" 2>/dev/null || echo "see-config")
SS_USERINFO=$(echo -n "aes-256-gcm:${SS_PASSWORD}" | base64 -w 0)
SS_URI="ss://${SS_USERINFO}@${SERVER_IP}:${PORT_SS}#ZenVPN-SS-${USERNAME}"
HY2_URI="hysteria2://${VLESS_UUID}@${SERVER_IP}:${PORT_HYSTERIA}?insecure=1&sni=${SNI}#ZenVPN-Hysteria2-${USERNAME}"

# ── Output ────────────────────────────────────────────────────────────────────
OUTPUT="
=============================================================
  ZenVPN — New User Credentials
  Generated: $(date)
=============================================================
  USER     : $USERNAME
  PLAN     : $PLAN
  SPEED    : ${BW} Mbps
  DEVICES  : $DEVICE_LIMIT max
  PRICE    : $PRICE
  EXPIRY   : $EXPIRY
-------------------------------------------------------------

[VLESS + WS + TLS — Port $PORT_VLESS] ← Recommended
URI : $VLESS_URI

[Trojan + WS + TLS — Port $PORT_TROJAN]
URI : $TROJAN_URI

[VMess + WS — Port $PORT_VMESS]
URI : $VMESS_URI

[Shadowsocks AES-256-GCM — Port $PORT_SS]
URI : $SS_URI

[Hysteria2 — Port $PORT_HYSTERIA] ← Best for gaming
URI : $HY2_URI

=============================================================
  Client Apps:
  Windows/Android : Hiddify  → https://hiddify.com
  iOS             : Streisand (App Store)
=============================================================
"

echo -e "$OUTPUT"
echo "$OUTPUT" >> "$CREDENTIALS_FILE"
log "Credentials saved to $CREDENTIALS_FILE"
