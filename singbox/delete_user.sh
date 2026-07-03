#!/bin/bash
# =============================================================================
# ZenVPN — Delete User Script
# Usage: bash delete_user.sh <username>
# Example: bash delete_user.sh john
# =============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${GREEN}[✔]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✘]${NC} $1"; exit 1; }

# ── Config ────────────────────────────────────────────────────────────────────
CONFIG_DIR="/etc/sing-box"
USER_DB="$CONFIG_DIR/users.json"

# ── Args ──────────────────────────────────────────────────────────────────────
USERNAME="${1:-}"
[[ -z "$USERNAME" ]] && error "Usage: bash delete_user.sh <username>"
[[ $EUID -ne 0 ]] && error "Run as root"

# ── Check user exists ─────────────────────────────────────────────────────────
EXISTS=$(jq -r --arg name "$USERNAME" '.users[] | select(.name == $name) | .name' "$USER_DB")
[[ -z "$EXISTS" ]] && error "User '$USERNAME' not found"

# ── Confirm ───────────────────────────────────────────────────────────────────
echo -e "${YELLOW}Are you sure you want to delete user '$USERNAME'? (yes/no)${NC}"
read -r CONFIRM
[[ "$CONFIRM" != "yes" ]] && echo "Cancelled." && exit 0

# ── Delete user from DB ───────────────────────────────────────────────────────
UPDATED=$(jq --arg name "$USERNAME" \
  'del(.users[] | select(.name == $name))' "$USER_DB")
echo "$UPDATED" > "$USER_DB"
log "User '$USERNAME' removed from database"

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

log "User '$USERNAME' deleted and disconnected successfully"
