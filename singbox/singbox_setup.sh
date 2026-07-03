#!/bin/bash
# =============================================================================
# sing-box VPN One-Shot Setup Script
# OS: Ubuntu 24.04 LTS aarch64
# Protocols: VLESS, Trojan, VMess, Shadowsocks, Hysteria2
# Traffic Camouflage: WebSocket + TLS (SNI: m.zoom.us)
# =============================================================================

set -e

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()     { echo -e "${GREEN}[✔]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✘]${NC} $1"; exit 1; }
section() { echo -e "\n${CYAN}${BOLD}── $1 ──${NC}"; }

# ── Config ───────────────────────────────────────────────────────────────────
SERVER_IP="129.150.32.96"
SNI="m.zoom.us"
WS_PATH="/zen"
CERT_DIR="/etc/sing-box/certs"
CONFIG_DIR="/etc/sing-box"
USER_DB="/etc/sing-box/users.json"
CREDENTIALS_FILE="/etc/sing-box/credentials.txt"
SS_PASSWORD="$(openssl rand -base64 16)"
SINGBOX_VERSION="1.9.0"

# Ports
PORT_VLESS=443
PORT_TROJAN=8443
PORT_VMESS=80
PORT_SS=8388
PORT_HYSTERIA=5443

# ── Root check ───────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash $0"

# =============================================================================
section "Step 1: System Update & Dependencies"
# =============================================================================
apt-get update -qq
apt-get install -y -qq \
    curl wget openssl uuid-runtime jq \
    net-tools ufw fail2ban unzip tar
log "Dependencies installed"

# =============================================================================
section "Step 2: Download & Install sing-box (aarch64)"
# =============================================================================
ARCH="linux-arm64"
DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-${ARCH}.tar.gz"

cd /tmp
wget -q --show-progress "$DOWNLOAD_URL" -O singbox.tar.gz || error "Failed to download sing-box"
tar -xzf singbox.tar.gz
cp "sing-box-${SINGBOX_VERSION}-${ARCH}/sing-box" /usr/local/bin/sing-box
chmod +x /usr/local/bin/sing-box
rm -rf singbox.tar.gz "sing-box-${SINGBOX_VERSION}-${ARCH}"

log "sing-box $(sing-box version | head -1) installed"

# =============================================================================
section "Step 3: Create Directories"
# =============================================================================
mkdir -p "$CERT_DIR" "$CONFIG_DIR"
touch "$USER_DB" "$CREDENTIALS_FILE"
log "Directories created"

# =============================================================================
section "Step 4: Generate Self-Signed SSL Certificate"
# =============================================================================
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -subj "/CN=m.zoom.us/O=Zoom/C=US" \
    -addext "subjectAltName=DNS:m.zoom.us,DNS:zoom.us,IP:$SERVER_IP" \
    2>/dev/null
chmod 600 "$CERT_DIR/server.key"
log "Self-signed cert generated (valid 10 years)"

# =============================================================================
section "Step 5: Generate Initial User Credentials"
# =============================================================================
VLESS_UUID=$(uuidgen)
TROJAN_UUID=$(uuidgen)
VMESS_UUID=$(uuidgen)

# Initialize users.json
cat > "$USER_DB" <<EOF
{
  "users": [
    {
      "name": "admin",
      "plan": "premium",
      "bandwidth_mbps": 0,
      "devices": [
        {
          "device": "device-1",
          "vless_uuid": "$VLESS_UUID",
          "trojan_uuid": "$TROJAN_UUID",
          "vmess_uuid": "$VMESS_UUID",
          "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        }
      ]
    }
  ]
}
EOF
log "User database initialized"

# =============================================================================
section "Step 6: Write sing-box Config (All Protocols)"
# =============================================================================
cat > "$CONFIG_DIR/config.json" <<EOF
{
  "log": {
    "level": "info",
    "output": "/var/log/sing-box.log",
    "timestamp": true
  },

  "inbounds": [

    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $PORT_VLESS,
      "users": $(jq '[.users[].devices[] | {"uuid": .vless_uuid, "flow": ""}]' "$USER_DB"),
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/server.crt",
        "key_path": "$CERT_DIR/server.key",
        "server_name": "$SNI"
      },
      "transport": {
        "type": "ws",
        "path": "$WS_PATH",
        "headers": {
          "Host": "$SNI"
        }
      }
    },

    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "::",
      "listen_port": $PORT_TROJAN,
      "users": $(jq '[.users[].devices[] | {"password": .trojan_uuid}]' "$USER_DB"),
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/server.crt",
        "key_path": "$CERT_DIR/server.key",
        "server_name": "$SNI"
      },
      "transport": {
        "type": "ws",
        "path": "/trojan",
        "headers": {
          "Host": "$SNI"
        }
      }
    },

    {
      "type": "vmess",
      "tag": "vmess-in",
      "listen": "::",
      "listen_port": $PORT_VMESS,
      "users": $(jq '[.users[].devices[] | {"uuid": .vmess_uuid, "alterId": 0}]' "$USER_DB"),
      "transport": {
        "type": "ws",
        "path": "/vmess",
        "headers": {
          "Host": "$SNI"
        }
      }
    },

    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "::",
      "listen_port": $PORT_SS,
      "method": "aes-256-gcm",
      "password": "$SS_PASSWORD"
    },

    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "::",
      "listen_port": $PORT_HYSTERIA,
      "users": $(jq '[.users[].devices[] | {"password": .vless_uuid}]' "$USER_DB"),
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/server.crt",
        "key_path": "$CERT_DIR/server.key",
        "server_name": "$SNI"
      }
    }

  ],

  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],

  "route": {
    "rules": [
      {
        "geoip": ["private"],
        "outbound": "block"
      }
    ],
    "final": "direct"
  }
}
EOF
log "sing-box config written"

# =============================================================================
section "Step 7: Create systemd Service"
# =============================================================================
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box VPN Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c $CONFIG_DIR/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemd-analyze verify /etc/systemd/system/sing-box.service 2>/dev/null || true
systemctl daemon-reload
systemctl enable sing-box
log "systemd service created and enabled"

# =============================================================================
section "Step 8: Firewall Rules (UFW)"
# =============================================================================
ufw --force reset > /dev/null
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null
ufw allow 22/tcp    comment "SSH"
ufw allow $PORT_VLESS/tcp   comment "VLESS"
ufw allow $PORT_TROJAN/tcp  comment "Trojan"
ufw allow $PORT_VMESS/tcp   comment "VMess"
ufw allow $PORT_SS/tcp      comment "Shadowsocks"
ufw allow $PORT_HYSTERIA/udp comment "Hysteria2"
ufw --force enable > /dev/null
log "Firewall configured"

# =============================================================================
section "Step 9: Configure fail2ban"
# =============================================================================
cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = ssh
maxretry = 5
bantime = 3600
findtime = 600
EOF
systemctl enable fail2ban --quiet
systemctl restart fail2ban
log "fail2ban configured"

# =============================================================================
section "Step 10: Start sing-box"
# =============================================================================
sing-box check -c "$CONFIG_DIR/config.json" || error "Config validation failed"
systemctl start sing-box
sleep 2
systemctl is-active --quiet sing-box && log "sing-box is running" || error "sing-box failed to start"

# =============================================================================
section "Step 11: Generate Share URIs"
# =============================================================================

# VLESS URI
VLESS_URI="vless://${VLESS_UUID}@${SERVER_IP}:${PORT_VLESS}?encryption=none&security=tls&sni=${SNI}&type=ws&host=${SNI}&path=$(python3 -c 'import urllib.parse; print(urllib.parse.quote("/zen"))')&allowInsecure=1#VPN-VLESS-admin"

# Trojan URI
TROJAN_URI="trojan://${TROJAN_UUID}@${SERVER_IP}:${PORT_TROJAN}?security=tls&sni=${SNI}&type=ws&host=${SNI}&path=%2Ftrojan&allowInsecure=1#VPN-Trojan-admin"

# VMess URI (base64 encoded JSON)
VMESS_JSON="{\"v\":\"2\",\"ps\":\"VPN-VMess-admin\",\"add\":\"${SERVER_IP}\",\"port\":\"${PORT_VMESS}\",\"id\":\"${VMESS_UUID}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${SNI}\",\"path\":\"/vmess\",\"tls\":\"none\"}"
VMESS_URI="vmess://$(echo -n "$VMESS_JSON" | base64 -w 0)"

# Shadowsocks URI
SS_USERINFO=$(echo -n "aes-256-gcm:${SS_PASSWORD}" | base64 -w 0)
SS_URI="ss://${SS_USERINFO}@${SERVER_IP}:${PORT_SS}#VPN-SS-admin"

# Hysteria2 URI
HY2_URI="hysteria2://${VLESS_UUID}@${SERVER_IP}:${PORT_HYSTERIA}?insecure=1&sni=${SNI}#VPN-Hysteria2-admin"

# ── Write credentials file ───────────────────────────────────────────────────
cat > "$CREDENTIALS_FILE" <<EOF
=============================================================
  sing-box VPN Credentials — Generated $(date)
=============================================================

SERVER IP  : $SERVER_IP
SNI        : $SNI
CERT       : Self-Signed (insecure=true on client)

-------------------------------------------------------------
USER: admin | PLAN: premium
-------------------------------------------------------------

[VLESS + WebSocket + TLS — Port $PORT_VLESS]
UUID       : $VLESS_UUID
URI        : $VLESS_URI

[Trojan + WebSocket + TLS — Port $PORT_TROJAN]
Password   : $TROJAN_UUID
URI        : $TROJAN_URI

[VMess + WebSocket — Port $PORT_VMESS]
UUID       : $VMESS_UUID
URI        : $VMESS_URI

[Shadowsocks AES-256-GCM — Port $PORT_SS]
Password   : $SS_PASSWORD
URI        : $SS_URI

[Hysteria2 — Port $PORT_HYSTERIA]
Password   : $VLESS_UUID
URI        : $HY2_URI

=============================================================
EOF

# ── Print to terminal ────────────────────────────────────────────────────────
cat "$CREDENTIALS_FILE"

log "Credentials saved to $CREDENTIALS_FILE"

# =============================================================================
section "Setup Complete!"
# =============================================================================
echo -e "
${GREEN}${BOLD}
  ✔ sing-box is running
  ✔ All 5 protocols active
  ✔ Firewall configured
  ✔ fail2ban active
  ✔ Credentials saved to $CREDENTIALS_FILE

  Next steps:
  → Add more users:  bash /etc/sing-box/add_user.sh
  → Check status:    systemctl status sing-box
  → View logs:       journalctl -u sing-box -f
${NC}"
