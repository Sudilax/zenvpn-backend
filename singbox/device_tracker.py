#!/usr/bin/env python3
# =============================================================================
# ZenVPN — Device Tracker Daemon
# Reads sing-box logs, auto-registers devices, enforces plan limits
# Runs every 30 seconds as a background service
# =============================================================================

import json
import re
import time
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

# ── Config ────────────────────────────────────────────────────────────────────
USER_DB       = "/etc/sing-box/users.json"
SINGBOX_LOG   = "/var/log/sing-box.log"
TRACKER_LOG   = "/var/log/zenvpn-tracker.log"
CHECK_INTERVAL = 30  # seconds

# Plan device limits
PLAN_LIMITS = {
    "basic":    2,   # 50 Mbps,  2 devices, 349 LKR/month
    "pro":      5,   # 100 Mbps, 5 devices, 499 LKR/month
    "premium":  99   # admin/unlimited
}

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(TRACKER_LOG),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("zenvpn-tracker")

# ── Helpers ───────────────────────────────────────────────────────────────────
def load_db():
    with open(USER_DB, "r") as f:
        return json.load(f)

def save_db(data):
    with open(USER_DB, "w") as f:
        json.dump(data, f, indent=2)

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def reload_singbox():
    subprocess.run(["systemctl", "reload", "sing-box"], check=False)
    log.info("sing-box reloaded")

def rebuild_singbox_config(db):
    """Rebuild sing-box config with only active devices"""
    config_path = "/etc/sing-box/config.json"

    with open(config_path, "r") as f:
        config = json.load(f)

    # Collect all active device UUIDs
    vless_users  = []
    trojan_users = []
    vmess_users  = []
    hy2_users    = []

    for user in db["users"]:
        if user.get("status") != "active":
            continue
        for device in user.get("devices", []):
            if device.get("status", "active") != "active":
                continue
            vless_users.append({"uuid": device["vless_uuid"], "flow": ""})
            trojan_users.append({"password": device["trojan_uuid"]})
            vmess_users.append({"uuid": device["vmess_uuid"], "alterId": 0})
            hy2_users.append({"password": device["vless_uuid"]})

    # Update inbounds
    for inbound in config["inbounds"]:
        if inbound["tag"] == "vless-in":
            inbound["users"] = vless_users
        elif inbound["tag"] == "trojan-in":
            inbound["users"] = trojan_users
        elif inbound["tag"] == "vmess-in":
            inbound["users"] = vmess_users
        elif inbound["tag"] == "hysteria2-in":
            inbound["users"] = hy2_users

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

# ── Log Parser ────────────────────────────────────────────────────────────────
def parse_connections():
    """
    Parse sing-box log for connection entries.
    Returns dict: {uuid: set(ip_addresses)}
    sing-box log format example:
    2026-05-20T09:00:00Z INFO inbound/vless-in: [::ffff:1.2.3.4]:12345 accepted
    """
    connections = defaultdict(set)

    try:
        with open(SINGBOX_LOG, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        log.warning(f"Log file not found: {SINGBOX_LOG}")
        return connections

    # Match lines with UUID and IP
    # sing-box logs user UUID in accepted connection lines
    uuid_pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'  # timestamp
        r'.*?'
        r'\[?([0-9a-fA-F:.]+)\]?:\d+'               # IP address
        r'.*?'
        r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'  # UUID
    )

    for line in lines:
        match = uuid_pattern.search(line)
        if match:
            ip   = match.group(2)
            uuid = match.group(3)
            # Skip loopback
            if ip not in ("127.0.0.1", "::1"):
                connections[uuid].add(ip)

    return connections

# ── UUID Lookup ───────────────────────────────────────────────────────────────
def find_user_by_uuid(db, uuid):
    """Find user and device index by any UUID"""
    for user in db["users"]:
        for i, device in enumerate(user.get("devices", [])):
            if uuid in (
                device.get("vless_uuid"),
                device.get("trojan_uuid"),
                device.get("vmess_uuid")
            ):
                return user, i
    return None, None

# ── Core Logic ────────────────────────────────────────────────────────────────
def enforce_device_limits(db, connections):
    """
    For each UUID seen connecting:
    - Find which user owns it
    - Track unique IPs as devices
    - If new IP seen and under limit → register device
    - If new IP seen and over limit → block that UUID
    """
    changed = False

    # Group connections by user
    user_ips = defaultdict(set)  # username → set of IPs seen

    for uuid, ips in connections.items():
        user, device_idx = find_user_by_uuid(db, uuid)
        if not user:
            continue
        user_ips[user["name"]].update(ips)

    for user in db["users"]:
        if user.get("status") != "active":
            continue

        username = user["name"]
        plan     = user.get("plan", "starter")
        limit    = PLAN_LIMITS.get(plan, 1)
        devices  = user.get("devices", [])

        # Get IPs seen for this user
        seen_ips = user_ips.get(username, set())
        if not seen_ips:
            continue

        # Get already registered IPs
        registered_ips = set(
            d.get("last_ip") for d in devices
            if d.get("last_ip") and d.get("status", "active") == "active"
        )

        new_ips = seen_ips - registered_ips

        for ip in new_ips:
            active_devices = [
                d for d in devices
                if d.get("status", "active") == "active"
            ]

            if len(active_devices) < limit:
                # Auto register new device
                device_num = len(devices) + 1
                import uuid as uuidlib
                new_device = {
                    "device":      f"auto-device-{device_num}",
                    "vless_uuid":  str(uuidlib.uuid4()),
                    "trojan_uuid": str(uuidlib.uuid4()),
                    "vmess_uuid":  str(uuidlib.uuid4()),
                    "last_ip":     ip,
                    "last_seen":   now(),
                    "registered":  now(),
                    "status":      "active"
                }
                user["devices"].append(new_device)
                log.info(f"[{username}] New device registered — IP: {ip} (device {device_num}/{limit})")
                changed = True

            else:
                # Over limit — find which UUID this IP is using and block it
                log.warning(f"[{username}] Device limit reached ({limit}/{limit}) — blocking IP: {ip}")

                # Find UUID used by this IP and mark blocked
                for uuid_key, ips_set in connections.items():
                    if ip in ips_set:
                        user_check, dev_idx = find_user_by_uuid(db, uuid_key)
                        if user_check and user_check["name"] == username:
                            devices[dev_idx]["status"] = "blocked"
                            log.warning(f"[{username}] Blocked device index {dev_idx} — UUID: {uuid_key}")
                            changed = True

        # Update last seen for all active devices
        for device in devices:
            if device.get("last_ip") in seen_ips:
                device["last_seen"] = now()
                changed = True

    return db, changed

# ── Expiry Check ──────────────────────────────────────────────────────────────
def check_expiry(db):
    """Disable expired user accounts"""
    changed = False
    now_dt  = datetime.now(timezone.utc)

    for user in db["users"]:
        expiry = user.get("expiry", "")
        if not expiry or user.get("status") != "active":
            continue
        try:
            expiry_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if now_dt > expiry_dt:
                user["status"] = "expired"
                log.info(f"[{user['name']}] Account expired — disabling")
                changed = True
        except ValueError:
            pass

    return db, changed

# ── Main Loop ─────────────────────────────────────────────────────────────────
def main():
    log.info("ZenVPN Device Tracker started")
    log.info(f"Checking every {CHECK_INTERVAL} seconds")

    while True:
        try:
            db          = load_db()
            connections = parse_connections()

            db, devices_changed = enforce_device_limits(db, connections)
            db, expiry_changed  = check_expiry(db)

            if devices_changed or expiry_changed:
                save_db(db)
                rebuild_singbox_config(db)
                reload_singbox()
                log.info("Database and config updated")
            else:
                log.debug("No changes detected")

        except Exception as e:
            log.error(f"Tracker error: {e}", exc_info=True)

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
