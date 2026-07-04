#!/usr/bin/env python3
# =============================================================================
# ZenVPN — Traffic Accumulator Daemon
# Polls sing-box Clash API (/connections) every POLL_INTERVAL seconds,
# maps sourceIP → device via users.json, and persists cumulative
# per-device byte counts to STATS_FILE.
#
# Stats file format:
# {
#   "updated": "2026-07-04T...",
#   "users": {
#     "laravel-1": {
#       "device-1": {"upload_bytes": 123, "download_bytes": 456}
#     }
#   }
# }
# =============================================================================

import json
import time
import logging
import requests
from datetime import datetime, timezone
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
CLASH_API     = "http://127.0.0.1:9090"
USER_DB       = "/etc/sing-box/users.json"
STATS_FILE    = "/var/lib/zenvpn/traffic_stats.json"
TRACKER_LOG   = "/var/log/zenvpn-traffic.log"
POLL_INTERVAL = 15   # seconds

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(TRACKER_LOG),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("zenvpn-traffic")

# ── Helpers ───────────────────────────────────────────────────────────────────
def load_user_db() -> dict:
    with open(USER_DB) as f:
        return json.load(f)

def load_stats() -> dict:
    p = Path(STATS_FILE)
    if p.exists():
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            pass
    return {"updated": "", "users": {}}

def save_stats(stats: dict):
    Path(STATS_FILE).parent.mkdir(parents=True, exist_ok=True)
    stats["updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f, indent=2)

def build_ip_to_device_map(db: dict) -> dict:
    """
    Returns {ip: (username, device_name)} for all active devices
    that have a recorded last_ip.
    """
    mapping = {}
    for user in db.get("users", []):
        if user.get("status", "active") != "active":
            continue
        uname = user["name"]
        for device in user.get("devices", []):
            if device.get("status", "active") != "active":
                continue
            ip = device.get("last_ip", "")
            if ip:
                mapping[ip] = (uname, device["device"])
    return mapping

def fetch_connections() -> dict:
    """
    Returns the full /connections response or empty dict on error.
    """
    try:
        r = requests.get(f"{CLASH_API}/connections", timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning(f"Failed to fetch connections: {e}")
        return {}

# ── Core accumulation logic ───────────────────────────────────────────────────
def accumulate(stats: dict, db: dict, prev_snapshot: dict, current_connections: list) -> dict:
    """
    For each active connection:
    - Look up sourceIP in ip_to_device_map
    - Compute delta upload/download since last poll
    - Add delta to stats
    """
    ip_map = build_ip_to_device_map(db)
    current_snapshot = {}

    for conn in current_connections:
        conn_id  = conn.get("id", "")
        meta     = conn.get("metadata", {})
        src_ip   = meta.get("sourceIP", "")
        upload   = conn.get("upload", 0)
        download = conn.get("download", 0)

        current_snapshot[conn_id] = {
            "upload":   upload,
            "download": download,
            "src_ip":   src_ip
        }

        if src_ip not in ip_map:
            continue  # Unknown IP — skip

        username, device_name = ip_map[src_ip]

        # Delta since last poll (connection may be ongoing)
        prev = prev_snapshot.get(conn_id, {})
        delta_up   = max(0, upload   - prev.get("upload",   0))
        delta_down = max(0, download - prev.get("download", 0))

        if delta_up == 0 and delta_down == 0:
            continue  # No new data

        # Accumulate into stats
        user_stats   = stats["users"].setdefault(username, {})
        device_stats = user_stats.setdefault(device_name, {"upload_bytes": 0, "download_bytes": 0})
        device_stats["upload_bytes"]   += delta_up
        device_stats["download_bytes"] += delta_down

        log.debug(f"[{username}/{device_name}] +{delta_up}up +{delta_down}down bytes (IP: {src_ip})")

    return current_snapshot

# ── Main Loop ─────────────────────────────────────────────────────────────────
def main():
    log.info("ZenVPN Traffic Accumulator started")
    log.info(f"Polling Clash API every {POLL_INTERVAL}s -> {STATS_FILE}")

    # Ensure stats directory exists
    Path(STATS_FILE).parent.mkdir(parents=True, exist_ok=True)

    stats         = load_stats()
    prev_snapshot = {}  # conn_id -> {upload, download, src_ip}

    while True:
        try:
            db   = load_user_db()
            data = fetch_connections()

            if data:
                connections   = data.get("connections", [])
                prev_snapshot = accumulate(stats, db, prev_snapshot, connections)
                save_stats(stats)
                log.debug(f"Snapshot: {len(connections)} active connections")

        except Exception as e:
            log.error(f"Accumulator error: {e}", exc_info=True)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
