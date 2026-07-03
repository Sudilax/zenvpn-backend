#!/usr/bin/env python3
# =============================================================================
# ZenVPN — FastAPI Backend
# Handles user management, auth, stats, expiry
# Run: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
# =============================================================================

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from apscheduler.schedulers.background import BackgroundScheduler
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from typing import Optional, List
import subprocess
import json
import uuid
import os

# =============================================================================
# Config
# =============================================================================
SECRET_KEY      = "zenvpn-secret-change-this-in-production"
ALGORITHM       = "HS256"
TOKEN_EXPIRE    = 60 * 24  # 24 hours
DATABASE_URL    = "sqlite:////etc/zenvpn/api/zenvpn.db"
USER_DB         = "/etc/sing-box/users.json"
SINGBOX_CONFIG  = "/etc/sing-box/config.json"
SERVER_IP       = "129.150.32.96"
SNI             = "m.zoom.us"

# Plans
PLANS = {
    "basic": {
        "name":         "Basic",
        "bandwidth_mbps": 50,
        "device_limit": 2,
        "price_lkr":    200,
        "duration_days": 30
    },
    "pro": {
        "name":         "Pro",
        "bandwidth_mbps": 100,
        "device_limit": 5,
        "price_lkr":    500,
        "duration_days": 30
    },
    "premium": {
        "name":         "Premium",
        "bandwidth_mbps": 0,
        "device_limit": 99,
        "price_lkr":    0,
        "duration_days": 36500
    }
}

# =============================================================================
# Database Setup
# =============================================================================
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AdminUser(Base):
    __tablename__ = "admins"
    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at    = Column(DateTime, default=datetime.utcnow)

class VPNUser(Base):
    __tablename__ = "vpn_users"
    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String, unique=True, index=True)
    plan          = Column(String, default="basic")
    status        = Column(String, default="active")  # active, suspended, expired
    bandwidth_mbps = Column(Integer, default=50)
    device_limit  = Column(Integer, default=2)
    price_lkr     = Column(Integer, default=200)
    created_at    = Column(DateTime, default=datetime.utcnow)
    expiry_date   = Column(DateTime)
    notes         = Column(String, default="")

Base.metadata.create_all(bind=engine)

# =============================================================================
# Auth
# =============================================================================
pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str):
    return pwd_context.verify(plain, hashed)

def create_token(data: dict):
    to_encode = data.copy()
    expire    = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    admin = db.query(AdminUser).filter(AdminUser.username == username).first()
    if admin is None:
        raise credentials_exception
    return admin

# =============================================================================
# sing-box Helpers
# =============================================================================
def load_singbox_users():
    with open(USER_DB) as f:
        return json.load(f)

def save_singbox_users(data):
    with open(USER_DB, "w") as f:
        json.dump(data, f, indent=2)

def reload_singbox():
    subprocess.Popen(["systemctl", "reload-or-restart", "sing-box"])

def rebuild_singbox_config():
    db_data = load_singbox_users()
    with open(SINGBOX_CONFIG) as f:
        config = json.load(f)

    vless_users  = []
    trojan_users = []
    vmess_users  = []
    hy2_users    = []

    for user in db_data["users"]:
        if user.get("status") != "active":
            continue
        for device in user.get("devices", []):
            if device.get("status", "active") != "active":
                continue
            vless_users.append({"uuid": device["vless_uuid"], "flow": ""})
            trojan_users.append({"password": device["trojan_uuid"]})
            vmess_users.append({"uuid": device["vmess_uuid"], "alterId": 0})
            hy2_users.append({"password": device["vless_uuid"]})

    for inbound in config["inbounds"]:
        if inbound["tag"] == "vless-in":
            inbound["users"] = vless_users
        elif inbound["tag"] == "trojan-in":
            inbound["users"] = trojan_users
        elif inbound["tag"] == "vmess-in":
            inbound["users"] = vmess_users
        elif inbound["tag"] == "hysteria2-in":
            inbound["users"] = hy2_users

    with open(SINGBOX_CONFIG, "w") as f:
        json.dump(config, f, indent=2)

def generate_uris(username: str, vless_uuid: str, trojan_uuid: str, vmess_uuid: str, sni: Optional[str] = None):
    use_sni = sni if sni is not None else SNI
    vmess_json = json.dumps({
        "v": "2", "ps": f"ZenVPN-{username}",
        "add": SERVER_IP, "port": "80",
        "id": vmess_uuid, "aid": "0",
        "net": "ws", "type": "none",
        "host": use_sni, "path": "/vmess", "tls": "none"
    })
    import base64
    vmess_b64 = base64.b64encode(vmess_json.encode()).decode()

    # Get SS password from config
    with open(SINGBOX_CONFIG) as f:
        config = json.load(f)
    ss_password = next((i["password"] for i in config["inbounds"] if i["tag"] == "ss-in"), "")
    ss_userinfo = base64.b64encode(f"aes-256-gcm:{ss_password}".encode()).decode()

    return {
        "vless":     f"vless://{vless_uuid}@{SERVER_IP}:4443?encryption=none&security=tls&sni={use_sni}&type=ws&host={use_sni}&path=%2Fzen&allowInsecure=1#ZenVPN-{username}",
        "trojan":    f"trojan://{trojan_uuid}@{SERVER_IP}:8443?security=tls&sni={use_sni}&type=ws&host={use_sni}&path=%2Ftrojan&allowInsecure=1#ZenVPN-Trojan-{username}",
        "vmess":     f"vmess://{vmess_b64}",
        "ss":        f"ss://{ss_userinfo}@{SERVER_IP}:8388#ZenVPN-SS-{username}",
        "hysteria2": f"hysteria2://{vless_uuid}@{SERVER_IP}:5443?insecure=1&sni={use_sni}#ZenVPN-Hysteria2-{username}"
    }

# =============================================================================
# Pydantic Schemas
# =============================================================================
class CreateUserRequest(BaseModel):
    username: str
    plan:     str = "basic"
    notes:    Optional[str] = ""

class UpdateUserRequest(BaseModel):
    plan:   Optional[str] = None
    status: Optional[str] = None
    notes:  Optional[str] = None

class AddDeviceRequest(BaseModel):
    device_name: Optional[str] = None
    sni: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str

# =============================================================================
# App
# =============================================================================
app = FastAPI(
    title="ZenVPN Admin API",
    description="Backend API for ZenVPN management",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Startup — Create default admin if none exists
# =============================================================================
@app.on_event("startup")
def startup():
    db = SessionLocal()
    admin = db.query(AdminUser).first()
    if not admin:
        default_admin = AdminUser(
            username="admin",
            hashed_password=hash_password("zenvpn2024")
        )
        db.add(default_admin)
        db.commit()
        print("✔ Default admin created → username: admin | password: zenvpn2024")
        print("⚠ Change password immediately via /auth/change-password")
    db.close()

# =============================================================================
# Auth Routes
# =============================================================================
@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    admin = db.query(AdminUser).filter(AdminUser.username == form.username).first()
    if not admin or not verify_password(form.password, admin.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_token({"sub": admin.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/change-password", tags=["Auth"])
def change_password(
    old_password: str,
    new_password: str,
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    if not verify_password(old_password, admin.hashed_password):
        raise HTTPException(status_code=400, detail="Old password incorrect")
    admin.hashed_password = hash_password(new_password)
    db.commit()
    return {"message": "Password changed successfully"}

# =============================================================================
# Plans Route
# =============================================================================
@app.get("/plans", tags=["Plans"])
def get_plans():
    return PLANS

# =============================================================================
# User Routes
# =============================================================================
@app.get("/users", tags=["Users"])
def list_users(admin=Depends(get_current_admin), db: Session = Depends(get_db)):
    users     = db.query(VPNUser).all()
    now       = datetime.utcnow()
    result    = []
    for u in users:
        expired = u.expiry_date and u.expiry_date < now
        result.append({
            "id":           u.id,
            "username":     u.username,
            "plan":         u.plan,
            "status":       "expired" if expired else u.status,
            "bandwidth_mbps": u.bandwidth_mbps,
            "device_limit": u.device_limit,
            "price_lkr":    u.price_lkr,
            "created_at":   u.created_at.isoformat(),
            "expiry_date":  u.expiry_date.isoformat() if u.expiry_date else None,
            "days_left":    (u.expiry_date - now).days if u.expiry_date and not expired else 0,
            "notes":        u.notes
        })
    return result

@app.post("/users", tags=["Users"])
def create_user(
    request: CreateUserRequest,
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    # Validate plan
    if request.plan not in PLANS:
        raise HTTPException(status_code=400, detail=f"Invalid plan. Choose: {list(PLANS.keys())}")

    # Check duplicate
    existing = db.query(VPNUser).filter(VPNUser.username == request.username).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"User '{request.username}' already exists")

    plan      = PLANS[request.plan]
    expiry    = datetime.utcnow() + timedelta(days=plan["duration_days"])

    # Generate UUIDs
    vless_uuid  = str(uuid.uuid4())
    trojan_uuid = str(uuid.uuid4())
    vmess_uuid  = str(uuid.uuid4())

    # Add to SQLite
    vpn_user = VPNUser(
        username      = request.username,
        plan          = request.plan,
        bandwidth_mbps = plan["bandwidth_mbps"],
        device_limit  = plan["device_limit"],
        price_lkr     = plan["price_lkr"],
        expiry_date   = expiry,
        notes         = request.notes or ""
    )
    db.add(vpn_user)
    db.commit()

    # Add to sing-box users.json
    sb_data = load_singbox_users()
    sb_data["users"].append({
        "name":          request.username,
        "plan":          request.plan,
        "bandwidth_mbps": plan["bandwidth_mbps"],
        "device_limit":  plan["device_limit"],
        "status":        "active",
        "created":       datetime.utcnow().isoformat() + "Z",
        "expiry":        expiry.isoformat() + "Z",
        "devices": [{
            "device":      "device-1",
            "vless_uuid":  vless_uuid,
            "trojan_uuid": trojan_uuid,
            "vmess_uuid":  vmess_uuid,
            "last_ip":     "",
            "last_seen":   "",
            "registered":  datetime.utcnow().isoformat() + "Z",
            "status":      "active"
        }]
    })
    save_singbox_users(sb_data)
    rebuild_singbox_config()
    reload_singbox()

    uris = generate_uris(request.username, vless_uuid, trojan_uuid, vmess_uuid)

    return {
        "message":  f"User '{request.username}' created successfully",
        "username": request.username,
        "plan":     request.plan,
        "expiry":   expiry.isoformat(),
        "uris":     uris
    }

@app.get("/users/{username}", tags=["Users"])
def get_user(username: str, admin=Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(VPNUser).filter(VPNUser.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get devices from sing-box DB
    sb_data  = load_singbox_users()
    sb_user  = next((u for u in sb_data["users"] if u["name"] == username), None)
    devices  = sb_user.get("devices", []) if sb_user else []

    return {
        "username":     user.username,
        "plan":         user.plan,
        "status":       user.status,
        "bandwidth_mbps": user.bandwidth_mbps,
        "device_limit": user.device_limit,
        "price_lkr":    user.price_lkr,
        "created_at":   user.created_at.isoformat(),
        "expiry_date":  user.expiry_date.isoformat() if user.expiry_date else None,
        "days_left":    (user.expiry_date - datetime.utcnow()).days if user.expiry_date else 0,
        "notes":        user.notes,
        "devices":      devices
    }

@app.put("/users/{username}", tags=["Users"])
def update_user(
    username: str,
    request: UpdateUserRequest,
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    user = db.query(VPNUser).filter(VPNUser.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if request.plan and request.plan in PLANS:
        plan               = PLANS[request.plan]
        user.plan          = request.plan
        user.bandwidth_mbps = plan["bandwidth_mbps"]
        user.device_limit  = plan["device_limit"]
        user.price_lkr     = plan["price_lkr"]

    if request.status:
        user.status = request.status

    if request.notes is not None:
        user.notes = request.notes

    db.commit()

    # Sync to sing-box users.json
    sb_data = load_singbox_users()
    for u in sb_data["users"]:
        if u["name"] == username:
            if request.status:
                u["status"] = request.status
            if request.plan:
                u["plan"]          = request.plan
                u["bandwidth_mbps"] = PLANS[request.plan]["bandwidth_mbps"]
                u["device_limit"]  = PLANS[request.plan]["device_limit"]

    save_singbox_users(sb_data)
    rebuild_singbox_config()
    reload_singbox()

    return {"message": f"User '{username}' updated successfully"}

@app.delete("/users/{username}", tags=["Users"])
def delete_user(username: str, admin=Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(VPNUser).filter(VPNUser.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()

    # Remove from sing-box
    sb_data         = load_singbox_users()
    sb_data["users"] = [u for u in sb_data["users"] if u["name"] != username]
    save_singbox_users(sb_data)
    rebuild_singbox_config()
    reload_singbox()

    return {"message": f"User '{username}' deleted and disconnected"}

@app.post("/users/{username}/suspend", tags=["Users"])
def suspend_user(username: str, admin=Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(VPNUser).filter(VPNUser.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.status = "suspended"
    db.commit()

    sb_data = load_singbox_users()
    for u in sb_data["users"]:
        if u["name"] == username:
            u["status"] = "suspended"
    save_singbox_users(sb_data)
    rebuild_singbox_config()
    reload_singbox()

    return {"message": f"User '{username}' suspended"}

@app.post("/users/{username}/reactivate", tags=["Users"])
def reactivate_user(username: str, admin=Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(VPNUser).filter(VPNUser.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    plan           = PLANS[user.plan]
    user.status    = "active"
    user.expiry_date = datetime.utcnow() + timedelta(days=plan["duration_days"])
    db.commit()

    sb_data = load_singbox_users()
    for u in sb_data["users"]:
        if u["name"] == username:
            u["status"] = "active"
            u["expiry"] = user.expiry_date.isoformat() + "Z"
    save_singbox_users(sb_data)
    rebuild_singbox_config()
    reload_singbox()

    return {"message": f"User '{username}' reactivated until {user.expiry_date.isoformat()}"}

@app.post("/users/{username}/renew", tags=["Users"])
def renew_user(username: str, admin=Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(VPNUser).filter(VPNUser.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    plan             = PLANS[user.plan]
    base             = max(user.expiry_date, datetime.utcnow()) if user.expiry_date else datetime.utcnow()
    user.expiry_date = base + timedelta(days=plan["duration_days"])
    user.status      = "active"
    db.commit()

    sb_data = load_singbox_users()
    for u in sb_data["users"]:
        if u["name"] == username:
            u["status"] = "active"
            u["expiry"] = user.expiry_date.isoformat() + "Z"
    save_singbox_users(sb_data)

    return {"message": f"User '{username}' renewed until {user.expiry_date.isoformat()}"}

@app.post("/users/{username}/devices", tags=["Users"])
def add_device(
    username: str,
    request: AddDeviceRequest,
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    user = db.query(VPNUser).filter(VPNUser.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    sb_data = load_singbox_users()
    sb_user = next((u for u in sb_data["users"] if u["name"] == username), None)
    if not sb_user:
        raise HTTPException(status_code=404, detail="User not found in sing-box config")

    devices = sb_user.setdefault("devices", [])
    if len(devices) >= user.device_limit:
        raise HTTPException(status_code=400, detail="Device limit reached")

    vless_uuid = str(uuid.uuid4())
    trojan_uuid = str(uuid.uuid4())
    vmess_uuid = str(uuid.uuid4())

    device_name = request.device_name if request.device_name else f"device-{len(devices) + 1}"

    new_device = {
        "device": device_name,
        "vless_uuid": vless_uuid,
        "trojan_uuid": trojan_uuid,
        "vmess_uuid": vmess_uuid,
        "last_ip": "",
        "last_seen": "",
        "registered": datetime.utcnow().isoformat() + "Z",
        "status": "active"
    }
    if request.device_name:
        new_device["device_name"] = request.device_name
    if request.sni:
        new_device["sni"] = request.sni

    devices.append(new_device)
    save_singbox_users(sb_data)
    rebuild_singbox_config()
    reload_singbox()

    uris = generate_uris(username, vless_uuid, trojan_uuid, vmess_uuid, sni=request.sni)

    return {
        "vless_uuid": vless_uuid,
        "trojan_uuid": trojan_uuid,
        "vmess_uuid": vmess_uuid,
        "uris": uris
    }

@app.delete("/users/{username}/devices/{device_index_or_id}", tags=["Users"])
def delete_device(
    username: str,
    device_index_or_id: str,
    admin=Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    user = db.query(VPNUser).filter(VPNUser.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    sb_data = load_singbox_users()
    sb_user = next((u for u in sb_data["users"] if u["name"] == username), None)
    if not sb_user:
        raise HTTPException(status_code=404, detail="User not found in sing-box config")

    devices = sb_user.setdefault("devices", [])

    target_idx = None
    try:
        idx = int(device_index_or_id)
        if 0 <= idx < len(devices):
            target_idx = idx
    except ValueError:
        pass

    if target_idx is None:
        for idx, dev in enumerate(devices):
            if (dev.get("device") == device_index_or_id or
                dev.get("device_name") == device_index_or_id or
                dev.get("vless_uuid") == device_index_or_id or
                dev.get("trojan_uuid") == device_index_or_id or
                dev.get("vmess_uuid") == device_index_or_id):
                target_idx = idx
                break

    if target_idx is None:
        raise HTTPException(status_code=404, detail="Device not found")

    removed_device = devices.pop(target_idx)
    sb_user["devices"] = devices

    save_singbox_users(sb_data)
    rebuild_singbox_config()
    reload_singbox()

    return {"message": f"Device '{removed_device.get('device', device_index_or_id)}' removed successfully"}

# =============================================================================
# Stats Route
# =============================================================================
@app.get("/stats", tags=["Stats"])
def get_stats(admin=Depends(get_current_admin), db: Session = Depends(get_db)):
    now      = datetime.utcnow()
    users    = db.query(VPNUser).all()

    total    = len(users)
    active   = sum(1 for u in users if u.status == "active" and (not u.expiry_date or u.expiry_date > now))
    expired  = sum(1 for u in users if u.expiry_date and u.expiry_date < now)
    suspended = sum(1 for u in users if u.status == "suspended")
    basic    = sum(1 for u in users if u.plan == "basic")
    pro      = sum(1 for u in users if u.plan == "pro")

    # Monthly revenue estimate
    revenue  = sum(u.price_lkr for u in users if u.status == "active")

    # Server stats
    try:
        with open("/proc/loadavg") as f:
            load = f.read().split()[0]
    except:
        load = "N/A"

    try:
        with open("/proc/meminfo") as f:
            lines   = f.readlines()
            mem_total = int(lines[0].split()[1])
            mem_free  = int(lines[1].split()[1])
            mem_used  = mem_total - mem_free
            mem_pct   = round((mem_used / mem_total) * 100, 1)
    except:
        mem_pct = "N/A"

    return {
        "users": {
            "total":     total,
            "active":    active,
            "expired":   expired,
            "suspended": suspended
        },
        "plans": {
            "basic": basic,
            "pro":   pro
        },
        "revenue": {
            "monthly_lkr": revenue
        },
        "server": {
            "load_avg":   load,
            "memory_pct": mem_pct,
            "ip":         SERVER_IP
        }
    }

# =============================================================================
# Background Expiry Worker
# =============================================================================
def expiry_worker():
    db  = SessionLocal()
    now = datetime.utcnow()
    try:
        expired_users = db.query(VPNUser).filter(
            VPNUser.expiry_date < now,
            VPNUser.status == "active"
        ).all()

        if expired_users:
            sb_data = load_singbox_users()
            for user in expired_users:
                user.status = "expired"
                for sb_user in sb_data["users"]:
                    if sb_user["name"] == user.username:
                        sb_user["status"] = "expired"
                print(f"[Expiry Worker] Expired: {user.username}")

            db.commit()
            save_singbox_users(sb_data)
            rebuild_singbox_config()
            reload_singbox()
    except Exception as e:
        print(f"[Expiry Worker] Error: {e}")
    finally:
        db.close()

scheduler = BackgroundScheduler()
scheduler.add_job(expiry_worker, "interval", minutes=1)
scheduler.start()

# =============================================================================
# Health Check
# =============================================================================
@app.get("/", tags=["Health"])
def root():
    return {
        "service": "ZenVPN API",
        "version": "1.0.0",
        "status":  "running"
    }
