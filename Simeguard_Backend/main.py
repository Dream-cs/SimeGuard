import base64
import hashlib
import heapq
import asyncio
import hmac
import json
import math
import os
import re
import secrets
import threading
import time
import urllib.request
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import anyio
from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from sqlalchemy import ForeignKey, Index, create_engine, delete, event, func, inspect, or_, select, text, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

try:   
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ==========================================
# 0. Configuration (environment variables, see .env.example)
# ==========================================
DEMO_MODE = os.getenv("DEMO_MODE", "1") == "1"
USE_ALEMBIC = os.getenv("USE_ALEMBIC") == "1"     
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
TOKEN_TTL = int(os.getenv("TOKEN_TTL_HOURS", "12")) * 3600

ALLOWED_ORIGINS = [o.strip() for o in os.getenv(
    "ALLOWED_ORIGINS", "*" if DEMO_MODE else "http://127.0.0.1:8000,http://localhost:8000").split(",") if o.strip()]
if "*" in ALLOWED_ORIGINS and not DEMO_MODE:
    print("[SimeGuard] WARNING: ALLOWED_ORIGINS=* in production. Set it to your dashboard URL.")

SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)   # random per start if unset (logins reset on restart)

if int(os.getenv("WEB_CONCURRENCY", "1") or 1) > 1:
    print("[SimeGuard] WARNING: several workers detected. The WebSocket hub and login lockout live in process "
          "memory, so run ONE worker (or move that state to Redis).")

# Timestamps are stored as naive local time. Change TIMEZONE if the site is not in Malaysia.
try:
    from zoneinfo import ZoneInfo
    LOCAL_TZ = ZoneInfo(os.getenv("TIMEZONE", "Asia/Kuala_Lumpur"))
except Exception:  
    LOCAL_TZ = timezone(timedelta(hours=8))


def now_local() -> datetime:
    return datetime.now(LOCAL_TZ).replace(tzinfo=None)


STALE_HOURS = max(1, int(os.getenv("STALE_HOURS", "24")))      # an open alert older than this counts as "old"
AUTO_RESOLVE = os.getenv("AUTO_RESOLVE", "1") == "1"            # 1 = close old non-pet alerts automatically (every 10 min)
FEED_LIMIT = int(os.getenv("FEED_LIMIT", "40"))                # newest open alerts shown (plus the latest of every track)
TRACK_WINDOW_MIN = int(os.getenv("TRACK_WINDOW_MIN", "120"))   # a track only uses sightings from the last N minutes

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
WEBHOOK_API_KEY = os.getenv("WEBHOOK_API_KEY") or ("dev-webhook-key" if DEMO_MODE else secrets.token_urlsafe(24))
if not os.getenv("WEBHOOK_API_KEY"):
    print(f"[SimeGuard] WEBHOOK_API_KEY not set. AI nodes must send header X-API-Key: {WEBHOOK_API_KEY}")


async def _auto_resolve_loop():
    """Every 10 minutes close old non-pet alerts nobody dealt with, so the open list cannot grow forever."""
    while True:
        try:
            await run_in_threadpool(auto_resolve_once)
        except Exception as exc:   # a housekeeping failure must never take the server down
            print(f"[SimeGuard] auto-resolve failed: {exc}")
        await asyncio.sleep(600)


@asynccontextmanager
async def lifespan(_app):
    await run_in_threadpool(init_db)
    task = asyncio.create_task(_auto_resolve_loop()) if AUTO_RESOLVE else None
    try:
        yield
    finally:
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


app = FastAPI(title="SimeGuard Security API", lifespan=lifespan)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")          # the dashboard may not be embedded in other sites
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api"):
        response.headers.setdefault("Cache-Control", "no-store")  # API answers (alerts, logins) are never cached
    return response


os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,   # set ALLOWED_ORIGINS to your dashboard URL in production
    allow_credentials=False,         # auth uses a bearer token, not cookies
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# 1. Database (SQLAlchemy: SQLite in dev, PostgreSQL in production)
#    export DATABASE_URL="postgresql+psycopg://user:pass@host:5432/simeguard"
# ==========================================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///simeguard.db")
IS_SQLITE = DATABASE_URL.startswith("sqlite")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    **({"connect_args": {"check_same_thread": False}} if IS_SQLITE else {"pool_size": 10, "max_overflow": 20}),
)

if IS_SQLITE:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA journal_mode=WAL")  # readers no longer block the writer

SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Resident(Base):
    __tablename__ = "Residents"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    phone: Mapped[str]
    unit_number: Mapped[str]
    registration_date: Mapped[datetime] = mapped_column(default=now_local)


class LostPet(Base):
    __tablename__ = "LostPets"
    id: Mapped[int] = mapped_column(primary_key=True)
    resident_id: Mapped[int] = mapped_column(ForeignKey("Residents.id"), index=True)
    pet_name: Mapped[str]
    species: Mapped[Optional[str]]
    pet_image_url: Mapped[Optional[str]]
    last_seen_location: Mapped[Optional[str]]
    status: Mapped[str] = mapped_column(default="missing")


class Incident(Base):
    __tablename__ = "Incidents"
    __table_args__ = (
        Index("ix_incident_status_ts", "status", "timestamp"),
        Index("ix_incident_debounce", "type", "location", "timestamp"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[Optional[str]]
    location: Mapped[Optional[str]]
    image_url: Mapped[Optional[str]]
    status: Mapped[str] = mapped_column(default="open")
    timestamp: Mapped[datetime]
    pet_id: Mapped[Optional[int]]
    plate_number: Mapped[Optional[str]]
    resolved_by: Mapped[Optional[str]]
    resolved_at: Mapped[Optional[datetime]]


class User(Base):
    __tablename__ = "Users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True, index=True)
    password_hash: Mapped[str]
    role: Mapped[str] = mapped_column(default="guard")  # "admin" | "guard" | "resident"
    resident_id: Mapped[Optional[int]]                  # set for role "resident": which household this login belongs to
    created_at: Mapped[datetime] = mapped_column(default=now_local)


def ensure_columns():
    """Dev convenience: add columns that older databases lack. Production uses Alembic instead."""
    wanted = {"Incidents": {"pet_id": "INTEGER", "plate_number": "VARCHAR", "resolved_by": "VARCHAR",
                            "resolved_at": "TIMESTAMP"},
              "Users": {"resident_id": "INTEGER"}}
    with engine.begin() as conn:
        for table, columns in wanted.items():
            have = {c["name"] for c in inspect(engine).get_columns(table)}
            for name, sql_type in columns.items():
                if name not in have:
                    conn.execute(text(f'ALTER TABLE "{table}" ADD COLUMN {name} {sql_type}'))


def init_db():
    if not USE_ALEMBIC:
        Base.metadata.create_all(engine)
        ensure_columns()
    with SessionLocal() as db:
        if DEMO_MODE:                 # never put fake residents into a real database
            seed_residents(db)
        canonicalize_units(db)
        seed_users(db)
        db.commit()

DEMO_RESIDENTS = [
    ("Ahmad Faiz", "012-3456789", "No. 12, Lorong 2"),
    ("Tan Mei Ling", "016-8889999", "No. 5, Lorong 1"),
    ("Priya Nair", "017-2223344", "No. 21, Lorong 2"),
    ("Lim Wei Jie", "011-12345678", "No. 8, Lorong 1"),
]

# ---- The site plan has exactly 60 houses (No. 1 to No. 60) ----
MAX_UNIT = 60
MAX_PER_UNIT = max(1, int(os.getenv("MAX_PER_UNIT", "4")))   # registered residents per house (1 = one per house)
_unit_lock = threading.Lock()   # makes "count, then insert" atomic within this process


def lorong_of(n: int) -> str:
    """Which street a house faces on the site plan: 1-10 L1, 11-30 L2 (both sides), 31-40 L3, 41-60 L4."""
    return "Lorong 1" if n <= 10 else "Lorong 2" if n <= 30 else "Lorong 3" if n <= 40 else "Lorong 4"


def unit_label(n: int) -> str:
    return f"No. {n}, {lorong_of(n)}"


def parse_unit(raw: Optional[str]) -> Optional[int]:
    s = (raw or "").strip().lower()
    m = re.search(r"\bno\.?\s*(\d+)", s) or re.search(r"\b(\d+)\b", s)
    n = int(m.group(1)) if m else 0
    
    if 1 <= n <= MAX_UNIT:
        # Verify the street matches the site plan if one was typed.
        # Compare the street NUMBER exactly so "Lorong 10" can't pass as "Lorong 1".
        if "lorong" in s:
            street = re.search(r"lorong\s*(\d+)\b", s)
            if not street or street.group(1) != lorong_of(n).split()[-1]:
                return None
        return n
    return None

def normalize_unit(raw: Optional[str]) -> str:
    n = parse_unit(raw)
    if n is None:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid address. Unit must be a valid number (1-{MAX_UNIT}) and match the correct street on the site plan."
        )
    return unit_label(n)


def canonicalize_units(db: Session):
    """Fix old rows such as 'No. 21, Lorong 3' to what the map says; warn about units that do not exist."""
    for r in db.scalars(select(Resident)):
        n = parse_unit(r.unit_number)
        if n is None:
            print(f"[SimeGuard] WARNING: resident #{r.id} ({r.name}) has unit '{r.unit_number}', which is not on the site plan.")
        elif r.unit_number != unit_label(n):
            r.unit_number = unit_label(n)



def digits(s):
    return re.sub(r"\D", "", s or "")


def fmt(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else None


def seed_residents(db: Session):
    if not db.scalar(select(func.count()).select_from(Resident)):
        db.add_all([Resident(name=n, phone=p, unit_number=u) for n, p, u in DEMO_RESIDENTS])


def find_resident(db: Session, name: str, phone: str):
    for r in db.scalars(select(Resident)):
        if digits(r.phone) == digits(phone) and r.name.strip().lower() == name.strip().lower():
            return {"resident_id": r.id, "name": r.name, "phone": r.phone, "unit_number": r.unit_number}
    return None


def get_db():
    with SessionLocal() as db:
        yield db


# ==========================================
# 1b. Auth: users, signed tokens, roles
# ==========================================
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    return f"{salt.hex()}${hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1).hex()
        return hmac.compare_digest(calc, digest)
    except Exception:
        return False


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _sign(body: str) -> str:
    return _b64(hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).digest())


RESIDENT_TOKEN_TTL = int(os.getenv("RESIDENT_TOKEN_HOURS", "4")) * 3600  # residents get shorter sessions


def make_token(username: str, role: str, rid: Optional[int] = None) -> str:
    ttl = RESIDENT_TOKEN_TTL if role == "resident" else TOKEN_TTL
    body = _b64(json.dumps({"u": username, "r": role, "rid": rid, "exp": int(time.time()) + ttl}).encode())
    return f"{body}.{_sign(body)}"


def read_token(token: Optional[str]):
    try:
        body, sig = (token or "").split(".")
        if not hmac.compare_digest(sig, _sign(body)):
            return None
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        return data if data["exp"] > time.time() else None
    except Exception:
        return None


WS_TICKET_TTL = 30  # seconds: a WebSocket ticket is single-purpose and expires almost immediately


def make_ws_ticket(user: dict) -> str:
    body = _b64(json.dumps({"u": user["u"], "r": user["r"], "ws": 1, "exp": int(time.time()) + WS_TICKET_TTL}).encode())
    return f"{body}.{_sign(body)}"


def current_user(authorization: Optional[str] = Header(None)):
    auth_str = authorization or ""
    if auth_str.startswith("Bearer "):
        auth_str = auth_str[7:]

    data = read_token(auth_str.strip())
    if not data or data.get("ws"):   # a WebSocket ticket is never a login token
        raise HTTPException(status_code=401, detail="Please sign in.")
    return data


def require_admin(user=Depends(current_user)):
    if user["r"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return user


def require_staff(user=Depends(current_user)):
    """Guards and admins only. Residents must never see alerts, camera data, other residents or history."""
    if user["r"] not in ("admin", "guard"):
        raise HTTPException(status_code=403, detail="Security staff access required.")
    return user


def check_webhook_key(x_api_key: Optional[str] = Header(None)):
    if not hmac.compare_digest(x_api_key or "", WEBHOOK_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key.")


def staff_or_node(authorization: Optional[str] = Header(None), x_api_key: Optional[str] = Header(None)):
    """Camera layout may be read by an AI node (webhook key) or by signed-in staff."""
    if x_api_key and hmac.compare_digest(x_api_key, WEBHOOK_API_KEY):
        return
    require_staff(current_user(authorization))


AUTH = [Depends(current_user)]    # any signed-in user
STAFF = [Depends(require_staff)]  # guards and admins only


def seed_users(db: Session):
    if not db.scalar(select(func.count()).select_from(User)):
        admin_pw = os.getenv("ADMIN_PASSWORD")
        if not admin_pw:
            admin_pw = "admin123" if DEMO_MODE else secrets.token_urlsafe(12)
            print(f"[SimeGuard] Created admin '{ADMIN_USER}' with password: {admin_pw}  (change it!)")
        db.add(User(username=ADMIN_USER, password_hash=hash_password(admin_pw), role="admin"))
        if DEMO_MODE:
            db.add(User(username="guard", password_hash=hash_password("guard123"), role="guard"))
            print("[SimeGuard] Demo guard account: guard / guard123")
    if DEMO_MODE and not db.scalar(select(User.id).where(User.username == "resident")):
        first = db.scalar(select(Resident.id).order_by(Resident.id).limit(1))
        if first:
            db.add(User(username="resident", password_hash=hash_password("resident123"), role="resident",
                        resident_id=first))
            print("[SimeGuard] Demo resident account: resident / resident123")


def resident_info(db: Session, rid: Optional[int]):
    r = db.get(Resident, rid) if rid else None
    return {"id": r.id, "name": r.name, "unit_number": r.unit_number} if r else None


class LoginBody(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "guard"
    resident_id: Optional[int] = None   # required when role == "resident"


class PasswordChange(BaseModel):
    old_password: str
    new_password: str


class ResidentCreate(BaseModel):
    name: str
    phone: str
    unit_number: str

    @field_validator("phone")
    @classmethod
    def _phone(cls, v):
        # Strip all non-numeric characters to count the actual digits
        clean_number = re.sub(r"\D", "", v)
        if not (8 <= len(clean_number) <= 15):
            raise ValueError("Invalid phone format. Must contain between 8 and 15 digits.")
        return v


_failed_logins: dict = {}  # "ip:user" -> (failures, locked_until)


@app.post("/api/login")
def login(body: LoginBody, request: Request, db: Session = Depends(get_db)):
    if len(_failed_logins) > 1000:   # stop the lockout table growing forever
        for k in [k for k, (_, until) in _failed_logins.items() if until <= time.time()]:
            _failed_logins.pop(k, None)
    key = f"{request.client.host if request.client else '?'}:{body.username.strip().lower()}"
    failures, locked_until = _failed_logins.get(key, (0, 0))
    if locked_until > time.time():
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in a minute.")
    user = db.scalar(select(User).where(func.lower(User.username) == body.username.strip().lower()))
    if not user or not verify_password(body.password, user.password_hash):
        failures += 1
        _failed_logins[key] = (failures, time.time() + 60 if failures >= 5 else 0)
        raise HTTPException(status_code=401, detail="Wrong username or password.")
    _failed_logins.pop(key, None)
    rid = user.resident_id if user.role == "resident" else None
    return {"token": make_token(user.username, user.role, rid), "username": user.username, "role": user.role,
            "demo": DEMO_MODE, "resident": resident_info(db, rid)}


@app.get("/api/ws_ticket")
def ws_ticket(user=Depends(require_staff)):
    """Browsers cannot set headers on a WebSocket, so the dashboard swaps its login token for a 30 s ticket
    and puts only that in the URL (URLs end up in logs; a 30 s single-purpose ticket is harmless there)."""
    return {"ticket": make_ws_ticket(user)}


@app.get("/api/me")
def me(user=Depends(current_user), db: Session = Depends(get_db)):
    return {"username": user["u"], "role": user["r"], "demo": DEMO_MODE,
            "resident": resident_info(db, user.get("rid")) if user["r"] == "resident" else None}


@app.post("/api/users")
def create_user(body: UserCreate, db: Session = Depends(get_db), _=Depends(require_admin)):
    if body.role not in ("admin", "guard", "resident"):
        raise HTTPException(status_code=400, detail="Role must be 'admin', 'guard' or 'resident'.")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    if body.role == "resident" and not db.get(Resident, body.resident_id or 0):
        raise HTTPException(status_code=400, detail="Choose the registered resident this login belongs to.")
    if db.scalar(select(User.id).where(func.lower(User.username) == body.username.strip().lower())):
        raise HTTPException(status_code=409, detail="That username is taken.")
    db.add(User(username=body.username.strip(), password_hash=hash_password(body.password), role=body.role,
                resident_id=body.resident_id if body.role == "resident" else None))
    db.commit()
    return {"status": "success"}


@app.post("/api/me/password")
def change_password(body: PasswordChange, db: Session = Depends(get_db), user=Depends(current_user)):
    row = db.scalar(select(User).where(User.username == user["u"]))
    if not row or not verify_password(body.old_password, row.password_hash):
        raise HTTPException(status_code=401, detail="Current password is wrong.")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    row.password_hash = hash_password(body.new_password)
    db.commit()
    return {"status": "success"}


# ==========================================
# 1c. Notifications (Telegram and/or any webhook: WhatsApp/SMS gateway, ntfy, Slack...)
# ==========================================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
NOTIFY_WEBHOOK_URL = os.getenv("NOTIFY_WEBHOOK_URL")
NOTIFY_COOLDOWN_S = int(os.getenv("NOTIFY_COOLDOWN_S", "60"))
NOTIFY_TYPES = {t.strip() for t in os.getenv("NOTIFY_TYPES", "").split(",") if t.strip()}  # empty = every type
NOTIFY_LANG = os.getenv("NOTIFY_LANG", "en").lower()  # "en" or "ms"
TYPE_LABELS_MS = {"suspicious_person": "ORANG MENCURIGAKAN", "unregistered_vehicle": "KENDERAAN TIDAK BERDAFTAR",
                  "lost_pet": "HAIWAN HILANG DIKESAN", "tailgating": "MENGEKORI MASUK", "trespasser": "PENCEROBOH"}
_last_notified: dict = {}
NOTIFY_ICONS = {"suspicious_person": "🕵️", "unregistered_vehicle": "🚗", "lost_pet": "🐾", "tailgating": "🚪", "trespasser": "🚷"}


def _post_json(url: str, payload: dict):
    req = urllib.request.Request(url, json.dumps(payload).encode(), {"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=8).read()
    except Exception as exc:  # never let a flaky notifier break alert ingestion
        print(f"[SimeGuard] notification failed: {exc}")


def _deliver(message: str, event: dict):
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        _post_json(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                   {"chat_id": TELEGRAM_CHAT_ID, "text": message})
    if NOTIFY_WEBHOOK_URL:
        _post_json(NOTIFY_WEBHOOK_URL, {"text": message, **event})


def notify_incident(db: Session, inc: Incident):
    """Fire-and-forget push for a brand-new incident (runs in a background thread)."""
    if not ((TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID) or NOTIFY_WEBHOOK_URL):
        return
    if NOTIFY_TYPES and inc.type not in NOTIFY_TYPES:
        return
    key, now = (inc.type, inc.location, inc.pet_id), time.time()
    if now - _last_notified.get(key, 0) < NOTIFY_COOLDOWN_S:
        return
    _last_notified[key] = now

    traj = trajectory_for(db, inc.type, inc.pet_id, inc.plate_number)
    route = traj.get("route_to_exit") if traj else None
    pet = owner = None
    if inc.pet_id:
        row = db.execute(select(LostPet, Resident).join(Resident, LostPet.resident_id == Resident.id)
                         .where(LostPet.id == inc.pet_id)).first()
        pet, owner = row if row else (None, None)

    ms = NOTIFY_LANG == "ms"
    label = (TYPE_LABELS_MS.get(inc.type) if ms else None) or (inc.type or "alert").replace("_", " ").upper()
    lines = [f"{NOTIFY_ICONS.get(inc.type, '⚠️')} {label} {'di' if ms else 'at'} {inc.location}"]
    if pet:
        lines.append(f"{'Haiwan' if ms else 'Pet'}: {pet.pet_name} ({pet.species})")
    if inc.plate_number:
        lines.append(f"{'No. plat' if ms else 'Plate'}: {inc.plate_number}")
    if route and route["eta_seconds"]:
        lines.append(f"⏱ {'Pintu keluar terdekat' if ms else 'Nearest exit'}: {route['gate']} "
                     f"{'dalam' if ms else 'in'} ~{route['eta_text']}")
    if traj and not ms:  # the recommendation text is English-only
        lines.append(f"🛡️ {traj['action_recommendation']}")
    # owner_phone and owner_message go only to the webhook (e.g. an SMS/WhatsApp gateway that texts the owner),
    # never into the group chat.
    owner_message = None
    if pet and owner:
        owner_message = (f"Hi {owner.name}, {pet.pet_name} dikesan di {inc.location} pada {fmt(inc.timestamp)}. "
                         f"Pengawal telah dimaklumkan. / {pet.pet_name} was just spotted at {inc.location}. "
                         f"Security has been alerted.")
    event = {"type": inc.type, "location": inc.location, "time": fmt(inc.timestamp), "plate_number": inc.plate_number,
             "pet_name": pet.pet_name if pet else None, "owner_phone": owner.phone if owner else None,
             "owner_message": owner_message, "eta_seconds": route["eta_seconds"] if route else None}
    threading.Thread(target=_deliver, args=("\n".join(lines), event), daemon=True).start()


# ==========================================
# 2. WebSocket hub: push alerts the instant they happen
# ==========================================
class ConnectionManager:
    def __init__(self):
        self.clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket):
        self.clients.discard(ws)

    async def broadcast(self, message: dict):
        for ws in list(self.clients):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(ws)


manager = ConnectionManager()


def push_feed(db: Session, reset: bool = False):
    """Called from sync endpoints (worker threads) after a commit; skips all work if nobody is watching."""
    if manager.clients:
        anyio.from_thread.run(manager.broadcast, {"event": "feed", "reset": reset, **feed_payload(db)})


def current_feed():
    with SessionLocal() as db:
        return feed_payload(db)


@app.websocket("/ws")
async def ws_feed(ws: WebSocket, token: Optional[str] = Query(None)):
    data = read_token(token)  # browsers can't set headers on WebSockets, so the token comes in the URL
    if not data or not data.get("ws") or data["r"] not in ("admin", "guard"):  # tickets only; residents never get the stream
        await ws.close(code=4401)
        return
    await manager.connect(ws)
    try:
        await ws.send_json({"event": "feed", "reset": False, **await run_in_threadpool(current_feed)})
        while True:
            msg = await ws.receive_json()
            if msg.get("op") == "ping":  # lets the dashboard measure real round-trip latency
                await ws.send_json({"event": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(ws)


# ==========================================
# 3. Data Models (Pydantic)
# ==========================================
KNOWN_TYPES = {"suspicious_person", "unregistered_vehicle", "lost_pet", "tailgating", "trespasser"}


def _check_location(v: str) -> str:
    if v not in CAMERA_NETWORK:
        raise ValueError(f"Unknown location. Use one of: {', '.join(CAMERA_NETWORK)}")
    return v


def _check_image_url(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    if len(v) > 500 or not v.startswith(("https://", "http://", "/static/")):
        raise ValueError("image_url must be an http(s) URL or a /static/ path (max 500 characters).")
    return v


class AlertIn(BaseModel):
    type: str
    location: str
    image_url: Optional[str] = None
    plate_number: Optional[str] = None
    pet_id: Optional[int] = None   # optional hint from an edge node that can recognise the pet itself

    @field_validator("type")
    @classmethod
    def _type(cls, v):
        if v not in KNOWN_TYPES:
            raise ValueError(f"Unknown alert type. Use one of: {', '.join(sorted(KNOWN_TYPES))}")
        return v

    @field_validator("location")
    @classmethod
    def _loc(cls, v):
        return _check_location(v)

    @field_validator("image_url")
    @classmethod
    def _img(cls, v):
        return _check_image_url(v)

    @field_validator("plate_number")
    @classmethod
    def _plate(cls, v):
        v = re.sub(r"\s+", " ", (v or "").strip().upper())
        if len(v) > 20:
            raise ValueError("plate_number is too long.")
        return v or None


class ResidentVerify(BaseModel):
    name: str
    phone: str


class LostPetCreate(BaseModel):
    resident_id: int
    pet_name: str
    species: str
    pet_image_url: str
    last_seen_location: str

    @field_validator("last_seen_location")
    @classmethod
    def _loc(cls, v):
        return _check_location(v)

    @field_validator("pet_image_url")
    @classmethod
    def _img(cls, v):
        return _check_image_url(v) or ""   # empty -> the endpoint substitutes a default picture


@app.get("/")
def read_root():
    return {"message": "SimeGuard Backend is successfully running!"}


# ==========================================
# 4. Core Security Endpoints (AI Alerts)
# ==========================================
@app.post("/api/ai_webhook", dependencies=[Depends(check_webhook_key)])
def receive_ai_alert(alert: AlertIn, db: Session = Depends(get_db)):
    now = now_local().replace(microsecond=0)
    same_target = Incident.plate_number == alert.plate_number if alert.plate_number else Incident.plate_number.is_(None)
    duplicate = db.scalar(
        select(Incident.id)
        .where(Incident.type == alert.type, Incident.location == alert.location, same_target,
               Incident.timestamp > now - timedelta(seconds=15))
        .limit(1)
    )
    if duplicate:
        return {"status": "ignored", "message": "Duplicate alert suppressed. System protected."}

    pet_id = pick_pet_for_sighting(db, alert.location, alert.pet_id) if alert.type == "lost_pet" else None

    inc = Incident(type=alert.type, location=alert.location, image_url=alert.image_url,
                   status="open", timestamp=now, plate_number=alert.plate_number, pet_id=pet_id)
    db.add(inc)
    db.commit()
    push_feed(db)
    notify_incident(db, inc)
    return {"status": "success", "message": "Alert logged", "timestamp": fmt(now)}


def feed_payload(db: Session) -> dict:
    is_open = Incident.status == "open"
    newest = select(Incident.id).where(is_open).order_by(Incident.timestamp.desc(), Incident.id.desc()).limit(FEED_LIMIT)
    # the latest sighting of every open track is always included, so a burst of new alerts cannot push it off the feed
    latest_per_track = select(func.max(Incident.id)).where(is_open).group_by(Incident.type, Incident.pet_id, Incident.plate_number)
    rows = db.execute(
        select(Incident, LostPet, Resident)
        .outerjoin(LostPet, Incident.pet_id == LostPet.id)
        .outerjoin(Resident, LostPet.resident_id == Resident.id)
        .where(is_open, or_(Incident.id.in_(newest), Incident.id.in_(latest_per_track)))
        .order_by(Incident.timestamp.desc(), Incident.id.desc())
    ).all()

    trajectories = {}
    for inc, _, _ in rows:
        key = (inc.type, inc.pet_id, inc.plate_number)
        if key not in trajectories:
            trajectories[key] = trajectory_for(db, inc.type, inc.pet_id, inc.plate_number)

    alerts = []
    for inc, pet, owner in rows:
        traj = trajectories[(inc.type, inc.pet_id, inc.plate_number)]
        alerts.append({
            "id": inc.id, "type": inc.type, "location": inc.location, "image_url": inc.image_url,
            "time": fmt(inc.timestamp), "plate_number": inc.plate_number,
            "owner_name": owner.name if owner else None,
            "owner_phone": owner.phone if owner else None,
            "owner_unit": owner.unit_number if owner else None,
            "pet_name": pet.pet_name if pet else None,
            "species": pet.species if pet else None,
            "pet_id": inc.pet_id,
            "last_seen_area": traj["last_seen"]["location"] if traj else inc.location,
            "trajectory": traj,
        })
    return {"alerts": alerts}


@app.get("/api/security_feed", dependencies=STAFF)
def get_security_feed(db: Session = Depends(get_db)):
    """HTTP fallback; the dashboard normally receives this over /ws."""
    return feed_payload(db)


@app.put("/api/resolve_alert/{incident_id}")
def resolve_alert(incident_id: int, db: Session = Depends(get_db), user=Depends(require_staff)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Alert not found.")
    stamp = {"status": "resolved", "resolved_by": user["u"], "resolved_at": now_local().replace(microsecond=0)}
    if inc.pet_id:
        db.execute(update(Incident).where(Incident.pet_id == inc.pet_id, Incident.status == "open").values(**stamp))
        db.execute(update(LostPet).where(LostPet.id == inc.pet_id).values(status="found"))
    elif inc.status == "open":
        for k, v in stamp.items():
            setattr(inc, k, v)
    db.commit()
    push_feed(db)
    return {"status": "success", "message": f"Alert {incident_id} has been resolved"}


@app.put("/api/reopen_alert/{incident_id}")
def reopen_alert(incident_id: int, db: Session = Depends(get_db), user=Depends(require_staff)):
    """Undo for 'Mark as resolved'. A pet alert resolves every open sighting of that pet at once, so undo
    brings back exactly that batch (same resolved_at) and marks the pet missing again."""
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Alert not found.")
    if inc.status != "resolved":
        raise HTTPException(status_code=409, detail="This alert is not resolved.")
    reopen = {"status": "open", "resolved_by": None, "resolved_at": None}
    if inc.pet_id and inc.resolved_at:
        db.execute(update(Incident).where(Incident.pet_id == inc.pet_id, Incident.status == "resolved",
                                          Incident.resolved_at == inc.resolved_at).values(**reopen))
        db.execute(update(LostPet).where(LostPet.id == inc.pet_id).values(status="missing"))
    else:
        for k, v in reopen.items():
            setattr(inc, k, v)
    db.commit()
    push_feed(db)
    return {"status": "success", "message": f"Alert {incident_id} reopened"}


def resolve_stale(db: Session, hours: int, by: str) -> int:
    """Close open alerts older than `hours`. Lost-pet sightings are skipped on purpose: resolving one marks the
    pet as FOUND, and only a person can know that."""
    cutoff = now_local() - timedelta(hours=hours)
    result = db.execute(update(Incident).where(Incident.status == "open", Incident.pet_id.is_(None),
                                               Incident.timestamp < cutoff)
                        .values(status="resolved", resolved_by=by, resolved_at=now_local().replace(microsecond=0)))
    db.commit()
    return result.rowcount or 0


def auto_resolve_once():
    with SessionLocal() as db:
        if resolve_stale(db, STALE_HOURS, "auto"):
            push_feed(db)


@app.put("/api/resolve_stale")
def resolve_stale_endpoint(hours: int = STALE_HOURS, db: Session = Depends(get_db), user=Depends(require_staff)):
    n = resolve_stale(db, max(1, hours), user["u"])
    if n:
        push_feed(db)
    return {"status": "success", "resolved": n}


@app.get("/api/stats", dependencies=STAFF)
def stats(db: Session = Depends(get_db)):
    """Real numbers for the top bar (replaces the old random 'AI load' / 'bandwidth' gauges)."""
    now = now_local()
    last_hour = db.scalar(select(func.count()).select_from(Incident).where(Incident.timestamp >= now - timedelta(hours=1)))
    oldest = db.scalar(select(func.min(Incident.timestamp)).where(Incident.status == "open"))
    stale = db.scalar(select(func.count()).select_from(Incident).where(
        Incident.status == "open", Incident.pet_id.is_(None), Incident.timestamp < now - timedelta(hours=STALE_HOURS)))
    return {"alerts_last_hour": last_hour or 0,
            "oldest_open_minutes": int((now - oldest).total_seconds() // 60) if oldest else None,
            "stale_count": stale or 0, "stale_hours": STALE_HOURS}


# ==========================================
# 5. Resident & Lost Pet Management
# ==========================================
@app.get("/api/residents", dependencies=STAFF)
def list_residents(db: Session = Depends(get_db)):
    missing = (select(func.count()).select_from(LostPet)
               .where(LostPet.resident_id == Resident.id, LostPet.status == "missing")
               .correlate(Resident).scalar_subquery())
    rows = db.execute(select(Resident, missing).order_by(Resident.id)).all()
    return {"residents": [
        {"id": r.id, "name": r.name, "phone": r.phone, "unit_number": r.unit_number,
         "registration_date": fmt(r.registration_date), "missing_pets": n} for r, n in rows
    ]}


@app.post("/api/residents", dependencies=[Depends(require_admin)])
def add_resident(resident: ResidentCreate, db: Session = Depends(get_db)):
    if not resident.name.strip():
        raise HTTPException(status_code=400, detail="Name is required.")
    unit = normalize_unit(resident.unit_number)
    with _unit_lock:   # count + insert must not interleave with another registration
        for phone in db.scalars(select(Resident.phone)):
            if digits(phone) == digits(resident.phone):
                raise HTTPException(status_code=409, detail="A resident with this phone number already exists.")
        taken = db.scalar(select(func.count()).select_from(Resident).where(Resident.unit_number == unit))
        if taken >= MAX_PER_UNIT:
            raise HTTPException(status_code=409, detail=f"{unit} already has {taken} registered resident(s) (limit {MAX_PER_UNIT}).")
        new = Resident(name=resident.name.strip(), phone=resident.phone, unit_number=unit)
        db.add(new)
        db.commit()
    return {"status": "success", "message": "Resident registered successfully", "resident_id": new.id, "unit_number": unit}


@app.delete("/api/residents/{resident_id}", dependencies=[Depends(require_admin)])
def delete_resident(resident_id: int, db: Session = Depends(get_db)):
    resident = db.get(Resident, resident_id)
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found.")
    
    # Remove everything that points at this resident (PostgreSQL enforces the LostPets foreign key).
    pet_ids = list(db.scalars(select(LostPet.id).where(LostPet.resident_id == resident_id)))
    if pet_ids:
        db.execute(update(Incident).where(Incident.pet_id.in_(pet_ids), Incident.status == "open")
                   .values(status="resolved", resolved_by="system", resolved_at=now_local().replace(microsecond=0)))
        db.execute(delete(LostPet).where(LostPet.id.in_(pet_ids)))
    db.execute(delete(User).where(User.resident_id == resident_id))
    db.delete(resident)
    db.commit()
    push_feed(db)
    return {"status": "success", "message": "Resident deleted successfully"}


@app.get("/api/units", dependencies=STAFF)
def unit_occupancy(db: Session = Depends(get_db)):
    """All 60 houses with how many residents each has, so the UI can grey out full ones."""
    counts = dict(db.execute(select(Resident.unit_number, func.count()).group_by(Resident.unit_number)).all())
    return {"max_unit": MAX_UNIT, "max_per_unit": MAX_PER_UNIT,
            "units": [{"unit": unit_label(n), "count": counts.get(unit_label(n), 0)} for n in range(1, MAX_UNIT + 1)]}


@app.post("/api/residents/verify", dependencies=STAFF)
def verify_resident(body: ResidentVerify, db: Session = Depends(get_db)):
    found = find_resident(db, body.name, body.phone)
    if not found:
        raise HTTPException(status_code=404, detail="Not a registered resident. Check the name and phone number.")
    return {"status": "success", **found}


@app.post("/api/lost_pets")
def report_lost_pet(pet: LostPetCreate, db: Session = Depends(get_db), user=Depends(current_user)):
    if user["r"] == "resident" and pet.resident_id != user.get("rid"):
        raise HTTPException(status_code=403, detail="You can only report your own pet.")  # never trust the id in the body
    if not db.get(Resident, pet.resident_id):
        raise HTTPException(status_code=404, detail="Only registered residents can report a lost pet.")
    img = pet.pet_image_url or "https://images.unsplash.com/photo-1543466835-00a7907e9de1?w=200"
    record = LostPet(resident_id=pet.resident_id, pet_name=pet.pet_name, species=pet.species,
                     pet_image_url=img, last_seen_location=pet.last_seen_location, status="missing")
    db.add(record)
    db.flush()
    db.add(Incident(type="lost_pet", location=pet.last_seen_location, image_url=img, status="open",
                    timestamp=now_local().replace(microsecond=0), pet_id=record.id))
    db.commit()
    push_feed(db)
    return {"status": "success", "message": "Lost pet reported successfully", "pet_id": record.id}


@app.get("/api/my_pets")
def my_pets(db: Session = Depends(get_db), user=Depends(current_user)):
    """A resident's own reports (newest first). Staff have no household, so they get an empty list."""
    rid = user.get("rid")
    rows = db.scalars(select(LostPet).where(LostPet.resident_id == rid).order_by(LostPet.id.desc()).limit(50)) if rid else []
    return {"pets": [{"pet_id": p.id, "pet_name": p.pet_name, "species": p.species, "pet_image_url": p.pet_image_url,
                      "last_seen_location": p.last_seen_location, "status": p.status} for p in rows]}


@app.put("/api/my_pets/{pet_id}/found")
def resident_found_pet(pet_id: int, db: Session = Depends(get_db), user=Depends(current_user)):
    pet = db.get(LostPet, pet_id)
    if not pet or pet.resident_id != user.get("rid"):
        raise HTTPException(status_code=403, detail="You can only manage your own pets.")
    
    pet.status = "found"
    
    # Automatically resolve any active AI alerts for this pet on the security dashboard
    db.execute(
        update(Incident)
        .where(Incident.pet_id == pet_id, Incident.status == "open")
        .values(status="resolved", resolved_by=user["u"], resolved_at=now_local().replace(microsecond=0))
    )
    db.commit()
    push_feed(db)
    return {"status": "success", "message": "Pet marked as found and security notified!"}


@app.get("/api/lost_pets", dependencies=STAFF)
def get_missing_pets(db: Session = Depends(get_db)):
    rows = db.execute(
        select(LostPet, Resident).join(Resident, LostPet.resident_id == Resident.id)
        .where(LostPet.status == "missing")
    ).all()
    return {"missing_pets": [
        {"pet_id": p.id, "pet_name": p.pet_name, "species": p.species, "pet_image_url": p.pet_image_url,
         "last_seen_location": p.last_seen_location, "owner_name": r.name, "owner_phone": r.phone,
         "owner_unit": r.unit_number} for p, r in rows
    ]}


@app.post("/api/upload_image", dependencies=AUTH)
def upload_image(file: UploadFile = File(...)):
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in (".jpg", ".jpeg", ".png", ".gif", ".webp"):
        raise HTTPException(status_code=400, detail="Only JPG, PNG, GIF or WEBP images are allowed.")
    name = f"pet_{uuid.uuid4().hex[:12]}{ext}"
    data = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Image is too large (max 5 MB).")
    with open(f"static/{name}", "wb") as buffer:
        buffer.write(data)
    return {"status": "success", "image_url": f"/static/{name}"}


# ==========================================
# 6. AI Trajectory Prediction + A* routing
# ==========================================
CAMERA_NETWORK = {
    "Main Gate":      {"x": 28.0, "y": 92.0, "neighbors": ["Lorong 1"]},
    "Side Gate":      {"x": 96.0, "y": 28.0, "neighbors": ["Lorong 3", "Lorong 4 East"]},
    "Community Park": {"x": 13.0, "y": 60.0, "neighbors": ["Lorong 1", "Lorong 4 West"]},
    "Lorong 1":       {"x": 28.0, "y": 60.0, "neighbors": ["Main Gate", "Community Park", "Lorong 4 West", "Lorong 2"]},
    "Lorong 2":       {"x": 61.0, "y": 60.0, "neighbors": ["Lorong 1", "Lorong 3", "Lorong 4 East"]},
    "Lorong 3":       {"x": 93.0, "y": 60.0, "neighbors": ["Side Gate", "Lorong 2"]},
    "Lorong 4 West":  {"x": 28.0, "y": 23.0, "neighbors": ["Lorong 1", "Community Park", "Lorong 4 East"]},
    "Lorong 4 East":  {"x": 61.0, "y": 23.0, "neighbors": ["Lorong 4 West", "Lorong 2", "Side Gate"]},
}

# Undirected adjacency built once, so a one-sided "neighbors" entry can never break routing.
GRAPH = {name: set() for name in CAMERA_NETWORK}
for _a, _info in CAMERA_NETWORK.items():
    for _b in _info["neighbors"]:
        GRAPH[_a].add(_b)
        GRAPH[_b].add(_a)

METERS_PER_UNIT = 3.0  # 1 map % ≈ 3 m. Calibrate this against your real site plan.
SPEED_MPS = {          # typical travel speeds per target type
    "suspicious_person": 1.4, "trespasser": 1.6, "lost_pet": 2.0,
    "unregistered_vehicle": 5.5, "tailgating": 5.5,
}
EXITS = ("Main Gate", "Side Gate")


def _meters(a: str, b: str) -> float:
    A, B = CAMERA_NETWORK[a], CAMERA_NETWORK[b]
    return math.hypot(A["x"] - B["x"], A["y"] - B["y"]) * METERS_PER_UNIT


def astar(start: str, goal: str, speed: float):
    """A* over the camera graph. Edge cost = travel seconds; the heuristic is straight-line seconds,
    which never overestimates, so the route is optimal. (With h = 0 this is plain Dijkstra.)"""
    h = lambda n: _meters(n, goal) / speed
    frontier = [(h(start), 0.0, start)]
    best, came_from = {start: 0.0}, {}
    while frontier:
        _, cost, node = heapq.heappop(frontier)
        if node == goal:
            path = [node]
            while node in came_from:
                node = came_from[node]
                path.append(node)
            return path[::-1], cost
        if cost > best.get(node, math.inf):
            continue
        for nxt in GRAPH[node]:
            new_cost = cost + _meters(node, nxt) / speed
            if new_cost < best.get(nxt, math.inf):
                best[nxt], came_from[nxt] = new_cost, node
                heapq.heappush(frontier, (new_cost + h(nxt), new_cost, nxt))
    return None, math.inf


def graph_hops(a: str, b: str) -> float:
    """Number of camera hops between two cameras (inf if unknown or unreachable)."""
    if a not in GRAPH or b not in GRAPH:
        return math.inf
    seen, queue = {a: 0}, [a]
    for node in queue:
        if node == b:
            return seen[node]
        for nxt in GRAPH[node]:
            if nxt not in seen:
                seen[nxt] = seen[node] + 1
                queue.append(nxt)
    return math.inf


def pick_pet_for_sighting(db: Session, location: str, hinted_id: Optional[int] = None) -> Optional[int]:
    """Which missing pet is this sighting most likely? An edge node that recognises the pet can send pet_id.
    Otherwise take the missing pet whose last known camera is closest to this one (ties: newest report)."""
    missing = db.scalars(select(LostPet).where(LostPet.status == "missing")).all()
    if not missing:
        return None
    if hinted_id is not None and any(p.id == hinted_id for p in missing):
        return hinted_id

    def last_known(p: LostPet):
        loc = db.scalar(select(Incident.location).where(Incident.pet_id == p.id)
                        .order_by(Incident.timestamp.desc(), Incident.id.desc()).limit(1))
        return loc or p.last_seen_location

    return min(missing, key=lambda p: (graph_hops(last_known(p), location), -p.id)).id


@app.get("/api/cameras", dependencies=[Depends(staff_or_node)])
def list_cameras():
    """Single source of truth for the camera layout (the simulator and edge nodes read it from here)."""
    return {"cameras": [{"name": n, "x": i["x"], "y": i["y"], "neighbors": sorted(GRAPH[n])}
                        for n, i in CAMERA_NETWORK.items()]}


def route_to_exit(location: str, incident_type: str):
    """Fastest multi-hop route from the last sighting to the nearest gate, with ETA."""
    if location not in GRAPH:
        return None
    speed = SPEED_MPS.get(incident_type, 1.4)
    options = [(cost, path, gate) for gate in EXITS for path, cost in [astar(location, gate, speed)] if path]
    if not options:
        return None
    cost, path, gate = min(options, key=lambda o: o[0])
    secs = round(cost)
    return {
        "gate": gate, "path": path, "eta_seconds": secs,
        "eta_text": f"{secs} s" if secs < 60 else f"{secs / 60:.1f} min",
        "speed_mps": speed,
    }


def predict_next_camera(records: list):
    latest_loc = records[-1][0]
    cam_info = CAMERA_NETWORK.get(latest_loc)

    if len(records) == 1 or not cam_info:
        if cam_info:
            predicted_zone = " or ".join(cam_info["neighbors"][:2])
        else:
            predicted_zone = f"Adjacent cameras near {latest_loc}"
        return (predicted_zone, f"Target detected at {latest_loc}. Monitor {predicted_zone} for potential movement.",
                {"kind": "first", "latest": latest_loc, "zone": predicted_zone})

    prev_loc = records[-2][0]
    prev_info = CAMERA_NETWORK.get(prev_loc)

    if prev_info and prev_loc != latest_loc:
        target_x = cam_info["x"] + (cam_info["x"] - prev_info["x"])
        target_y = cam_info["y"] + (cam_info["y"] - prev_info["y"])
        options = sorted(GRAPH[latest_loc])                      # a target can only move to a connected camera
        candidates = [n for n in options if n != prev_loc] or options
        best_cam = min(candidates, key=lambda n: (CAMERA_NETWORK[n]["x"] - target_x) ** 2 + (CAMERA_NETWORK[n]["y"] - target_y) ** 2)
        secondary = [n for n in options if n not in (prev_loc, best_cam)]
        predicted_zone = f"{best_cam} (Primary) / {secondary[0]}" if secondary else best_cam
        action = f"Moving from {prev_loc} → {latest_loc}. Dispatch patrol to intercept at {best_cam} immediately."
        info = {"kind": "moving", "prev": prev_loc, "latest": latest_loc, "best": best_cam}
    else:
        predicted_zone = " or ".join(cam_info["neighbors"][:2])
        action = f"Target lingering around {latest_loc}. Secure perimeter at {predicted_zone}."
        info = {"kind": "linger", "latest": latest_loc, "zone": predicted_zone}
    return predicted_zone, action, info


def build_trajectory(incident_type: str, records: list):
    if not records:
        return None
    predicted_zone, action, action_info = predict_next_camera(records)
    route = route_to_exit(records[-1][0], incident_type)
    if route:
        if route["eta_seconds"] == 0:
            action += f" Target is at {route['gate']}."
        else:
            action += f" Nearest exit: {route['gate']} in ~{route['eta_text']} via {' → '.join(route['path'])}."
    return {
        "first_seen": {"location": records[0][0], "time": records[0][1]},
        "last_seen": {"location": records[-1][0], "time": records[-1][1]},
        "total_sightings": len(records),
        "predicted_next_zone": predicted_zone,
        "action_recommendation": action,
        "action_info": action_info,   # structured form of the sentence, so the dashboard can translate it
        "route_to_exit": route,
    }


def trajectory_for(db: Session, incident_type: Optional[str], pet_id: Optional[int], plate: Optional[str] = None):
    """Track = open sightings from the last TRACK_WINDOW_MIN minutes of the SAME target
    (same pet, or same plate, or an unidentified person), so old resolved incidents never leak into a new track."""
    same_pet = Incident.pet_id.is_(None) if pet_id is None else Incident.pet_id == pet_id
    same_plate = Incident.plate_number == plate if plate else Incident.plate_number.is_(None)
    since = now_local() - timedelta(minutes=TRACK_WINDOW_MIN)
    recs = db.execute(
        select(Incident.location, Incident.timestamp)
        .where(Incident.type == incident_type, same_pet, same_plate,
               Incident.status == "open", Incident.timestamp >= since)
        .order_by(Incident.timestamp, Incident.id)
    ).all()
    return build_trajectory(incident_type, [(loc, fmt(ts)) for loc, ts in recs])


@app.get("/api/analyze_trajectory/{incident_type}", dependencies=STAFF)
def analyze_trajectory(incident_type: str, plate: Optional[str] = None, db: Session = Depends(get_db)):
    conds = [Incident.type == incident_type, Incident.status == "open",
             Incident.timestamp >= now_local() - timedelta(minutes=TRACK_WINDOW_MIN)]
    if plate:
        conds.append(Incident.plate_number == plate.strip().upper())
    recs = db.execute(
        select(Incident.location, Incident.timestamp).where(*conds)
        .order_by(Incident.timestamp, Incident.id)
    ).all()
    trajectory = build_trajectory(incident_type, [(loc, fmt(ts)) for loc, ts in recs])
    if trajectory is None:
        return {"status": "insufficient_data", "message": f"No sightings found for {incident_type}."}
    return {
        "status": "success",
        "target_type": incident_type,
        "tracking_summary": {k: trajectory[k] for k in ("first_seen", "last_seen", "total_sightings")},
        "ai_prediction": {k: trajectory[k] for k in ("predicted_next_zone", "action_recommendation", "action_info", "route_to_exit")},
    }


@app.get("/api/route/{start}/{goal}", dependencies=STAFF)
def get_route(start: str, goal: str, mode: str = "suspicious_person"):
    """Ad-hoc A* query, e.g. /api/route/Side Gate/Main Gate?mode=unregistered_vehicle"""
    if start not in GRAPH or goal not in GRAPH:
        raise HTTPException(status_code=404, detail="Unknown camera name.")
    path, cost = astar(start, goal, SPEED_MPS.get(mode, 1.4))
    return {"path": path, "eta_seconds": round(cost)}


@app.delete("/api/reset_db", dependencies=[Depends(require_admin)])
def reset_database(db: Session = Depends(get_db)):
    if not DEMO_MODE:
        raise HTTPException(status_code=403, detail="Reset is disabled outside demo mode (DEMO_MODE=0).")
    for model in (Incident, LostPet, Resident):
        db.execute(delete(model))
    seed_residents(db)
    db.flush()

    img_pet = "https://images.unsplash.com/photo-1543466835-00a7907e9de1?w=200"
    img_car = "https://images.unsplash.com/photo-1533473359331-0135ef1b58bf?w=200"
    img_man = "https://images.unsplash.com/photo-1506794778202-cad84cf45f1d?w=200"
    owner_id = db.scalar(select(Resident.id).order_by(Resident.id).limit(1))
    buddy = LostPet(resident_id=owner_id, pet_name="Buddy", species="Beagle", pet_image_url=img_pet,
                    last_seen_location="Community Park", status="missing")
    db.add(buddy)
    db.flush()

    ago = lambda m: (now_local() - timedelta(minutes=m)).replace(microsecond=0)
    demo = [  # type, location, image, minutes ago, plate, pet_id
        ("unregistered_vehicle", "Main Gate", img_car, 15, "WXY 8821", None),
        ("unregistered_vehicle", "Lorong 1", img_car, 3, "WXY 8821", None),
        ("suspicious_person", "Side Gate", img_man, 18, None, None),
        ("suspicious_person", "Lorong 3", img_man, 5, None, None),
        ("lost_pet", "Community Park", img_pet, 22, None, buddy.id),
        ("lost_pet", "Lorong 4 West", img_pet, 2, None, buddy.id),
        ("tailgating", "Lorong 2", "https://images.unsplash.com/photo-1517841905240-472988babdf9?w=200", 8, "VAB 3390", None),
        ("trespasser", "Lorong 4 East", "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=200", 11, None, None),
    ]
    db.add_all([Incident(type=t, location=l, image_url=i, status="open", timestamp=ago(m), plate_number=p, pet_id=pid)
                for t, l, i, m, p, pid in demo])
    db.commit()
    push_feed(db, reset=True)
    return {"message": "Database reset for Demo!", "status": "success"}


# ==========================================
# 7. Alert history (all statuses, searchable) and serving the dashboard
# ==========================================
@app.get("/api/history", dependencies=STAFF)
def alert_history(q: str = "", type: str = "", status: str = "", date_from: str = "", date_to: str = "",
                  limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    conds = []
    if type:
        conds.append(Incident.type == type)
    if status in ("open", "resolved"):
        conds.append(Incident.status == status)
    try:
        if date_from:
            conds.append(Incident.timestamp >= datetime.strptime(date_from, "%Y-%m-%d"))
        if date_to:
            conds.append(Incident.timestamp < datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1))
    except ValueError:
        raise HTTPException(status_code=400, detail="Dates must look like 2026-10-18.")
    if q.strip():
        like = f"%{q.strip()}%"
        conds.append(or_(Incident.location.ilike(like), Incident.plate_number.ilike(like),
                         Incident.type.ilike(like), LostPet.pet_name.ilike(like)))

    join = (Incident.pet_id == LostPet.id)
    total = db.scalar(select(func.count(Incident.id)).select_from(Incident).outerjoin(LostPet, join).where(*conds))
    rows = db.execute(
        select(Incident, LostPet.pet_name).outerjoin(LostPet, join).where(*conds)
        .order_by(Incident.timestamp.desc(), Incident.id.desc())
        .limit(max(1, min(limit, 200))).offset(max(0, offset))
    ).all()
    return {"total": total, "items": [
        {"id": i.id, "type": i.type, "location": i.location, "time": fmt(i.timestamp), "status": i.status,
         "plate_number": i.plate_number, "pet_name": pet_name, "image_url": i.image_url,
         "resolved_by": i.resolved_by, "resolved_at": fmt(i.resolved_at)} for i, pet_name in rows
    ]}


@app.get("/dashboard")
def dashboard():
    return FileResponse("index.html")


MAP_FILE = next((f for f in ("Community_map.png", "Community map.png") if os.path.exists(f)), "Community_map.png")


@app.get("/Community_map.png")
def community_map():
    return FileResponse(MAP_FILE)