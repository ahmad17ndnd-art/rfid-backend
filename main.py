import os
import sqlite3
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.hash import bcrypt
import jwt
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

# ==================== الإعدادات ====================
DB_PATH = os.environ.get("DB_PATH", "rfid_data.db")
JWT_SECRET = os.environ.get("JWT_SECRET", "change_this_secret_please")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
DEVICE_API_KEY = os.environ.get("DEVICE_API_KEY", "change_this_device_key")

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)

app = FastAPI(title="RFID Access Control API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # عدّلها لدومين الداشبورد بعد النشر
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== قاعدة البيانات ====================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    # حساب الأدمن (واحد أو أكثر - أول مرة بيتربط بجوجل)
    c.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            google_sub TEXT UNIQUE,
            password_hash TEXT,
            created_at TEXT
        )
    """)

    # أكواد استعادة كلمة المرور
    c.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            code TEXT,
            expires_at TEXT,
            used INTEGER DEFAULT 0
        )
    """)

    # البطاقات (الأشخاص المصرح لهم)
    c.execute("""
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT UNIQUE,
            person_name TEXT,
            status TEXT DEFAULT 'allowed',
            card_type TEXT DEFAULT 'permanent',
            valid_from TEXT DEFAULT NULL,
            valid_to TEXT DEFAULT NULL,
            is_emergency INTEGER DEFAULT 0,
            created_at TEXT
        )
    """)

    # سجل الدخول والخروج
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_uid TEXT,
            person_name TEXT,
            event_type TEXT,
            granted INTEGER DEFAULT 1,
            reason TEXT DEFAULT NULL,
            offline INTEGER DEFAULT 0,
            timestamp TEXT
        )
    """)

    # أمر فتح الباب عن بعد
    c.execute("""
        CREATE TABLE IF NOT EXISTS door_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pending INTEGER DEFAULT 0,
            requested_at TEXT
        )
    """)
    c.execute("SELECT COUNT(*) FROM door_commands")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO door_commands (pending) VALUES (0)")

    # الإشعارات
    c.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            title_ar TEXT,
            title_en TEXT,
            message_ar TEXT,
            message_en TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT
        )
    """)

    # إعدادات الإشعارات (سطر واحد عام للنظام)
    c.execute("""
        CREATE TABLE IF NOT EXISTS notification_settings (
            id INTEGER PRIMARY KEY,
            notify_email_enabled INTEGER DEFAULT 1,
            notify_on_denied INTEGER DEFAULT 1,
            notify_on_door_open INTEGER DEFAULT 1,
            notify_on_emergency INTEGER DEFAULT 1
        )
    """)
    c.execute("INSERT OR IGNORE INTO notification_settings (id) VALUES (1)")

    # ترحيل لقواعد بيانات قديمة
    migrations = [
        ("cards", "is_emergency", "INTEGER DEFAULT 0"),
        ("logs", "offline", "INTEGER DEFAULT 0"),
    ]
    for table, column, col_def in migrations:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ==================== نماذج البيانات (Pydantic) ====================

class GoogleLoginRequest(BaseModel):
    id_token: str


class SetPasswordRequest(BaseModel):
    admin_id: int
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    email: str
    code: str
    new_password: str


class CardCreateRequest(BaseModel):
    uid: str
    person_name: str
    status: str = "allowed"          # allowed | denied
    card_type: str = "permanent"     # permanent | temporary
    valid_from: str | None = None    # ISO datetime, للبطاقات المؤقتة
    valid_to: str | None = None
    is_emergency: bool = False       # بطاقة طوارئ (تشتغل حتى بدون نت)


class CardUpdateRequest(BaseModel):
    person_name: str | None = None
    status: str | None = None
    card_type: str | None = None
    valid_from: str | None = None
    valid_to: str | None = None
    is_emergency: bool | None = None


class ScanRequest(BaseModel):
    uid: str


class OfflineLogEntry(BaseModel):
    uid: str
    person_name: str
    event_type: str          # entry | exit
    timestamp: str           # ISO datetime كما سجّله الجهاز محلياً


class OfflineLogSyncRequest(BaseModel):
    entries: list[OfflineLogEntry]


class NotificationSettingsUpdate(BaseModel):
    notify_email_enabled: bool | None = None
    notify_on_denied: bool | None = None
    notify_on_door_open: bool | None = None
    notify_on_emergency: bool | None = None


# ==================== أدوات مساعدة: JWT ====================

def create_token(admin_id: int, email: str) -> str:
    payload = {
        "admin_id": admin_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(days=7),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_current_admin(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.replace("Bearer ", "")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def verify_device_key(x_device_key: str = Header(None)):
    if x_device_key != DEVICE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid device key")
    return True


def send_email(to_email: str, subject: str, body: str):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        raise HTTPException(status_code=500, detail="SMTP not configured on server")
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM, [to_email], msg.as_string())


def get_notification_settings():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM notification_settings WHERE id = 1")
    row = c.fetchone()
    conn.close()
    return dict(row) if row else {
        "notify_email_enabled": 1, "notify_on_denied": 1,
        "notify_on_door_open": 1, "notify_on_emergency": 1
    }


def create_notification(ntype: str, title_ar: str, title_en: str, message_ar: str, message_en: str,
                         should_email: bool = False):
    """يسجّل إشعار بالداشبورد، وممكن كمان يبعت إيميل حسب الإعدادات."""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """INSERT INTO notifications (type, title_ar, title_en, message_ar, message_en, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (ntype, title_ar, title_en, message_ar, message_en, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

    settings = get_notification_settings()
    if should_email and settings.get("notify_email_enabled"):
        conn2 = get_db()
        c2 = conn2.cursor()
        c2.execute("SELECT email FROM admins WHERE email IS NOT NULL")
        admin_emails = [r["email"] for r in c2.fetchall()]
        conn2.close()
        for email in admin_emails:
            try:
                send_email(email, f"{title_ar} / {title_en}", f"{message_ar}\n\n{message_en}")
            except Exception:
                pass  # ما منوقف العملية الأساسية إذا فشل الإيميل


# ==================== المصادقة (Auth) ====================

@app.post("/auth/google")
def auth_google(req: GoogleLoginRequest):
    """أول خطوة: ربط حساب Google. لو الحساب موجود ومربوط بكلمة مرور، بيرجع يطلب دخول عادي."""
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GOOGLE_CLIENT_ID not configured on server")

    try:
        idinfo = google_id_token.verify_oauth2_token(
            req.id_token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Google token")

    google_sub = idinfo["sub"]
    email = idinfo.get("email")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM admins WHERE google_sub = ?", (google_sub,))
    admin = c.fetchone()

    if admin:
        conn.close()
        if admin["password_hash"]:
            # عنده كلمة مرور مسبقاً -> يسجل دخول مباشرة
            token = create_token(admin["id"], admin["email"])
            return {"status": "logged_in", "token": token, "email": admin["email"]}
        else:
            # لسا ما حط كلمة مرور
            return {"status": "needs_password", "admin_id": admin["id"], "email": admin["email"]}

    # أدمن جديد -> ننشئه بدون كلمة مرور لسا
    c.execute(
        "INSERT INTO admins (email, google_sub, created_at) VALUES (?, ?, ?)",
        (email, google_sub, datetime.now().isoformat())
    )
    conn.commit()
    new_id = c.lastrowid
    conn.close()

    return {"status": "needs_password", "admin_id": new_id, "email": email}


@app.post("/auth/set-password")
def set_password(req: SetPasswordRequest):
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password too short (min 6 chars)")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM admins WHERE id = ?", (req.admin_id,))
    admin = c.fetchone()
    if not admin:
        conn.close()
        raise HTTPException(status_code=404, detail="Admin not found")

    password_hash = bcrypt.hash(req.password)
    c.execute("UPDATE admins SET password_hash = ? WHERE id = ?", (password_hash, req.admin_id))
    conn.commit()
    conn.close()

    token = create_token(admin["id"], admin["email"])
    return {"status": "ok", "token": token, "email": admin["email"]}


@app.post("/auth/login")
def login(req: LoginRequest):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM admins WHERE email = ?", (req.email.strip().lower(),))
    admin = c.fetchone()
    conn.close()

    if not admin or not admin["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not bcrypt.verify(req.password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(admin["id"], admin["email"])
    return {"status": "ok", "token": token, "email": admin["email"]}


@app.post("/auth/register")
def register(req: RegisterRequest):
    email = req.email.strip().lower()
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password too short (min 6 chars)")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM admins WHERE email = ?", (email,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = bcrypt.hash(req.password)
    c.execute(
        "INSERT INTO admins (email, password_hash, created_at) VALUES (?, ?, ?)",
        (email, password_hash, datetime.now().isoformat())
    )
    conn.commit()
    new_id = c.lastrowid
    conn.close()

    token = create_token(new_id, email)
    return {"status": "ok", "token": token, "email": email}


@app.post("/auth/forgot-password")
def forgot_password(req: ForgotPasswordRequest):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM admins WHERE email = ?", (req.email,))
    admin = c.fetchone()

    if not admin:
        conn.close()
        # ما منفضح إذا الإيميل موجود ولا لأ (أمان)
        return {"status": "ok", "message": "If this email exists, a code was sent."}

    code = f"{secrets.randbelow(1000000):06d}"
    expires_at = (datetime.now() + timedelta(minutes=10)).isoformat()
    c.execute(
        "INSERT INTO password_resets (admin_id, code, expires_at) VALUES (?, ?, ?)",
        (admin["id"], code, expires_at)
    )
    conn.commit()
    conn.close()

    try:
        send_email(
            req.email,
            "رمز استعادة كلمة المرور / Password Reset Code",
            f"رمز التحقق الخاص فيك هو: {code}\nصالح لمدة 10 دقائق.\n\nYour verification code is: {code}\nValid for 10 minutes."
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {e}")

    return {"status": "ok", "message": "If this email exists, a code was sent."}


@app.post("/auth/reset-password")
def reset_password(req: ResetPasswordRequest):
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password too short (min 6 chars)")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM admins WHERE email = ?", (req.email,))
    admin = c.fetchone()
    if not admin:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid code")

    c.execute(
        "SELECT * FROM password_resets WHERE admin_id = ? AND code = ? AND used = 0 ORDER BY id DESC LIMIT 1",
        (admin["id"], req.code)
    )
    reset_row = c.fetchone()

    if not reset_row:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid code")

    if datetime.fromisoformat(reset_row["expires_at"]) < datetime.now():
        conn.close()
        raise HTTPException(status_code=400, detail="Code expired")

    password_hash = bcrypt.hash(req.new_password)
    c.execute("UPDATE admins SET password_hash = ? WHERE id = ?", (password_hash, admin["id"]))
    c.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (reset_row["id"],))
    conn.commit()
    conn.close()

    return {"status": "ok", "message": "Password updated"}


# ==================== إدارة البطاقات (يحتاج تسجيل دخول) ====================

@app.get("/cards")
def list_cards(admin=Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM cards ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


@app.post("/cards")
def create_card(req: CardCreateRequest, admin=Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute(
            """INSERT INTO cards (uid, person_name, status, card_type, valid_from, valid_to, is_emergency, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (req.uid, req.person_name, req.status, req.card_type, req.valid_from, req.valid_to,
             int(req.is_emergency), datetime.now().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Card UID already exists")
    new_id = c.lastrowid
    conn.close()
    return {"status": "ok", "id": new_id}


@app.put("/cards/{card_id}")
def update_card(card_id: int, req: CardUpdateRequest, admin=Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM cards WHERE id = ?", (card_id,))
    card = c.fetchone()
    if not card:
        conn.close()
        raise HTTPException(status_code=404, detail="Card not found")

    updates = req.dict(exclude_unset=True)
    if updates:
        fields = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [card_id]
        c.execute(f"UPDATE cards SET {fields} WHERE id = ?", values)
        conn.commit()
    conn.close()
    return {"status": "ok"}


@app.delete("/cards/{card_id}")
def delete_card(card_id: int, admin=Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM cards WHERE id = ?", (card_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}


# ==================== السجل (Logs) ====================

@app.get("/logs")
def list_logs(limit: int = 100, admin=Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# ==================== فتح الباب عن بعد ====================

@app.post("/door/open")
def request_door_open(admin=Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE door_commands SET pending = 1, requested_at = ? WHERE id = 1",
              (datetime.now().isoformat(),))
    conn.commit()
    conn.close()

    settings = get_notification_settings()
    if settings.get("notify_on_door_open"):
        create_notification(
            "door_open",
            "تم فتح الباب عن بعد", "Door Opened Remotely",
            f"قام {admin.get('email', 'الأدمن')} بفتح الباب عن بعد من الداشبورد",
            f"{admin.get('email', 'Admin')} opened the door remotely from the dashboard",
            should_email=True
        )
    return {"status": "ok", "message": "Door open command queued"}


# ==================== نقاط اتصال جهاز ESP32 ====================

@app.post("/device/scan")
def device_scan(req: ScanRequest, ok=Depends(verify_device_key)):
    """الـ ESP32 يستدعي هاد الإندبوينت كل مرة تنمسح بطاقة."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM cards WHERE uid = ?", (req.uid,))
    card = c.fetchone()

    now = datetime.now()

    if not card:
        c.execute(
            "INSERT INTO logs (card_uid, person_name, event_type, granted, reason, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (req.uid, "Unknown", "denied", 0, "card_not_registered", now.isoformat())
        )
        conn.commit()
        conn.close()
        settings = get_notification_settings()
        if settings.get("notify_on_denied"):
            create_notification(
                "access_denied",
                "محاولة دخول مرفوضة", "Access Attempt Denied",
                f"بطاقة غير مسجّلة حاولت الدخول (UID: {req.uid})",
                f"An unregistered card attempted to enter (UID: {req.uid})",
                should_email=True
            )
        return {"granted": False, "reason": "card_not_registered", "open_door": False}

    if card["status"] != "allowed":
        c.execute(
            "INSERT INTO logs (card_uid, person_name, event_type, granted, reason, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (req.uid, card["person_name"], "denied", 0, "access_denied", now.isoformat())
        )
        conn.commit()
        conn.close()
        settings = get_notification_settings()
        if settings.get("notify_on_denied"):
            create_notification(
                "access_denied",
                "محاولة دخول مرفوضة", "Access Attempt Denied",
                f"{card['person_name']} حاول الدخول وهو ممنوع",
                f"{card['person_name']} attempted to enter but is denied access",
                should_email=True
            )
        return {"granted": False, "reason": "access_denied", "open_door": False}

    if card["card_type"] == "temporary":
        valid_from = datetime.fromisoformat(card["valid_from"]) if card["valid_from"] else None
        valid_to = datetime.fromisoformat(card["valid_to"]) if card["valid_to"] else None
        if (valid_from and now < valid_from) or (valid_to and now > valid_to):
            c.execute(
                "INSERT INTO logs (card_uid, person_name, event_type, granted, reason, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (req.uid, card["person_name"], "denied", 0, "outside_time_window", now.isoformat())
            )
            conn.commit()
            conn.close()
            settings = get_notification_settings()
            if settings.get("notify_on_denied"):
                create_notification(
                    "access_denied",
                    "محاولة دخول خارج الوقت المسموح", "Access Attempt Outside Allowed Time",
                    f"{card['person_name']} حاول الدخول ببطاقة مؤقتة خارج وقتها المسموح",
                    f"{card['person_name']} attempted entry with a temporary card outside its allowed time window",
                    should_email=True
                )
            return {"granted": False, "reason": "outside_time_window", "open_door": False}

    # تحديد دخول/خروج بالتبادل (آخر حركة لنفس البطاقة)
    c.execute(
        "SELECT event_type FROM logs WHERE card_uid = ? AND granted = 1 ORDER BY id DESC LIMIT 1",
        (req.uid,)
    )
    last = c.fetchone()
    event_type = "exit" if (last and last["event_type"] == "entry") else "entry"

    c.execute(
        "INSERT INTO logs (card_uid, person_name, event_type, granted, reason, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        (req.uid, card["person_name"], event_type, 1, None, now.isoformat())
    )
    conn.commit()
    conn.close()

    return {"granted": True, "person_name": card["person_name"], "event_type": event_type, "open_door": True}


@app.get("/device/poll")
def device_poll(ok=Depends(verify_device_key)):
    """الـ ESP32 يسأل هاد كل كم ثانية: في أمر فتح باب عن بعد؟"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT pending FROM door_commands WHERE id = 1")
    row = c.fetchone()
    pending = bool(row["pending"]) if row else False

    if pending:
        c.execute("UPDATE door_commands SET pending = 0 WHERE id = 1")
        conn.commit()

    conn.close()
    return {"open_door": pending}


@app.get("/device/emergency-list")
def device_emergency_list(ok=Depends(verify_device_key)):
    """
    الـ ESP32 يستدعي هاد بشكل دوري (كل ما يكون النت شغّال) عشان يحمّل
    ويخزّن محلياً قائمة بطاقات الطوارئ يلي لازم تشتغل حتى لو انقطع النت.
    منقتصر القائمة على البطاقات الدائمة المسموحة والمعلّمة is_emergency=1،
    لأنو الجهاز أوفلاين ما فيه يتحقق من نافذة وقت البطاقات المؤقتة بدقة.
    """
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT uid, person_name FROM cards WHERE is_emergency = 1 AND status = 'allowed' AND card_type = 'permanent'"
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"cards": rows}


@app.post("/device/offline-log")
def device_offline_log(req: OfflineLogSyncRequest, ok=Depends(verify_device_key)):
    """
    الـ ESP32 يستدعي هاد لما يرجع النت، وبيبعت كل الحركات يلي صارت
    وهو أوفلاين (بطاقات طوارئ استخدمت بدون اتصال) عشان تنسجل بالسجل المركزي.
    """
    conn = get_db()
    c = conn.cursor()
    for entry in req.entries:
        c.execute(
            """INSERT INTO logs (card_uid, person_name, event_type, granted, reason, offline, timestamp)
               VALUES (?, ?, ?, 1, 'emergency_offline', 1, ?)""",
            (entry.uid, entry.person_name, entry.event_type, entry.timestamp)
        )
    conn.commit()
    conn.close()

    if req.entries:
        settings = get_notification_settings()
        if settings.get("notify_on_emergency"):
            names = "، ".join(sorted(set(e.person_name for e in req.entries)))
            create_notification(
                "emergency_sync",
                "دخول طوارئ أثناء انقطاع النت", "Emergency Access While Offline",
                f"تم استخدام بطاقة/بطاقات طوارئ وقت انقطاع النت: {names} ({len(req.entries)} حركة)",
                f"Emergency card(s) used while offline: {names} ({len(req.entries)} events)",
                should_email=True
            )

    return {"status": "ok", "synced": len(req.entries)}


# ==================== الإشعارات (للداشبورد) ====================

@app.get("/notifications")
def list_notifications(limit: int = 50, admin=Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


@app.get("/notifications/unread-count")
def unread_notifications_count(admin=Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as cnt FROM notifications WHERE is_read = 0")
    count = c.fetchone()["cnt"]
    conn.close()
    return {"unread": count}


@app.put("/notifications/{notification_id}/read")
def mark_notification_read(notification_id: int, admin=Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (notification_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.put("/notifications/read-all")
def mark_all_notifications_read(admin=Depends(get_current_admin)):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE notifications SET is_read = 1 WHERE is_read = 0")
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/notifications/settings")
def get_notif_settings(admin=Depends(get_current_admin)):
    return get_notification_settings()


@app.put("/notifications/settings")
def update_notif_settings(req: NotificationSettingsUpdate, admin=Depends(get_current_admin)):
    updates = {k: int(v) for k, v in req.dict(exclude_unset=True).items()}
    if updates:
        conn = get_db()
        c = conn.cursor()
        fields = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values())
        c.execute(f"UPDATE notification_settings SET {fields} WHERE id = 1", values)
        conn.commit()
        conn.close()
    return get_notification_settings()


@app.get("/")
def home():
    return {"status": "RFID Access Control API is running"}
