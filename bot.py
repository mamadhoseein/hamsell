import os, logging, json, asyncio, time, random, re, math, requests, qrcode
from main import RouterOSManager
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple
from io import BytesIO

from pyrogram import Client, filters, StopPropagation
from pyrogram.errors import PeerIdInvalid, UserNotParticipant, RPCError
from pyrogram.types import (
    InlineKeyboardMarkup, InlineKeyboardButton,
    ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove,
    InputMediaPhoto, InputMediaDocument, Message
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("bot_logs.log", encoding="utf-8"), logging.StreamHandler()]
)
logger = logging.getLogger("config_seller_bot")

api_id = int(os.getenv("TG_API_ID", "TG_API_ID"))
api_hash = os.getenv("TG_API_HASH", "TG_API_HASH")
bot_token = os.getenv("TG_BOT_TOKEN", "TG_BOT_TOKEN")
MAIN_ADMIN_ID = int(os.getenv("MAIN_ADMIN_ID", "MAIN_ADMIN_ID"))
YOUR_BRAND_ID = os.getenv("YOUR_BRAND_ID", "YOUR_BRAND_ID")
SESS_DIR = os.path.abspath("./.sessions"); os.makedirs(SESS_DIR, exist_ok=True)
SESSION_NAME = "config_bot"
app = Client(SESSION_NAME, api_id=api_id, api_hash=api_hash, bot_token=bot_token, workdir=SESS_DIR)
TMP_DIR = "/dev/shm" if os.path.exists("/dev/shm") else "."
QR_DIR = os.path.join(TMP_DIR, "qr_codes")
CONF_DIR = os.path.join(TMP_DIR, "configs")
os.makedirs(QR_DIR, exist_ok=True)
os.makedirs(CONF_DIR, exist_ok=True)

ADMINS_FILE = "admins.json"
TARIFFS_FILE = "tariffs.json"
USERS_FILE = "users.json"
SETTINGS_FILE = "settings.json"
KNOWN_PEERS_FILE = "known_admins.json"
ADMIN_QUEUE_FILE = "admin_queue.json"
ORDERS_FILE = "orders.json"
PENDING_ORDERS_FILE = "pending_orders.json"
BANNED_USERS_FILE = "banned_users.json"


def _load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(default, dict) and not isinstance(data, dict):
                raise TypeError(f"File {path} is not a dictionary.")
            if isinstance(default, list) and not isinstance(data, list):
                raise TypeError(f"File {path} is not a list.")
            return data
    except Exception as e:
        logger.warning(f"Error loading {path}: {e}. Reverting to default.")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, ensure_ascii=False, indent=2)
        return default

def _save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def _load_banned_users() -> List[int]:
    return _load_json(BANNED_USERS_FILE, [])

def _save_banned_users(banned_list: List[int]):
    _save_json(BANNED_USERS_FILE, banned_list)

def is_banned(user_id: int) -> bool:
    return user_id in _load_banned_users()

def ban_user(user_id: int) -> bool:
    banned_list = _load_banned_users()
    if user_id not in banned_list:
        banned_list.append(user_id)
        _save_banned_users(banned_list)
        return True
    return False

def unban_user(user_id: int) -> bool:
    banned_list = _load_banned_users()
    if user_id in banned_list:
        banned_list.remove(user_id)
        _save_banned_users(banned_list)
        return True
    return False

class Settings:
    def __init__(self, file=SETTINGS_FILE):
        self.file = file
        self.default_settings = {
            "card_number": "",
            "download_payload": None,
            "panels": {
                "wireguard": {"username": "تنظیم نشده", "password": "تنظیم نشده", "base_url": "تنظیم نشده"},
                "mikrotik": {"host": "تنظیم نشده", "port": 8728, "user": "تنظیم نشده", "pass": "تنظیم نشده"}
            },
            "general": {
                "support_contact": "تنظیم نشده",
                "required_channels": "تنظیم نشده",
                "sub_prompt": "برای استفاده از ربات، ابتدا عضو کانال(های) ما شوید:",
                "bot_active": True,
                "purchase_active": True,
                "mikrotik_purchase_active": True,
                "wireguard_purchase_active": True,
                "openvpn_button_active": False,
                "welcome_text": "",
            },
            "purchase_info": {
                "mt_server_host": "تنظیم نشده",
                "mt_server_ip": "تنظیم نشده",
                "mt_ipsec_secret": "تنظیم نشده",
                "ovpn_file_path": "/root/client.ovpn"
            }
        }
        data = _load_json(file, {})
        for key, value in self.default_settings.items():
            if key not in data:
                data[key] = value
            elif isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    if sub_key not in data.get(key, {}):
                        data.setdefault(key, {})[sub_key] = sub_value
        _save_json(file, data)

    def _load(self):
        return _load_json(self.file, self.default_settings)

    def _save(self, data):
        _save_json(self.file, data)

    def get(self, key_path: str, default: Any = None) -> Any:
        data = self._load()
        keys = key_path.split('.')
        for key in keys:
            if isinstance(data, dict) and key in data:
                data = data[key]
            else:
                return default
        return data

    def set(self, key_path: str, value: Any):
        data = self._load()
        keys = key_path.split('.')
        d = data
        for key in keys[:-1]:
            d = d.setdefault(key, {})
        d[keys[-1]] = value
        self._save(data)

    def get_card(self) -> str: return self.get("card_number", "")
    def set_card(self, num: str): self.set("card_number", num.strip())
    def get_download(self) -> Optional[dict]: return self.get("download_payload")
    def set_download(self, payload: Optional[dict]): self.set("download_payload", payload)

settings = Settings()

class OrderManager:
    def __init__(self, file=ORDERS_FILE):
        self.file = file
        _load_json(file, [])

    def _load(self) -> List[dict]:
        return _load_json(self.file, [])

    def _save(self, data: List[dict]):
        _save_json(self.file, data)

    def add_order(self, order_id: str, user_id: int, telegram_username: Optional[str], service_username: str, service_type: str, tariff_desc: str, price: int, payment_method: str):
        orders = self._load()
        new_order = {
            "order_id": order_id,
            "user_id": user_id,
            "telegram_username": telegram_username,
            "service_username": service_username,
            "service_type": service_type,
            "tariff_desc": tariff_desc,
            "price": price,
            "payment_method": payment_method,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        orders.insert(0, new_order)
        self._save(orders)

    def get_user_orders(self, user_id: int, limit: int = 10) -> List[dict]:
        orders = self._load()
        user_orders = [order for order in orders if order.get("user_id") == user_id]
        return user_orders[:limit]

    def get_all_orders(self, limit: int = 10) -> List[dict]:
        return self._load()[:limit]

orders_db = OrderManager()

def get_req_channels():
    return [x.strip() for x in settings.get("general.required_channels", "").split(",") if x.strip()]

def get_sub_prompt():
    return settings.get("general.sub_prompt", "برای استفاده از ربات، ابتدا عضو کانال(های) ما شوید:")

def format_expire(expire):
    if isinstance(expire, datetime):
        return expire.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif isinstance(expire, str):
        return expire
    return None

class WireGuardPanel:
    def __init__(self, base_url: str):
        self.session = requests.Session()
        self.base_url = base_url.rstrip("/")

    def send_request(self, method: str, url: str, headers=None, data=None, **kwargs):
        resp = self.session.request(method, url, headers=headers, data=data, timeout=30, **kwargs)
        resp.raise_for_status()
        return resp

    def login(self, username: str, password: str) -> bool:
        url = f"{self.base_url}/api/auth/login"
        payload = {"username": username, "password": password}
        self.session.headers.update({
            "Content-Type": "application/json", "Accept": "*/*", "User-Agent": "Mozilla/5.0",
            "Origin": self.base_url, "Referer": f"{self.base_url}/Login?ReturnUrl=%2F",
        })
        
        try:
            resp = self.send_request("POST", url, data=json.dumps(payload))
            if resp.status_code == 200 and 'Set-Cookie' in resp.headers:
                set_cookie_header = resp.headers["Set-Cookie"]
                authentication_cookie = set_cookie_header.split(";")[0]
                self.session.headers.update({"Cookie": authentication_cookie})
                return True
            else:
                logger.warning(f"Login request returned status {resp.status_code} but no 'Set-Cookie' header. Check credentials.")
                return False
        except Exception as e:
            logger.error(f"Login request failed critically: {e}")
            return False

    def get_interface(self):
        return "wireguard1"

    def create_user(self, name: str, expire=None, traffic=None) -> bool:
        url = f"{self.base_url}/api/users"
        interface = self.get_interface()
        payload = {
            "name": name, "password": "", "interface": interface,
            "privateKey": "auto", "publicKey": "", "presharedKey": "",
            "inheritIP": True, "IPAddress": None, "allowedAddress": None,
            "inheritAllowedAddress": True, "allowedIPs": None, "endpointAddress": "",
            "endpointPort": None, "keepalive": None, "inheritDNS": False, "dnsAddress": "8.8.8.8, 8.8.4.4",
            "expire": format_expire(expire),
            "traffic": int(traffic) if traffic else 0,
            "enabled": True
        }
        resp = self.send_request("POST", url, data=json.dumps(payload))
        try:
            data = resp.json()
            return data.get("background") == "success"
        except (json.JSONDecodeError, AttributeError):
            return False

    def get_user_id_by_name(self, name: str) -> Optional[str]:
        url = f"{self.base_url}/api/users"
        try:
            resp = self.send_request("GET", url)
            users = resp.json()
            for user in users:
                if user.get("name") == name:
                    return user.get("id")
        except Exception as e:
            logger.error(f"Could not get user ID for '{name}': {e}")
        return None

    def get_user_config(self, user_id: str) -> Optional[str]:
        url = f"{self.base_url}/api/users/file/{user_id}"
        try:
            resp = self.send_request("GET", url)
            if resp.text and "[Interface]" in resp.text:
                return resp.text
        except Exception as e:
            logger.error(f"Could not get config for user ID '{user_id}': {e}")
        return None

    def update_user(self, user_id: str, expire=None, traffic=None) -> bool:
        url = f"{self.base_url}/api/users/{user_id}"
        try:
            get_resp = self.send_request("GET", url)
            payload = get_resp.json()
        except Exception as e:
            logger.error(f"Failed to get user data for {user_id} before updating: {e}")
            return False

        if expire:
            payload['expire'] = format_expire(expire)
        
        if traffic is not None:
            payload['traffic'] = int(traffic) if traffic >= 0 else 0
        
        for key in ['received', 'sent', 'created', 'updated']:
            payload.pop(key, None)

        try:
            resp = self.send_request("PUT", url, data=json.dumps(payload))
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Failed to update user {user_id}: {e}")
            return False

    def get_user_details(self, username: str) -> Optional[dict]:
        user_id = self.get_user_id_by_name(username)
        if not user_id:
            return None
            
        url = f"{self.base_url}/api/users/{user_id}"
        try:
            resp = self.send_request("GET", url)
            data = resp.json()
            
            expires_in_days = "N/A"
            if data.get('expire'):
                try:
                    expire_dt = datetime.fromisoformat(data['expire'].replace("Z", "+00:00"))
                    remaining = expire_dt - datetime.now(timezone.utc)
                    expires_in_days = max(0, remaining.days)
                except:
                    pass

            return {
                'name': data.get('name'),
                'total_used_bytes': int(data.get('sent', 0)) + int(data.get('received', 0)),
                'total_limit_bytes': int(data.get('traffic', 0)) * 1024 * 1024 * 1024,
                'expires_in_days': expires_in_days,
            }
        except Exception as e:
            logger.error(f"Could not get details for WG user '{username}': {e}")
            return None

wg_panel = None
_ROUTER = None

def initialize_wg_panel():
    global wg_panel
    wg_panel = None
    try:
        base_url = settings.get("panels.wireguard.base_url")
        username = settings.get("panels.wireguard.username")
        password = settings.get("panels.wireguard.password")
        if not all([base_url, username, password]) or "تنظیم نشده" in [base_url, username, password]:
            logger.warning("WireGuard panel credentials are not fully set in settings.")
            return

        logger.info("Initializing WireGuard Panel...")
        panel = WireGuardPanel(base_url=base_url)
        if panel.login(username=username, password=password):
            wg_panel = panel
            logger.info("Successfully logged into WireGuard Panel.")
        else:
            logger.error("Failed to log into WireGuard Panel. Check credentials in bot settings.")
    except Exception as e:
        logger.error(f"Error initializing WireGuard Panel: {e}")

def initialize_router():
    global _ROUTER
    _ROUTER = None
    try:
        host = settings.get("panels.mikrotik.host")
        port = int(settings.get("panels.mikrotik.port", 8728))
        user = settings.get("panels.mikrotik.user")
        password = settings.get("panels.mikrotik.pass")

        if not all([host, user, password]) or host == "تنظیم نشده":
            logger.warning("اطلاعات اتصال به میکروتیک در تنظیمات ربات کامل نیست.")
            return

        logger.info("در حال مقداردهی اولیه مدیر روتر...")
        _ROUTER = RouterOSManager(host=host, port=port, username=user, password=password)
        if _ROUTER._connect():
            logger.info("اتصال به میکروتیک با موفقیت برقرار شد.")
        else:
            logger.error("اتصال به میکروتیک ناموفق بود. اطلاعات را بررسی کنید.")
            _ROUTER = None
    except Exception as e:
        logger.error(f"خطا در هنگام مقداردهی اولیه مدیر روتر: {e}")
        _ROUTER = None

initialize_wg_panel()
initialize_router()

def get_router():
    global _ROUTER
    if _ROUTER is None:
        initialize_router()
    return _ROUTER

_save_json(ADMINS_FILE, _load_json(ADMINS_FILE, [MAIN_ADMIN_ID]))

def _load_admins() -> List[int]:
    lst = _load_json(ADMINS_FILE, [MAIN_ADMIN_ID])
    if MAIN_ADMIN_ID not in lst:
        lst = [MAIN_ADMIN_ID] + [x for x in lst if x != MAIN_ADMIN_ID]
        _save_json(ADMINS_FILE, lst)
    return lst
admins: List[int] = _load_admins()
def is_admin(uid:int)->bool: return uid in admins

def get_welcome_text() -> str:
    default_text = (
        "سلام، خوش آمدید 👋\n\n"
        "در این ربات می‌توانید اکانت‌های WireGuard و MikroTik خریداری و دریافت کنید.\n"
        "از منوی زیر انتخاب کنید:"
    )
    base_text = settings.get("general.welcome_text") or default_text
    channels = get_req_channels()
    
    if channels:
        channels_str = ", ".join(ch for ch in channels if ch)
        return f"{base_text}\n\nکانال ما: {channels_str}"
    return f"{base_text}"

async def run_blocking(func, /, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

known_peers: List[int] = _load_json(KNOWN_PEERS_FILE, [MAIN_ADMIN_ID])
admin_queue: Dict[str, List[dict]] = _load_json(ADMIN_QUEUE_FILE, {})

def _queue_admin_msg(admin_id: int, payload: dict):
    key = str(admin_id)
    q = admin_queue.get(key, [])
    q.append(payload)
    admin_queue[key] = q
    _save_json(ADMIN_QUEUE_FILE, admin_queue)

async def _flush_admin_queue_for(aid: int):
    key = str(aid)
    jobs = admin_queue.get(key, [])
    if not jobs: return
    for job in jobs:
        kind = job.get("kind")
        try:
            if kind == "text": await app.send_message(aid, job.get("text", ""))
            elif kind == "photo": await app.send_photo(aid, job.get("file_id"), caption=job.get("caption",""))
            elif kind == "document": await app.send_document(aid, job.get("file_id"), caption=job.get("caption",""))
        except Exception as e: logger.error(f"flush send failed for admin {aid}: {e}")
    admin_queue[key] = []
    _save_json(ADMIN_QUEUE_FILE, admin_queue)

async def safe_send_to_admins(method: str, *args, caption: str = "", reply_markup=None, **kwargs):
    for aid in admins:
        try:
            if method == "message": await app.send_message(aid, caption, reply_markup=reply_markup)
            elif method == "photo": await app.send_photo(aid, *args, caption=caption, reply_markup=reply_markup)
            elif method == "document": await app.send_document(aid, *args, caption=caption, reply_markup=reply_markup)
        except PeerIdInvalid:
            _queue_admin_msg(aid, {"kind": "text" if method=="message" else method, "file_id": args[0] if args else None, "caption": caption, "text": caption})
        except Exception as e: logger.warning(f"send to admin failed: {e}")

class UsersDB:
    def __init__(self, file=USERS_FILE):
        self.file=file
        _load_json(file, {})
    def _load(self)->Dict[str, Any]:
        return _load_json(self.file, {})
    def _save(self, data:Dict[str,Any]):
        _save_json(self.file, data)
    def register(self, uid:int, username:str=None, full_name:str=None):
        data=self._load()
        key=str(uid)
        now=datetime.now(timezone.utc).isoformat()
        if key not in data:
            data[key]={"first_seen": now, "last_seen": now, "username": username, "name": full_name, "starts": 1, "has_purchased": False}
        else:
            data[key]["last_seen"]=now
            data[key]["starts"]=int(data[key].get("starts",0))+1
            if username is not None: data[key]["username"]=username
            if full_name is not None: data[key]["name"]=full_name
        self._save(data)
    def set_has_purchased(self, uid: int, status: bool):
        data = self._load()
        key = str(uid)
        if key in data:
            data[key]["has_purchased"] = status
            self._save(data)
    def has_purchased(self, uid: int) -> bool:
        data = self._load()
        return bool(data.get(str(uid), {}).get("has_purchased", False))
    def count(self)->int: return len(self._load())
    def get_user_data(self, uid: int) -> Optional[dict]:
        user = self._load().get(str(uid))
        if user:
            user['id'] = uid
        return user
    def active_last_hours(self, hours=24)->int:
        data=self._load()
        now=datetime.now(timezone.utc)
        c=0
        for row in data.values():
            try:
                dt=datetime.fromisoformat(row.get("last_seen"))
                if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
                if (now-dt)<=timedelta(hours=hours): c+=1
            except: pass
        return c
    def all_ids(self)->List[int]:
        try: return [int(uid) for uid in self._load().keys()]
        except: return []

users_db = UsersDB()

def _rand_id() -> int:
    return int(str(int(time.time()))[-6:] + f"{random.randint(10,99)}")

class TariffManager:
    def __init__(self, file=TARIFFS_FILE):
        self.file=file
        _load_json(file, [])
    def _load(self):
        rows=_load_json(self.file, [])
        changed=False
        for r in rows:
            if "group_main" not in r and "group" in r:
                r["group_main"]=r.get("group"); r.pop("group",None); changed=True
            if "group_sub" not in r: r["group_sub"]=r.get("group_sub", None)
            if "desc" not in r: r["desc"]=None
            if "id" not in r: r["id"]=_rand_id(); changed=True
        if changed: self._save(rows)
        return rows
    def _save(self, rows): _save_json(self.file, rows)
    def list_tariffs(self): return self._load()
    def set_tariff(self, ttype, profile, size_mb, shared_users, price, group_main=None, group_sub=None, desc: Optional[str]=None):
        ttype=str(ttype).lower()
        rows=self._load(); updated=False
        for r in rows:
            if (r["type"] == ttype and r["profile"] == profile and int(r["size_mb"]) == int(size_mb) and int(r["shared_users"]) == int(shared_users)):
                r.update({"price":int(price),"group_main":group_main,"group_sub":group_sub,"desc":desc, "updated_at":datetime.now(timezone.utc).isoformat()})
                if "id" not in r: r["id"]=_rand_id()
                updated=True; break
        if not updated:
            rows.append({"id":_rand_id(),"type":ttype,"profile":profile,"size_mb":int(size_mb),"shared_users":int(shared_users), "price":int(price),"group_main":group_main,"group_sub":group_sub,"desc":desc, "updated_at":datetime.now(timezone.utc).isoformat()})
        
        self._save(rows)
        return True

    def del_by_id(self, tid: int) -> bool:
        rows=self._load()
        new_rows=[r for r in rows if int(r.get("id",-1))!=int(tid)]
        self._save(new_rows)
        return len(new_rows)!=len(rows)
    def by_id(self, tid:int)->Optional[dict]:
        for r in self._load():
            if int(r.get("id",-1))==int(tid): return r
        return None

tariffs=TariffManager()

def normalize_persian_numerals(text: str) -> str:
    if not isinstance(text, str):
        return text
    persian_to_ascii = str.maketrans('۰۱۲۳۴۵۶۷۸۹', '0123456789')
    return text.translate(persian_to_ascii)

def numeric_str(n:int)->str:
    if n<=0: return "1"
    return str(random.randint(1,9)) + "".join(str(random.randint(0,9)) for _ in range(n-1))
def new_username_numeric()->str: return numeric_str(9)
def new_password_numeric()->str: return "".join(str(random.randint(0,9)) for _ in range(random.randint(6,8)))

def format_toman(x: float|int) -> str:
    try: amt = int(float(x))
    except: return f"{x} تومان"
    return f"{amt:,} تومان"

def human_gb(size_mb: int) -> str:
    if not size_mb or int(size_mb) == 0: return "نامحدود"
    gb = int(size_mb) // 1024
    return f"{gb}GB"

def bytes_to_human(byte_count: int) -> str:
    if byte_count is None: return "N/A"
    try:
        byte_count = int(byte_count)
    except (ValueError, TypeError):
        return "N/A"
    if byte_count == 0: return "0 B"
    gb = byte_count / (1024 ** 3)
    if gb < 1:
        mb = byte_count / (1024 ** 2)
        return f"{mb:.2f} MB"
    return f"{gb:.2f} GB"


def build_rows(pairs, cols=2):
    out=[]; row=[]
    for lbl, cb in pairs:
        row.append(InlineKeyboardButton(lbl, callback_data=cb))
        if len(row)==cols: out.append(row); row=[]
    if row: out.append(row)
    return out
def make_menu(*sections):
    kb=[]
    for pairs, cols in sections:
        kb += build_rows(pairs, cols)
    return InlineKeyboardMarkup(kb)

def _pretty_tariff_card(t: dict) -> str:
    ttype = "MikroTik" if t["type"] == "mikrotik" else "WireGuard"
    profile = t.get("profile", "")
    size_txt = human_gb(t.get("size_mb") or 0)
    su_txt = str(t.get("shared_users", 1))
    price_txt = format_toman(t.get('price',0))
    gm = t.get("group_main"); gs = t.get("group_sub")
    group_txt = (f"{gm}/{gs}" if gm and gs else gm or "—")
    tid = t.get("id","-")
    desc = t.get("desc")

    if desc:
        days = desc
    elif isinstance(profile, str) and profile.lower().endswith("day"):
        try: days = f"{int(profile[:-3])} روزه"
        except: days = profile
    else:
        days = profile

    return "\n".join([
        f"📦 کُد: {tid}", f"📡 سرویس: {ttype}", f"⏳ شرح: {days}",
        f"💾 حجم: {size_txt}", f"👥 کاربران همزمان: {su_txt}",
        f"🏷 گروه: {group_txt}", f"💵 قیمت: {price_txt}",
    ]) + "\n"

def _render_invoice(t:dict, card_number:str, inv_id:str)->str:
    ttype = "MikroTik" if t["type"]=="mikrotik" else "WireGuard"
    prof = t.get("desc") or t.get("profile","")
    size_txt = human_gb(t.get("size_mb") or 0)
    su_txt = str(t.get("shared_users",1))
    price_txt = format_toman(t.get('price',0))
    card_disp = card_number if card_number else "— (ثبت نشده)"
    return "\n".join([
        f"🧾 فاکتور #{inv_id}", f"📡 سرویس: {ttype}",
        f"⏳ پلن: {prof}", f"💾 حجم: {size_txt} | 👥 کاربران: {su_txt}",
        f"💵 مبلغ قابل پرداخت: {price_txt}", f"💳 شماره کارت: {card_disp}",
        "لطفاً پس از واریز، رسید را ارسال کنید.",
    ])

def _render_purchase_report(t:dict, inv_id:str, method:str)->str:
    ttype = "MikroTik" if t["type"]=="mikrotik" else "WireGuard"
    prof = t.get("desc") or t.get("profile","")
    price_txt = format_toman(t.get("price",0))
    size_txt = human_gb(t.get("size_mb") or 0)
    su_txt = str(t.get("shared_users",1))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "🎉 خرید شما ثبت شد", f"🧾 شناسه فاکتور: {inv_id}", f"🕒 زمان: {ts}",
        f"📡 سرویس: {ttype}", f"⏳ پلن: {prof}",
        f"💾 حجم: {size_txt} | 👥 کاربران: {su_txt}", f"💳 روش پرداخت: {method}",
        f"💵 مبلغ: {price_txt}",
    ]
    return "\n".join(lines)


async def send_purchase_report(uid:int, user_info: dict, t:dict, inv_id:str, method:str):
    rep = _render_purchase_report(t, inv_id, method)
    
    kb = make_menu(
        ([("📋 کپی شناسه فاکتور", f"copy_inv_{inv_id}")],1),
        ([("🔙 بازگشت","u_back_home_user")],1)
    )
    await app.send_message(uid, rep, reply_markup=kb)
    
    service_username = LAST_CREDS.get(uid, {}).get("u", "نامشخص")

    orders_db.add_order(
        order_id=inv_id, user_id=uid, telegram_username=user_info.get("username"),
        service_username=service_username,
        service_type=t['type'],
        tariff_desc=t.get('desc', t.get('profile')),
        price=t['price'],
        payment_method=method
    )

USER_BTN_BUY = "🛒 خرید سرویس"
USER_BTN_MY_SERVICES = "👤 سرویس‌های من"
USER_BTN_TARIFFS = "📋 لیست تعرفه‌ها"
USER_BTN_GUIDE = "💡 راهنمای اتصال"
USER_BTN_ORDERS = "🛍️ سفارشات من"
USER_BTN_SUPPORT = "💬 پشتیبانی آنلاین"

ADMIN_BTN_TARIFFS = "📄 مدیریت تعرفه‌ها"
ADMIN_BTN_STATS = "📊 آمار ربات"
ADMIN_BTN_GUIDE = "🔗 راهنمای اتصال"
ADMIN_BTN_CARD = "💳 تنظیم شماره کارت"
ADMIN_BTN_ORDERS = "🛍️ لیست سفارشات"
ADMIN_BTN_SETTINGS = "⚙️ تنظیمات ربات"


def user_main_reply_keyboard(user_id: int) -> ReplyKeyboardMarkup:
    keyboard = []
    
    row1 = []
    if settings.get("general.purchase_active", True):
        row1.append(KeyboardButton(USER_BTN_BUY))
        
    if row1:
        keyboard.append(row1)

    keyboard.extend([
        [KeyboardButton(USER_BTN_MY_SERVICES), KeyboardButton(USER_BTN_TARIFFS)],
        [KeyboardButton(USER_BTN_ORDERS), KeyboardButton(USER_BTN_GUIDE)],
        [KeyboardButton(USER_BTN_SUPPORT)],
    ])

    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


def admin_main_reply_keyboard() -> ReplyKeyboardMarkup:
    keyboard = [
        [KeyboardButton(ADMIN_BTN_TARIFFS), KeyboardButton(ADMIN_BTN_ORDERS)],
        [KeyboardButton(ADMIN_BTN_GUIDE), KeyboardButton(ADMIN_BTN_CARD)],
        [KeyboardButton(ADMIN_BTN_SETTINGS), KeyboardButton(ADMIN_BTN_STATS)],
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

def back_menu_user(): return make_menu(([("🔙 بازگشت", "u_back_home_user")],1))
def back_menu_admin(): return make_menu(([("🔙 بازگشت", "back_home")],1))

def render_mikrotik_server_info() -> str:
    return (
        "🔧 تنظیمات اتصال L2TP/SSTP/PPTP\n"
        f"🌐 Server (DNS): `{settings.get('purchase_info.mt_server_host', 'N/A')}`\n"
        f"📍 IP (در صورت نیاز): `{settings.get('purchase_info.mt_server_ip', 'N/A')}`\n"
        f"🔐 IPSec Secret: `{settings.get('purchase_info.mt_ipsec_secret', 'N/A')}`\n"
        "ℹ️ اگر دستگاه‌تان نام دامنه را پشتیبانی نمی‌کند، از IP استفاده کنید."
    )

def server_info_kb():
    return make_menu(
        ([("📋 کپی Server", "copy_host"), ("📋 کپی IP", "copy_ip")], 2),
        ([("📋 کپی IPSec", "copy_ipsec")], 1),
        ([("🔙 بازگشت","u_back_home_user")], 1)
    )

def valid_username(s: str) -> bool:
    if not s: return False
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{3,16}", s or ""))

def valid_password(s: str) -> bool:
    if not s: return False
    return bool(re.fullmatch(r"[A-Za-z0-9]{5,20}", s or ""))


async def smart_edit(msg, text: str, reply_markup=None):
    try:
        if getattr(msg, "media", None): await msg.edit_caption(caption=text, reply_markup=reply_markup)
        else: await msg.edit_text(text, reply_markup=reply_markup)
    except Exception:
        try: await app.send_message(msg.chat.id, text, reply_markup=reply_markup)
        except Exception as e: logger.error(f"Smart_edit fallback failed: {e}")

async def smart_replace_media(c, msg, kind: str, file_id: str, caption: str = "", reply_markup=None):
    try:
        media = InputMediaPhoto(media=file_id, caption=caption) if kind=="photo" else InputMediaDocument(media=file_id, caption=caption)
        await msg.edit_media(media=media, reply_markup=reply_markup)
    except Exception:
        try: await c.delete_messages(chat_id=msg.chat.id, message_ids=[msg.id])
        except Exception: pass
        if kind=="photo": await c.send_photo(chat_id=msg.chat.id, photo=file_id, caption=caption, reply_markup=reply_markup)
        else: await c.send_document(chat_id=msg.chat.id, document=file_id, caption=caption, reply_markup=reply_markup)

def _channel_button_title(ch: str) -> str:
    if ch.startswith("http"): return "عضویت / Join"
    if ch.startswith("@"):    return f"عضویت در {ch}"
    return "عضویت / Join"

def _channel_button_url(ch: str) -> str:
    if ch.startswith("http"): return ch
    if ch.startswith("@"):    return f"https://t.me/{ch[1:]}"
    logger.warning(f"Invalid channel format in settings: {ch}. Using fallback URL.")
    return "https://telegram.org"

def sub_keyboard():
    rows = [[InlineKeyboardButton(_channel_button_title(ch), url=_channel_button_url(ch))] for ch in get_req_channels()]
    rows.append([InlineKeyboardButton("🔁 بررسی عضویت", callback_data="recheck_subs")])
    return InlineKeyboardMarkup(rows)

async def is_all_subscribed(user_id: int) -> bool:
    req_channels = get_req_channels()
    if not req_channels: return True
    for ch in req_channels:
        if ch.startswith("http"): continue
        try:
            member = await app.get_chat_member(ch, user_id)
            if str(getattr(member, "status", "left")).lower() in ("left", "kicked"): return False
        except UserNotParticipant: return False
        except RPCError as e:
            if "CHAT_ADMIN_REQUIRED" in str(e):
                try: await app.send_message(MAIN_ADMIN_ID, f"⚠️ ربات در کانال {ch} ادمین نیست.")
                except: pass
            logger.warning(f"sub check failed for {user_id} in {ch}: {e}")
            return False
        except Exception as e:
            logger.warning(f"sub check unknown error for {user_id} in {ch}: {e}")
            return False
    return True

async def enforce_subscription(c, user_id: int, msg=None, cq=None):
    if is_admin(user_id) or await is_all_subscribed(user_id):
        return True

    text = f"🛑 {get_sub_prompt()}"
    kb = sub_keyboard()
    if cq:
        await cq.answer()
        try: await smart_edit(cq.message, text, reply_markup=kb)
        except: await c.send_message(user_id, text, reply_markup=kb)
    elif msg:
        await msg.reply(text, reply_markup=kb)

    logger.info(f"[GATE] user={user_id} not subscribed; prompt sent.")
    raise StopPropagation

def _group_sizes(ttype: str, rows: List[dict]) -> List[int]:
    sizes = sorted({int(r.get("size_mb",0)) for r in rows if r.get("type")==ttype})
    return sizes

def _size_buttons(ttype: str, sizes: List[int]) -> List[Tuple[str,str]]:
    tag = "wg" if ttype=="wireguard" else "mt"
    btns=[]
    for mb in sizes:
        label = "نامحدود" if int(mb)==0 else human_gb(int(mb))
        cb = f"sz_{tag}_{'U' if int(mb)==0 else int(mb)}"
        btns.append((label, cb))
    return btns

def _tariffs_by_size(ttype: str, size_mb: int, rows: List[dict]) -> List[dict]:
    return [r for r in rows if r.get("type")==ttype and int(r.get("size_mb",0))==int(size_mb)]

user_data: Dict[int, Dict[str, Any]] = {}
PENDING_ORDERS: Dict[str, Dict[str, Any]] = _load_json(PENDING_ORDERS_FILE, {})
LAST_CREDS: Dict[int, Dict[str,str]] = {}

@app.on_message(filters.command("ping") & filters.private, group=-1)
async def ping_admin(c, m):
    if not is_admin(m.from_user.id): return
    await m.reply("pong ✅")

@app.on_message(filters.command("start") & filters.private, group=-1)
async def start_always(c, m):
    uid = m.from_user.id
    if is_banned(uid):
        await m.reply("⛔️ شما توسط مدیر از استفاده از این ربات منع شده‌اید.")
        return

    user_data.pop(uid, None)
    
    users_db.register(
        uid,
        username=(m.from_user.username or None),
        full_name=(f"{m.from_user.first_name or ''} {m.from_user.last_name or ''}".strip() or None)
    )
    if uid not in known_peers:
        known_peers.append(uid)
        _save_json(KNOWN_PEERS_FILE, known_peers)

    if not is_admin(uid) and not settings.get("general.bot_active", True):
        await m.reply("🤖 ربات در حال حاضر برای تعمیرات خاموش است. لطفاً بعداً دوباره امتحان کنید.")
        return

    if is_admin(uid):
        await _flush_admin_queue_for(uid)
        admin_start_text = "سلام. به پنل مدیریت خوش آمدید."
        await m.reply(admin_start_text, reply_markup=admin_main_reply_keyboard())
    else:
        await m.reply(get_welcome_text(), reply_markup=user_main_reply_keyboard(uid))

@app.on_message(filters.private, group=-2)
async def _gate_private_messages(c, m):
    uid = m.from_user.id
    if is_banned(uid):
        raise StopPropagation

    if not is_admin(uid) and not settings.get("general.bot_active", True):
        await m.reply("🤖 ربات در حال حاضر برای تعمیرات خاموش است. لطفاً بعداً دوباره امتحان کنید.")
        raise StopPropagation

    if m.text and m.text.startswith("/") and m.text.split()[0].lower() in ("/start", "/ping", "/subdebug"): return
    await enforce_subscription(c, uid, msg=m)

@app.on_callback_query(group=-2)
async def _gate_callbacks(c, cq):
    uid = cq.from_user.id
    if is_banned(uid):
        await cq.answer("⛔️ شما توسط مدیر مسدود شده‌اید.", show_alert=True)
        raise StopPropagation

    if not is_admin(uid) and not settings.get("general.bot_active", True):
        await cq.answer("🤖 ربات در حال حاضر برای تعمیرات خاموش است.", show_alert=True)
        raise StopPropagation
        
    if cq.data in ("recheck_subs",): return
    await enforce_subscription(c, uid, cq=cq)


@app.on_callback_query(filters.regex("^recheck_subs$"))
async def recheck_subs(c, cq):
    await cq.answer()
    if await is_all_subscribed(cq.from_user.id):
        uid = cq.from_user.id
        is_user_admin = is_admin(uid)
        
        if is_user_admin:
            text = "✅ عضویت تایید شد. به پنل مدیریت خوش آمدید."
        else:
            text = get_welcome_text()
            
        kb = admin_main_reply_keyboard() if is_user_admin else user_main_reply_keyboard(uid)
        try:
            await cq.message.delete()
        except:
            pass
        await c.send_message(uid, text, reply_markup=kb)
    else:
        await cq.answer("هنوز در تمام کانال‌ها عضو نشده‌اید.", show_alert=True)

@app.on_message(filters.command("subdebug") & filters.private)
async def subdebug(c, m):
    if not is_admin(m.from_user.id): return
    lines = [f"🔎 SubDebug for {m.from_user.id}:"]
    req_channels = get_req_channels()
    for ch in req_channels:
        if ch.startswith("http"):
            lines.append(f"• {ch} : Link (not checkable)")
            continue
        try:
            member = await app.get_chat_member(ch, m.from_user.id)
            lines.append(f"• {ch} : OK (status={str(getattr(member, 'status', 'left')).lower()})")
        except Exception as e:
            lines.append(f"• {ch} : ERROR → {e}")
    await m.reply("\n".join(lines))

@app.on_callback_query(filters.regex("^u_back_home_user$"))
async def back_home_user(c, cq):
    await cq.answer()
    uid = cq.from_user.id
    user_data.pop(uid, None)
    
    try:
        await cq.message.delete()
    except Exception:
        pass

    await c.send_message(
        chat_id=uid,
        text=get_welcome_text(),
        reply_markup=user_main_reply_keyboard(uid)
    )

@app.on_callback_query(filters.regex("^back_home$"))
async def back_home(c, cq):
    await cq.answer()
    uid = cq.from_user.id
    user_data.pop(uid, None)

    try:
        await cq.message.delete()
    except Exception:
        pass
    
    admin_start_text = "سلام. به پنل مدیریت خوش آمدید."

    await c.send_message(
        chat_id=uid,
        text=admin_start_text,
        reply_markup=admin_main_reply_keyboard()
    )

@app.on_callback_query(filters.regex("^u_support$"))
async def u_support(c, cq):
    await cq.answer()
    support_contact = settings.get("general.support_contact", "N/A")
    kb = make_menu(([("✉️ ارسال پیام به پشتیبانی", "u_support_send")],1), ([("🔙 بازگشت", "u_back_home_user")],1))
    await smart_edit(cq.message, f"💬 پشتیبانی آنلاین\n\nبرای ارتباط سریع: {support_contact}\n\nیا پیام خود را برای مدیران ارسال کنید:", reply_markup=kb)

@app.on_callback_query(filters.regex("^u_support_send$"))
async def u_support_send(c, cq):
    await cq.answer()
    user_data[cq.from_user.id] = {"awaiting":"support_message", "prompt_message_id": cq.message.id}
    await smart_edit(cq.message, "✍️ پیام پشتیبانی‌تان را ارسال کنید.\n(برای بازگشت دکمه زیر را بزنید)", reply_markup=back_menu_user())


@app.on_callback_query(filters.regex("^u_download_file$"))
async def u_download_file(c, cq):
    await cq.answer()
    payload = settings.get_download()
    if not payload:
        await smart_edit(cq.message, "❌ راهنمای دانلود هنوز توسط ادمین تنظیم نشده.", reply_markup=back_menu_user())
        return
    kind = payload.get("kind")
    caption = payload.get("caption","")
    text = payload.get("text")
    file_id = payload.get("file_id")
    if kind == "photo":
        await smart_replace_media(c, cq.message, "photo", file_id, caption, reply_markup=back_menu_user())
    elif kind == "document":
        await smart_replace_media(c, cq.message, "document", file_id, caption, reply_markup=back_menu_user())
    else:
        await smart_edit(cq.message, text or "—", reply_markup=back_menu_user())

@app.on_message(filters.text & filters.private, group=0)
async def main_menu_router(c, m: Message):
    text = m.text
    uid = m.from_user.id

    if uid in user_data and user_data[uid].get("awaiting"):
        return

    class FakeCQ:
        def __init__(self, message_to_edit: Message, from_user_obj, button_text: str):
            self.message = message_to_edit
            self.from_user = from_user_obj
            
            callback_data_map = {
                USER_BTN_BUY: "u_buy_service_menu",
                USER_BTN_TARIFFS: "u_tariffs_menu",
            }
            self.data = callback_data_map.get(button_text, "")

        async def answer(self, *args, **kwargs):
            pass

    user_actions = {
        USER_BTN_BUY: u_service_or_tariffs_menu,
        USER_BTN_MY_SERVICES: show_my_services,
        USER_BTN_TARIFFS: u_service_or_tariffs_menu,
        USER_BTN_GUIDE: u_download_file,
        USER_BTN_ORDERS: show_my_orders,
        USER_BTN_SUPPORT: u_support,
    }

    admin_actions = {
        ADMIN_BTN_TARIFFS: admin_tariffs,
        ADMIN_BTN_STATS: admin_simple_stats,
        ADMIN_BTN_GUIDE: admin_set_download_prompt,
        ADMIN_BTN_CARD: admin_set_card,
        ADMIN_BTN_ORDERS: show_admin_orders,
        ADMIN_BTN_SETTINGS: admin_settings_main,
    }

    handler_func = None
    if is_admin(uid) and text in admin_actions:
        handler_func = admin_actions[text]
    elif not is_admin(uid) and text in user_actions:
        handler_func = user_actions[text]

    if handler_func:
        sent_message = await c.send_message(uid, "در حال بارگذاری...")
        
        fake_cq = FakeCQ(sent_message, m.from_user, text)
        
        await handler_func(c, fake_cq)
        
        raise StopPropagation

@app.on_message(filters.text & filters.private & ~filters.command(["start","ping","subdebug"]), group=1)
async def text_router(c, m: Message):
    uid=m.from_user.id
    ud = user_data.get(uid,{})
    step = ud.get("awaiting")
    if not step: return

    prompt_msg = m
    prompt_message_id = ud.get("prompt_message_id")
    if prompt_message_id:
        try: prompt_msg = await c.get_messages(m.chat.id, prompt_message_id)
        except: pass
        
    text_input = normalize_persian_numerals(m.text or "")

    if step == "check_mt_username":
        username_to_check = text_input.strip()
        await smart_edit(prompt_msg, f"⏳ در حال جستجوی سرویس User Manager با نام کاربری `{username_to_check}`...")
        
        rm = get_router()
        if not rm:
            await smart_edit(prompt_msg, "❌ خطای داخلی: سرویس میکروتیک در دسترس نیست.", reply_markup=back_menu_user())
            user_data.pop(uid, None)
            return

        details = await run_blocking(rm.get_user_details, username=username_to_check)
        
        if details:
            profile = details.get('actual-profile', 'N/A')
            
            download_used_bytes = int(details.get('total-download', 0))
            upload_used_bytes = int(details.get('total-upload', 0))
            total_used_bytes = download_used_bytes + upload_used_bytes
            
            download_used = bytes_to_human(download_used_bytes)
            upload_used = bytes_to_human(upload_used_bytes)
            total_used = bytes_to_human(total_used_bytes)
            
            uptime = details.get('total-uptime', 'N/A')
            status = "آنلاین 🟢" if int(details.get('active-sessions', 0)) > 0 else "آفلاین 🔴"

            panel_text = (
                f"✅ **اطلاعات سرویس MikroTik شما:**\n\n"
                f"👤 **نام کاربری:** `{details.get('name', 'N/A')}`\n"
                f"🚦 **وضعیت فعلی:** {status}\n"
                f"🏷️ **پروفایل فعال:** `{profile}`\n\n"
                f"**--- آمار مصرف ---**\n"
                f"📥 **حجم دانلود شده:** {download_used}\n"
                f"📤 **حجم آپلود شده:** {upload_used}\n"
                f"📊 **مجموع مصرف:** {total_used}\n\n"
                f"⏱️ **زمان کل اتصال (Uptime):** `{uptime}`"
            )
            
            kb = back_menu_user()
            
            await smart_edit(prompt_msg, panel_text, reply_markup=kb)
        else:
            await smart_edit(prompt_msg, "❌ سرویسی با این نام کاربری یافت نشد. لطفاً دوباره تلاش کنید.", reply_markup=back_menu_user())
            
        user_data.pop(uid, None)
        return

    if step == "check_wg_username":
        username_to_check = text_input.strip()
        await smart_edit(prompt_msg, f"⏳ در حال جستجوی سرویس وایرگارد با نام کاربری `{username_to_check}`...")

        if not wg_panel:
            await smart_edit(prompt_msg, "❌ خطای داخلی: سرویس وایرگارد در دسترس نیست.", reply_markup=back_menu_user())
            user_data.pop(uid, None)
            return

        details = await run_blocking(wg_panel.get_user_details, username=username_to_check)
        
        if details:
            total_used = bytes_to_human(details.get('total_used_bytes', 0))
            total_limit = bytes_to_human(details.get('total_limit_bytes', 0)) if details.get('total_limit_bytes', 0) > 0 else "نامحدود"
            expires_in = f"{details.get('expires_in_days', 'N/A')} روز"

            panel_text = (
                f"✅ **اطلاعات سرویس یافت شد:**\n\n"
                f"👤 **نام کاربری:** `{details['name']}`\n"
                f"📡 **نوع سرویس:** WireGuard\n"
                f"⏳ **اعتبار باقی‌مانده:** {expires_in}\n"
                f"📊 **حجم مصرفی:** {total_used} / {total_limit}"
            )
            
            await smart_edit(prompt_msg, panel_text, reply_markup=back_menu_user())
        else:
            await smart_edit(prompt_msg, "❌ سرویسی با این نام کاربری یافت نشد. لطفاً دوباره تلاش کنید.", reply_markup=back_menu_user())
            
        user_data.pop(uid, None)
        return

    if step=="support_message":
        txt = text_input.strip()
        inv_btn = [("✍️ پاسخ به کاربر", f"as_reply_{uid}"), ("✅ بستن", f"as_close_{uid}")]
        kb_admin = make_menu((inv_btn, 2))
        await safe_send_to_admins("message", caption=f"📩 پیام پشتیبانی از کاربر {uid} (@{m.from_user.username or '—'}):\n\n{txt}", reply_markup=kb_admin)
        await smart_edit(prompt_msg, "✅ پیام شما به پشتیبانی ارسال شد. لطفاً منتظر پاسخ بمانید.", reply_markup=back_menu_user())
        user_data.pop(uid,None); return

    if step == "ask_username":
        name = text_input.strip()
        if not valid_username(name):
            await m.reply("❌ نام نامعتبر است. فقط حروف/عدد/—/_ و ۳ تا ۱۶ کاراکتر.", reply_markup=back_menu_user(), quote=True); return
        user_data[uid]["wanted_name"] = name
        t = user_data[uid]["tariff"]; inv_id = user_data[uid]["invoice_id"]; card = settings.get_card()
        invoice = _render_invoice(t, card, inv_id) + f"\n👤 نام کاربری انتخابی: {name}"
        
        pay_btns = []
        
        pay_btns.append(("📤 ارسال رسید پرداخت", "u_send_receipt"))
        kb = make_menu((pay_btns, 1), ([("📋 کپی شماره کارت", "copy_card"), ("📋 کپی شناسه فاکتور", f"copy_inv_{inv_id}")], 2), ([("🔙 بازگشت", "u_back_home_user")], 1))
        user_data[uid]["awaiting"] = "order_pay"
        await smart_edit(prompt_msg, invoice, reply_markup=kb); return
    
    if not is_admin(uid): return

    SETTING_MAP = {
        "set_wg_url": ("panels.wireguard.base_url", "آدرس پنل وایرگارد", initialize_wg_panel),
        "set_wg_user": ("panels.wireguard.username", "یوزرنیم پنل وایرگارد", initialize_wg_panel),
        "set_wg_pass": ("panels.wireguard.password", "پسورد پنل وایرگارد", initialize_wg_panel),
        "set_ros_host": ("panels.mikrotik.host", "آدرس هاست میکروتیک", initialize_router),
        "set_ros_port": ("panels.mikrotik.port", "پورت میکروتیک", initialize_router),
        "set_ros_user": ("panels.mikrotik.user", "یوزرنیم میکروتیک", initialize_router),
        "set_ros_pass": ("panels.mikrotik.pass", "پسورد میکروتیک", initialize_router),
        "set_support_contact": ("general.support_contact", "آیدی پشتیبانی", None),
        "set_req_channels": ("general.required_channels", "کانال‌های عضویت اجباری", None),
        "set_pi_host": ("purchase_info.mt_server_host", "هاست اتصال", None),
        "set_pi_ip": ("purchase_info.mt_server_ip", "آی‌پی اتصال", None),
        "set_pi_ipsec": ("purchase_info.mt_ipsec_secret", "کد IPSec", None),
        "set_pi_ovpn": ("purchase_info.ovpn_file_path", "مسیر فایل OpenVPN", None),
    }

    if step in SETTING_MAP:
        key_path, label, reinit_func = SETTING_MAP[step]
        value = text_input.strip()
        
        if key_path.endswith(".port"):
            try:
                value = int(value)
            except ValueError:
                await m.reply(f"❌ مقدار وارد شده برای {label} باید عددی باشد.", reply_markup=back_menu_admin(), quote=True)
                return
        
        settings.set(key_path, value)
        if reinit_func:
            reinit_func()
        
        await smart_edit(prompt_msg, f"✅ {label} با موفقیت به `{value}` تغییر یافت.", reply_markup=make_menu(([("🔙 بازگشت به تنظیمات", "admin_settings_main")], 1)))
        user_data.pop(uid, None)
        return

    if step.startswith("tariff_"):
        if step=="tariff_group_main":
            user_data[uid].update({"group_main":text_input.strip(), "awaiting":"tariff_group_sub"})
            await smart_edit(prompt_msg, "نام گروه فرعی را بفرست (یا '-' اگر خالی):", reply_markup=back_menu_admin())
            return

        if step=="tariff_group_sub":
            sub=text_input.strip()
            user_data[uid].update({"group_sub": None if sub=="-" else sub, "awaiting":"tariff_type_choose"})
            kb=make_menu(([("WireGuard","twg"),("MikroTik","tmt")],2),([("🔙 بازگشت","back_home")],1))
            await smart_edit(prompt_msg, "نوع سرویس را انتخاب کن:",reply_markup=kb)
            return
            
        if step == "tariff_profile_name":
            profile_name = text_input.strip()
            user_data[uid].update({"profile": profile_name, "awaiting": "tariff_size"})
            await smart_edit(prompt_msg, "چند گیگ ترافیک؟ (۰ = نامحدود)", reply_markup=back_menu_admin())
            return

        try:
            val = int(text_input.strip())
            if step=="tariff_size":
                user_data[uid].update({"size_mb":0 if val==0 else val*1024, "awaiting":"tariff_shared"})
                await smart_edit(prompt_msg, "چند کاربره باشد؟", reply_markup=back_menu_admin())
                return
            if step=="tariff_shared":
                user_data[uid].update({"shared_users":val, "awaiting":"tariff_price"})
                await smart_edit(prompt_msg, "قیمت به تومان؟", reply_markup=back_menu_admin())
                return
            if step=="tariff_price":
                user_data[uid].update({"price":val, "awaiting":"tariff_desc"})
                await smart_edit(prompt_msg, "📝 توضیحات تعرفه (برای نمایش به کاربر):", reply_markup=back_menu_admin())
                return
        except:
            await m.reply("❌ عدد معتبر بده", reply_markup=back_menu_admin(), quote=True)
            return

        if step=="tariff_desc":
            desc = text_input.strip()
            udl = user_data[uid]
            auto_desc = f"{'MikroTik' if udl['type']=='mikrotik' else 'WireGuard'} | {udl['profile']} | حجم: {human_gb(udl['size_mb'])}"
            
            success = tariffs.set_tariff(udl["type"], udl["profile"], udl["size_mb"], udl["shared_users"], udl["price"], udl.get("group_main"), udl.get("group_sub"), desc if desc and desc != "-" else auto_desc)
            
            if success:
                await smart_edit(prompt_msg, "✅ تعرفه ثبت شد.", reply_markup=back_menu_admin())
            else:
                await smart_edit(prompt_msg, "❌ خطا در ثبت تعرفه.", reply_markup=back_menu_admin())
            
            user_data.pop(uid,None)
            return

        if step=="tariff_delete_id":
            try:
                tid = int(text_input.strip())
                ok = tariffs.del_by_id(tid)
                await smart_edit(prompt_msg, "✅ حذف شد." if ok else "❌ کُد یافت نشد.", reply_markup=back_menu_admin())
                user_data.pop(uid,None)
                return
            except:
                await m.reply("❌ کُد معتبر نیست.", reply_markup=back_menu_admin(), quote=True)
                return

    if step == "admin_set_card":
        settings.set_card(text_input.strip())
        await smart_edit(prompt_msg, f"✅ شماره کارت ذخیره شد.", reply_markup=back_menu_admin())
        user_data.pop(uid,None); return

    if step == "admin_support_reply_text":
        target = ud.get("reply_to")
        await c.send_message(target, f"💬 *پاسخ پشتیبانی:*\n{text_input.strip()}")
        await m.reply("✅ پاسخ ارسال شد.", reply_markup=back_menu_admin())
        user_data.pop(uid,None); return

    if step == "admin_set_download":
        ud.setdefault("dl_buf", {})
        if ud["dl_buf"].get("kind") in ("photo","document"):
            ud["dl_buf"]["caption"] = (ud["dl_buf"].get("caption","") + ("\n\n" if ud["dl_buf"].get("caption") else "") + text_input).strip()
        else:
            ud["dl_buf"]["text"] = (ud["dl_buf"].get("text","") + ("\n\n" if ud["dl_buf"].get("text") else "") + text_input).strip()
        await m.reply("📝 متن به بافر اضافه شد. در پایان «✅ ذخیره».")
        return

@app.on_message((filters.photo|filters.document) & filters.private, group=1)
async def media_router(c, m: Message):
    uid=m.from_user.id
    ud = user_data.get(uid,{})
    step=ud.get("awaiting")
    if not step: return

    prompt_msg = m
    if ud.get("prompt_message_id"):
        try: prompt_msg = await c.get_messages(m.chat.id, ud["prompt_message_id"])
        except: pass

    if step=="order_receipt":
        t=ud["tariff"]; inv_id = ud.get("invoice_id") or "INV"+numeric_str(8); reqid=f"ORD{numeric_str(6)}"
        kb=make_menu(([("✅ تایید",f"ordok_{reqid}"),("❌ رد",f"ordno_{reqid}")],2))
        caption=f"Order {reqid} | Inv: {inv_id} | User:{uid} | Price:{format_toman(t['price'])}"
        file_id = m.photo.file_id if m.photo else m.document.file_id
        method = "photo" if m.photo else "document"
        
        PENDING_ORDERS[reqid] = {
            "uid": uid,
            "tariff": t,
            "inv_id": inv_id,
            "desired_name": ud.get("wanted_name"),
            "flow_type": "purchase",
            "user_info": {"id": m.from_user.id, "username": m.from_user.username}
        }
        _save_json(PENDING_ORDERS_FILE, PENDING_ORDERS)
        
        await safe_send_to_admins(method, file_id, caption=caption, reply_markup=kb)
        await smart_edit(prompt_msg, "رسید دریافت شد ✅ منتظر تایید ادمین باش.", reply_markup=back_menu_user())
        user_data.pop(uid,None); return
        
    if is_admin(uid) and ud.get("awaiting") == "admin_set_download":
        ud.setdefault("dl_buf", {})
        ud["dl_buf"].update({"kind": "photo" if m.photo else "document", "file_id": m.photo.file_id if m.photo else m.document.file_id, "caption": m.caption or ""})
        await m.reply("🖼 رسانه برای راهنما ثبت شد.", reply_markup=back_menu_admin()); return

@app.on_callback_query(filters.regex(r"^(as_reply|as_close)_(\d+)$"))
async def as_reply_close(c, cq):
    await cq.answer()
    if not is_admin(cq.from_user.id): return
    action, target_uid_str = cq.data.rsplit("_", 1)
    target_uid = int(target_uid_str)
    if action == "as_reply":
        user_data[cq.from_user.id] = {"awaiting":"admin_support_reply_text", "reply_to": target_uid, "prompt_message_id": cq.message.id}
        await cq.message.reply(f"✍️ متن پاسخ برای کاربر {target_uid} را ارسال کن:", reply_markup=back_menu_admin())
    else:
        try: await c.send_message(target_uid, "✅ تیکت شما بسته شد.")
        except: pass
        if getattr(cq.message, "caption", None):
            await cq.message.edit_caption("تیکت بسته شد.")
        else:
            await cq.message.edit_text("تیکت بسته شد.")

@app.on_callback_query(filters.regex("^u_my_orders$"))
async def show_my_orders(c, cq):
    await cq.answer()
    user_id = cq.from_user.id
    orders = orders_db.get_user_orders(user_id, limit=5)

    if not orders:
        await smart_edit(cq.message, "شما تاکنون سفارشی ثبت نکرده‌اید.", reply_markup=back_menu_user())
        return

    text = "🛍️ **۵ سفارش آخر شما:**\n\n"
    for order in orders:
        ts = datetime.fromisoformat(order['timestamp']).strftime('%Y-%m-%d')
        text += (
            f"🧾 **شناسه:** `{order['order_id']}`\n"
            f"🗓 **تاریخ:** {ts}\n"
            f"👤 **نام کاربری سرویس:** `{order['service_username']}`\n"
            f"📦 **پلن:** {order['tariff_desc']}\n"
            "--------------------\n"
        )
    
    await smart_edit(cq.message, text, reply_markup=back_menu_user())

@app.on_callback_query(filters.regex("^admin_orders$"))
async def show_admin_orders(c, cq):
    await cq.answer()
    if not is_admin(cq.from_user.id): return

    orders = orders_db.get_all_orders(limit=10)

    if not orders:
        await smart_edit(cq.message, "هنوز هیچ سفارشی در سیستم ثبت نشده است.", reply_markup=back_menu_admin())
        return
    
    text = "🛍️ **۱۰ سفارش آخر سیستم:**\n\n"
    for order in orders:
        ts = datetime.fromisoformat(order['timestamp']).strftime('%Y-%m-%d %H:%M')
        telegram_user = f"{order['user_id']} (@{order['telegram_username'] or '—'})"
        text += (
            f"🧾 **شناسه:** `{order['order_id']}`\n"
            f"🗓 **زمان:** {ts}\n"
            f"👤 **کاربر تلگرام:** {telegram_user}\n"
            f"🛠️ **سرویس:** `{order['service_username']}` ({order['service_type']})\n"
            f"📦 **پلن:** {order['tariff_desc']}\n"
            f"💳 **پرداخت:** {format_toman(order['price'])} ({order['payment_method']})\n"
            "--------------------\n"
        )
    
    await smart_edit(cq.message, text, reply_markup=back_menu_admin())

@app.on_callback_query(filters.regex("^u_buy_service_menu$|^u_tariffs_menu$"))
async def u_service_or_tariffs_menu(c, cq):
    await cq.answer()
    is_buy = cq.data == "u_buy_service_menu"
    
    if is_buy and not settings.get("general.purchase_active", True):
        await cq.answer("⛔️ امکان خرید سرویس در حال حاضر غیرفعال است.", show_alert=True)
        return
        
    action_verb = "خرید" if is_buy else "مشاهده"
    cb_prefix = "u_buy" if is_buy else "u_tariffs_list"
    
    btns = []
    if settings.get("general.wireguard_purchase_active", True):
        btns.append(("🛡️ WireGuard", f"{cb_prefix}_wireguard"))
    if settings.get("general.mikrotik_purchase_active", True):
        btns.append(("🌐 MikroTik", f"{cb_prefix}_mikrotik"))

    if not btns:
        await smart_edit(cq.message, f"⛔️ در حال حاضر سرویسی برای {action_verb} موجود نیست.", reply_markup=back_menu_user())
        return

    kb = make_menu(
        (btns, 2),
        ([("🔙 بازگشت", "u_back_home_user")], 1)
    )
    await smart_edit(cq.message, f"🛒 کدام نوع سرویس را برای {action_verb} انتخاب می‌کنید؟", reply_markup=kb)

@app.on_callback_query(filters.regex("^u_tariffs_list_(wireguard|mikrotik)$"))
async def u_tariffs_list(c, cq):
    await cq.answer()
    ttype = "wireguard" if cq.data.endswith("_wireguard") else "mikrotik"
    service_name = "WireGuard" if ttype == "wireguard" else "MikroTik"
    all_tariffs = tariffs.list_tariffs()
    filtered_list = [t for t in all_tariffs if t.get("type") == ttype]
    if not filtered_list:
        await smart_edit(cq.message, f"❌ در حال حاضر هیچ تعرفه‌ای برای {service_name} ثبت نشده.", reply_markup=back_menu_user()); return
    cards = [_pretty_tariff_card(t) for t in filtered_list]
    text = f"📋 لیست تعرفه‌های {service_name}:\n\n" + "\n\n".join(cards) + "\n\nبرای خرید از منوی اصلی اقدام کنید."
    await smart_edit(cq.message, text, reply_markup=make_menu(([("🔙 بازگشت", "u_tariffs_menu")], 1)))

@app.on_callback_query(filters.regex("^u_buy_(wireguard|mikrotik)$"))
async def u_buy_service(c, cq):
    await cq.answer()
    ttype = cq.data.split("_")[2]
    rows = tariffs.list_tariffs()
    sizes = _group_sizes(ttype, rows)
    if not sizes:
        await smart_edit(cq.message, f"❌ تعرفه {ttype.title()} ثبت نشده.", reply_markup=back_menu_user()); return
    glass = f"🛒 خرید {ttype.title()}\nلطفاً ابتدا حجم را انتخاب کنید."
    kb = make_menu((_size_buttons(ttype, sizes), 2), ([("🔙 بازگشت","u_buy_service_menu")],1))
    await smart_edit(cq.message, glass, reply_markup=kb)

@app.on_callback_query(filters.regex(r"^sz_(wg|mt)_(U|\d+)$"))
async def tar_size_pick(c, cq):
    await cq.answer()
    uid = cq.from_user.id
    m = re.match(r"^sz_(wg|mt)_(U|\d+)$", cq.data)
    ttype = "wireguard" if m.group(1) == "wg" else "mikrotik"
    size_mb = 0 if m.group(2) == "U" else int(m.group(2))
    items = _tariffs_by_size(ttype, size_mb, tariffs.list_tariffs())
    if not items:
        await cq.answer("برای این حجم تعرفه‌ای نیست.", show_alert=True); return

    user_data.setdefault(uid, {}).update({"awaiting": "tariff_pick", "current_tariffs": items})
    cards = [_pretty_tariff_card(t) for t in items]
    btns = [(t.get("desc", f"پلن {format_toman(t['price'])}"), f"ordx_{i}") for i, t in enumerate(items)]
    kb = make_menu((btns, 1), ([("⬅️ انتخاب حجم دیگر", f"u_buy_{ttype}")], 1), ([("🔙 بازگشت", "u_back_home_user")], 1))
    await smart_edit(cq.message, f"🔎 انتخاب پلن ({human_gb(size_mb)})\n\n" + "\n\n".join(cards), reply_markup=kb)

@app.on_callback_query(filters.regex(r"^ordx_(\d+)$"))
async def order_from_size(c, cq):
    await cq.answer()
    uid = cq.from_user.id
    ud = user_data.get(uid, {})
    cur_list = ud.get("current_tariffs", [])
    try:
        idx = int(cq.data.split("_")[1]); t = cur_list[idx]
    except (IndexError, ValueError):
        await cq.answer("سفارش منقضی شده.", show_alert=True); return
    
    inv_id = "INV" + numeric_str(8)
    ud.update({"awaiting": "ask_username", "tariff": t, "invoice_id": inv_id, "prompt_message_id": cq.message.id})
    kb = make_menu(([("🎲 نام تصادفی", "pick_rand_uname")], 1), ([("🔙 بازگشت", "u_back_home_user")], 1))
    await smart_edit(cq.message, "👤 لطفاً نام کاربری دلخواهت را بفرست (3-16 کاراکتر، فقط A-Z a-z 0-9 - _)\n\nیا روی «🎲 نام تصادفی» بزن.", reply_markup=kb)

@app.on_callback_query(filters.regex("^pick_rand_uname$"))
async def pick_rand_uname(c, cq):
    await cq.answer()
    uid = cq.from_user.id
    ud = user_data.get(uid, {})
    if ud.get("awaiting") != "ask_username": return
    
    t = ud["tariff"]; inv_id = ud["invoice_id"]
    invoice = _render_invoice(t, settings.get_card(), inv_id) + "\n👤 نام کاربری: (تصادفی)"
    
    pay_btns = []
    
    pay_btns.append(("📤 ارسال رسید پرداخت", "u_send_receipt"))
    kb = make_menu((pay_btns, 1), ([("📋 کپی کارت", "copy_card"), ("📋 کپی فاکتور", f"copy_inv_{inv_id}")], 2), ([("🔙 بازگشت", "u_back_home_user")], 1))
    ud["awaiting"] = "order_pay"
    await smart_edit(cq.message, invoice, reply_markup=kb)

@app.on_callback_query(filters.regex("^copy_(card|host|ip|ipsec)$"))
async def copy_details(c, cq):
    key = cq.data.split("_")[1]
    data = {
        "card": settings.get_card(),
        "host": settings.get('purchase_info.mt_server_host'),
        "ip": settings.get('purchase_info.mt_server_ip'),
        "ipsec": settings.get('purchase_info.mt_ipsec_secret')
    }
    text = data.get(key)
    if text: await cq.answer(f"کپی شد: {text}", show_alert=True)
    else: await cq.answer("موردی برای کپی یافت نشد.", show_alert=True)

@app.on_callback_query(filters.regex(r"^copy_inv_(.+)$"))
async def copy_inv(c, cq):
    inv = cq.data.split("_")[2]
    await cq.answer(f"شناسه فاکتور کپی شد: {inv}", show_alert=True)

@app.on_callback_query(filters.regex("^copy_u(name|pass)$"))
async def copy_creds(c, cq):
    key = "u" if cq.data.endswith("name") else "p"
    val = (LAST_CREDS.get(cq.from_user.id) or {}).get(key, "—")
    label = "نام کاربری" if key == "u" else "رمز عبور"
    await cq.answer(f"{label} کپی شد: {val}", show_alert=True)
    

async def create_single_wireguard_for_order(uid: int, profile: str, size_mb: int, wanted_name: Optional[str]) -> Tuple[bool, str]:
    if not wg_panel:
        return False, "سرویس WireGuard در حال حاضر در دسترس نیست."

    username = wanted_name if wanted_name and valid_username(wanted_name) else new_username_numeric()
    
    try:
        days_match = re.search(r'\d+', profile)
        days = int(days_match.group()) if days_match else 30
        expire_date = datetime.now(timezone.utc) + timedelta(days=days)
    except Exception:
        expire_date = None

    traffic_gb = math.ceil(size_mb / 1024) if size_mb > 0 else 0

    try:
        creation_ok = await run_blocking(wg_panel.create_user, name=username, expire=expire_date, traffic=traffic_gb)
        if not creation_ok:
            return False, "خطا در ساخت کاربر در پنل WireGuard."

        user_id_panel = await run_blocking(wg_panel.get_user_id_by_name, name=username)
        if not user_id_panel:
            return False, "کاربر ساخته شد اما اطلاعات آن یافت نشد."

        config_text = await run_blocking(wg_panel.get_user_config, user_id_panel)
        if not config_text:
            return False, "کانفیگ کاربر یافت نشد."

        conf_path = os.path.join(CONF_DIR, f"{username}.conf")
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(config_text)

        qr_path = os.path.join(QR_DIR, f"{username}.png")
        qr_img = qrcode.make(config_text)
        qr_img.save(qr_path)
        
        LAST_CREDS[uid] = {"u": username, "p": "—"}
        
        caption = (f"✅ سرویس WireGuard شما با نام کاربری `{username}` ایجاد شد.\n"
                   f"از فایل یا کد QR برای اتصال استفاده کنید.")
        
        await app.send_photo(uid, qr_path, caption=caption)
        await app.send_document(uid, conf_path, caption="فایل کانفیگ شما 📄")

        return True, "Success"
        
    except Exception as e:
        logger.error(f"Error creating WG user '{username}': {e}")
        return False, f"خطای پیش‌بینی نشده در ساخت سرویس: {e}"

async def create_single_mikrotik_for_order(uid: int, profile: str, size_mb: int, shared_users: int, wanted_name: Optional[str]) -> Tuple[bool, str]:
    rm = get_router()
    if not rm:
        return False, "سرویس MikroTik در حال حاضر در دسترس نیست."

    username = wanted_name if wanted_name and valid_username(wanted_name) else new_username_numeric()
    password = new_password_numeric()
    
    try:
        success = await run_blocking(
            rm.create_user_with_profile,
            username=username,
            password=password,
            profile=profile,
            limit_gb=size_mb / 1024 if size_mb > 0 else 0,
            shared_users=shared_users
        )
        if not success:
            return False, "خطا در ساخت کاربر در MikroTik."

        LAST_CREDS[uid] = {"u": username, "p": password}
        text = (
            f"✅ سرویس MikroTik شما با موفقیت ایجاد شد:\n\n"
            f"👤 **Username:** `{username}`\n"
            f"🔑 **Password:** `{password}`\n\n"
            f"{render_mikrotik_server_info()}"
        )
        kb = make_menu(
            ([("📋 کپی نام کاربری", "copy_uname"), ("📋 کپی رمز عبور", "copy_upass")], 2),
            ([("🔙 بازگشت", "u_back_home_user")], 1)
        )
        await app.send_message(uid, text, reply_markup=kb)
        return True, "Success"
    except Exception as e:
        logger.error(f"Error creating MikroTik user '{username}': {e}")
        return False, f"خطای پیش‌بینی نشده: {e}"


@app.on_callback_query(filters.regex("^u_send_receipt$"))
async def handle_payment(c,cq):
    await cq.answer()
    uid=cq.from_user.id
    ud=user_data.get(uid,{})
    t=ud.get("tariff")
    if not t: await cq.answer("سفارش یافت نشد",show_alert=True); return
    
    user_data[uid]["awaiting"]="order_receipt"
    await smart_edit(cq.message, "لطفاً رسید پرداخت را ارسال کن (عکس یا فایل).", reply_markup=back_menu_user())

@app.on_message(filters.regex(f"^{USER_BTN_MY_SERVICES}$"), group=0)
async def show_my_services_from_reply(c, m):
    sent_msg = await m.reply("لطفا نوع سرویس خود را انتخاب کنید:")
    class FakeCQ:
        def __init__(self, message, from_user):
            self.message = message
            self.from_user = from_user
        async def answer(self, *args, **kwargs):
            pass
    await show_my_services(c, FakeCQ(sent_msg, m.from_user))


async def show_my_services(c, cq):
    await cq.answer()
    
    kb = make_menu(
        ([
            ("🌐 بررسی سرویس MikroTik", "u_check_service_mt"),
            ("🛡️ بررسی سرویس WireGuard", "u_check_service_wg")
        ], 1),
        ([("🔙 بازگشت", "u_back_home_user")], 1)
    )
    
    await smart_edit(cq.message, "👤 برای مشاهده اطلاعات و مدیریت سرویس‌های خود، لطفاً نوع آن را انتخاب کنید:", reply_markup=kb)


@app.on_callback_query(filters.regex("^u_check_service_mt$"))
async def u_check_service_mt_prompt(c, cq):
    await cq.answer()
    uid = cq.from_user.id
    user_data[uid] = {"awaiting": "check_mt_username", "prompt_message_id": cq.message.id}
    await smart_edit(cq.message, "لطفاً نام کاربری سرویس MikroTik خود را که می‌خواهید بررسی کنید، وارد نمایید:", reply_markup=back_menu_user())


@app.on_callback_query(filters.regex("^u_check_service_wg$"))
async def u_check_service_wg_prompt(c, cq):
    await cq.answer()
    uid = cq.from_user.id
    user_data[uid] = {"awaiting": "check_wg_username", "prompt_message_id": cq.message.id}
    await smart_edit(cq.message, "لطفاً نام کاربری سرویس WireGuard خود را که می‌خواهید بررسی کنید، وارد نمایید:", reply_markup=back_menu_user())

async def admin_simple_stats(c, cq):
    await cq.answer()
    
    try:
        total_users = users_db.count()
        total_orders = len(orders_db._load())
    except Exception as e:
        logger.error(f"Error getting simple stats: {e}")
        await smart_edit(cq.message, "❌ خطایی در دریافت آمار رخ داد.", reply_markup=back_menu_admin())
        return

    text = (
        f"📊 **آمار ربات**\n\n"
        f"👥 **تعداد کل کاربران:** {total_users} نفر\n"
        f"🛍️ **تعداد کل سفارشات:** {total_orders} عدد\n"
    )
    
    await smart_edit(cq.message, text, reply_markup=back_menu_admin())

@app.on_callback_query(filters.regex("^admin_tariffs$"))
async def admin_tariffs(c, cq):
    await cq.answer()
    kb = make_menu(
        ([("➕ افزودن تعرفه","t_add"), ("🗑 حذف تعرفه","t_del")],2),
        ([("📋 لیست همه","t_list")],1),
        ([("🔙 بازگشت","back_home")],1)
    )
    await smart_edit(cq.message, "📄 مدیریت تعرفه‌ها", reply_markup=kb)

@app.on_callback_query(filters.regex("^t_add$"))
async def t_add(c,cq):
    await cq.answer()
    user_data[cq.from_user.id] = {"awaiting":"tariff_group_main", "prompt_message_id": cq.message.id}
    await smart_edit(cq.message, "نام گروه اصلی را بفرست:", reply_markup=back_menu_admin())

@app.on_callback_query(filters.regex("^t_del$"))
async def t_del(c,cq):
    await cq.answer()
    user_data[cq.from_user.id] = {"awaiting":"tariff_delete_id", "prompt_message_id": cq.message.id}
    await smart_edit(cq.message, "کُد تعرفه‌ای که باید حذف شود را بفرست:", reply_markup=back_menu_admin())

@app.on_callback_query(filters.regex("^t_list$"))
async def t_list(c,cq):
    await cq.answer()
    rows = tariffs.list_tariffs()
    if not rows: await smart_edit(cq.message, "لیست خالی است.", reply_markup=back_menu_admin()); return
    cards = "\n\n".join(_pretty_tariff_card(t) for t in rows)
    await smart_edit(cq.message, "📋 تعرفه‌ها:\n\n"+cards, reply_markup=back_menu_admin())

@app.on_callback_query(filters.regex("^(twg|tmt)$"))
async def t_type_pick(c, cq):
    await cq.answer()
    uid = cq.from_user.id
    ud = user_data.get(uid, {})
    
    ttype = "wireguard" if cq.data == "twg" else "mikrotik"
    ud["type"] = ttype

    if ttype == "wireguard":
        ud["awaiting"] = "tariff_profile_name"
        await smart_edit(cq.message, "لطفا نام پروفایل (مدت زمان) را وارد کنید (مثال: 30DAY):", reply_markup=back_menu_admin())
        return

    rm = get_router()
    if not rm:
        await smart_edit(cq.message, "❌ اتصال به روتر برقرار نیست. ابتدا تنظیمات ربات را بررسی کنید.", reply_markup=back_menu_admin())
        return

    await smart_edit(cq.message, "⏳ در حال دریافت لیست پروفایل‌ها از میکروتیک...")
    try:
        profiles = await run_blocking(rm.get_all_profiles)
        
        if profiles is None:
                raise ConnectionError("لیست پروفایل‌ها از میکروتیک دریافت نشد.")
        
        if not profiles:
            await smart_edit(cq.message, "❌ هیچ پروفایلی در User Manager میکروتیک یافت نشد.", reply_markup=back_menu_admin())
            return
        
        profile_buttons = [(p.get('name', 'N/A'), f"tariff_p_select_{p.get('name', 'N/A')}") for p in profiles]
        kb = make_menu(
            (profile_buttons, 2),
            ([("🔙 بازگشت", "admin_tariffs")], 1)
        )
        await smart_edit(cq.message, "لطفا پروفایل مورد نظر را از لیست زیر انتخاب کنید:", reply_markup=kb)

    except Exception as e:
        logger.error(f"خطا در دریافت پروفایل‌های میکروتیک: {e}")
        await smart_edit(cq.message, f"❌ خطایی در ارتباط با روتر رخ داد: {e}", reply_markup=back_menu_admin())

@app.on_callback_query(filters.regex("^tariff_p_select_(.+)"))
async def admin_select_profile(c, cq):
    await cq.answer()
    uid = cq.from_user.id
    
    profile_name = cq.data.removeprefix("tariff_p_select_")
    
    user_data[uid].update({
        "profile": profile_name,
        "awaiting": "tariff_size"
    })
    
    await smart_edit(cq.message, f"✅ پروفایل `{profile_name}` انتخاب شد.\n\nحالا چند گیگ ترافیک؟ (عدد ۰ برای نامحدود)", reply_markup=back_menu_admin())

@app.on_callback_query(filters.regex("^admin_set_card$"))
async def admin_set_card(c, cq):
    await cq.answer()
    user_data[cq.from_user.id] = {"awaiting": "admin_set_card", "prompt_message_id": cq.message.id}
    current_card = settings.get_card()
    await smart_edit(cq.message, f"💳 شماره کارت فعلی: `{current_card or 'ثبت نشده'}`\n\nلطفاً شماره کارت جدید را ارسال کنید:", reply_markup=back_menu_admin())

@app.on_callback_query(filters.regex("^admin_set_download$"))
async def admin_set_download_prompt(c, cq):
    await cq.answer()
    user_data[cq.from_user.id] = {"awaiting": "admin_set_download", "dl_buf": {}, "prompt_message_id": cq.message.id}
    kb = make_menu(([("✅ ذخیره", "dl_save"), ("🗑 لغو", "dl_cancel")], 2))
    await smart_edit(cq.message, "🔗 لطفاً فایل راهنمای اتصال (عکس، فایل یا متن) را ارسال کنید. پس از ارسال، دکمه «ذخیره» را بزنید.", reply_markup=kb)

@app.on_callback_query(filters.regex("^(dl_save|dl_cancel)$"))
async def save_or_cancel_download(c, cq):
    await cq.answer()
    uid = cq.from_user.id
    if cq.data == "dl_save":
        dl_buf = user_data.get(uid, {}).get("dl_buf")
        if dl_buf:
            settings.set_download(dl_buf)
            await smart_edit(cq.message, "✅ راهنمای اتصال با موفقیت ذخیره شد.", reply_markup=back_menu_admin())
        else:
            await cq.answer("❌ محتوایی برای ذخیره ارسال نشده است.", show_alert=True)
    else:
        await smart_edit(cq.message, "عملیات لغو شد.", reply_markup=back_menu_admin())
    user_data.pop(uid, None)

@app.on_callback_query(filters.regex("^admin_settings_main$"))
async def admin_settings_main(c, cq):
    await cq.answer()
    kb = make_menu(
        ([("🤖 تنظیمات عمومی ربات", "admin_settings_general")], 1),
        ([("📡 تنظیمات پنل‌ها", "admin_settings_panels")], 1),
        ([("ℹ️ تنظیمات اطلاعات خرید", "admin_settings_purchase_info")], 1),
        ([("🔙 بازگشت", "back_home")], 1)
    )
    await smart_edit(cq.message, "⚙️ بخش تنظیمات اصلی ربات", reply_markup=kb)

@app.on_callback_query(filters.regex("^admin_settings_general$"))
async def admin_settings_general(c, cq):
    await cq.answer()
    kb = make_menu(
        ([("☎️ آیدی پشتیبانی", "set_s_support_contact"), ("📢 کانال‌های عضویت", "set_s_req_channels")], 2),
        ([("روشن/خاموش کردن ربات", "tgl_s_bot_active"), ("روشن/خاموش کردن کل خریدها", "tgl_s_purchase_active")], 2),
        ([("خرید MikroTik", "tgl_s_mikrotik_purchase_active"), ("خرید WireGuard", "tgl_s_wireguard_purchase_active")], 2),
        ([("🔙 بازگشت به تنظیمات", "admin_settings_main")], 1)
    )
    await smart_edit(cq.message, "🤖 تنظیمات عمومی ربات", reply_markup=kb)

@app.on_callback_query(filters.regex("^admin_settings_panels$"))
async def admin_settings_panels(c, cq):
    await cq.answer()
    kb = make_menu(
        ([("🛡️ تنظیمات پنل WireGuard", "admin_settings_wg")], 1),
        ([("🌐 تنظیمات پنل MikroTik", "admin_settings_mt")], 1),
        ([("🔙 بازگشت به تنظیمات", "admin_settings_main")], 1)
    )
    await smart_edit(cq.message, "📡 کدام پنل را می‌خواهید تنظیم کنید؟", reply_markup=kb)

@app.on_callback_query(filters.regex("^admin_settings_wg$"))
async def admin_settings_wg(c, cq):
    await cq.answer()
    kb = make_menu(
        ([("🔗 URL پنل", "set_s_wg_url")], 1),
        ([("👤 نام کاربری", "set_s_wg_user")], 1),
        ([("🔑 رمز عبور", "set_s_wg_pass")], 1),
        ([("🔙 بازگشت", "admin_settings_panels")], 1)
    )
    await smart_edit(cq.message, "🛡️ تنظیمات پنل WireGuard", reply_markup=kb)

@app.on_callback_query(filters.regex("^admin_settings_mt$"))
async def admin_settings_mt(c, cq):
    await cq.answer()
    kb = make_menu(
        ([("🖥️ هاست/IP", "set_s_ros_host"), ("🔌 پورت", "set_s_ros_port")], 2),
        ([("👤 نام کاربری", "set_s_ros_user"), ("🔑 رمز عبور", "set_s_ros_pass")], 2),
        ([("🔙 بازگشت", "admin_settings_panels")], 1)
    )
    await smart_edit(cq.message, "🌐 تنظیمات پنل MikroTik", reply_markup=kb)

@app.on_callback_query(filters.regex("^admin_settings_purchase_info$"))
async def admin_settings_purchase_info(c, cq):
    await cq.answer()
    kb = make_menu(
        ([("هاست اتصال MT", "set_s_pi_host"), ("آی‌پی اتصال MT", "set_s_pi_ip")], 2),
        ([("کد IPSec", "set_s_pi_ipsec")], 1),
        ([("🔙 بازگشت به تنظیمات", "admin_settings_main")], 1)
    )
    await smart_edit(cq.message, "ℹ️ تنظیمات اطلاعاتی که پس از خرید به کاربر نمایش داده می‌شود", reply_markup=kb)

@app.on_callback_query(filters.regex("^set_s_"))
async def admin_set_string_values(c, cq):
    await cq.answer()
    key_map = {
        "support_contact": "آیدی پشتیبانی", "req_channels": "کانال‌های عضویت (با کاما جدا کنید)",
        "wg_url": "آدرس پنل وایرگارد", "wg_user": "یوزرنیم پنل وایرگارد", "wg_pass": "پسورد پنل وایرگارد",
        "ros_host": "آدرس هاست میکروتیک", "ros_port": "پورت میکروتیک", "ros_user": "یوزرنیم میکروتیک", "ros_pass": "پسورد میکروتیک",
        "pi_host": "هاست اتصال میکروتیک", "pi_ip": "آی‌پی اتصال میکروتیک", "pi_ipsec": "کد IPSec",
        "pi_ovpn": "مسیر کامل فایل OpenVPN روی سرور",
    }
    setting_key = cq.data.replace("set_s_", "")
    prompt_text = key_map.get(setting_key, "مقدار جدید")
    
    user_data[cq.from_user.id] = {"awaiting": f"set_{setting_key}", "prompt_message_id": cq.message.id}
    await smart_edit(cq.message, f"لطفا مقدار جدید برای «{prompt_text}» را ارسال کنید:", reply_markup=back_menu_admin())
    
@app.on_callback_query(filters.regex("^tgl_s_"))
async def admin_toggle_boolean_values(c, cq):
    key_map = {
        "bot_active": ("general.bot_active", "وضعیت کلی ربات"),
        "purchase_active": ("general.purchase_active", "قابلیت خرید کلی"),
        "mikrotik_purchase_active": ("general.mikrotik_purchase_active", "خرید سرویس MikroTik"),
        "wireguard_purchase_active": ("general.wireguard_purchase_active", "خرید سرویس WireGuard"),
    }
    
    setting_key = cq.data.replace("tgl_s_", "")
    
    if setting_key in key_map:
        key_path, label = key_map[setting_key]
        current_status = settings.get(key_path, True)
        new_status = not current_status
        settings.set(key_path, new_status)
        await cq.answer(f"{label}: {'✅ روشن' if new_status else '❌ خاموش'}", show_alert=True)

@app.on_callback_query(filters.regex(r"^(ordok|ordno)_(ORD\d+)$"))
async def handle_order_approval(c, cq):
    if not is_admin(cq.from_user.id):
        await cq.answer("شما ادمین نیستید.", show_alert=True)
        return

    action, reqid = cq.data.split("_")
    
    global PENDING_ORDERS
    order_data = PENDING_ORDERS.pop(reqid, None)

    if not order_data:
        await cq.answer("❌ این سفارش قبلاً پردازش شده یا یافت نشد.", show_alert=True)
        try: await smart_edit(cq.message, cq.message.caption + "\n\n**⚠️ سفارش یافت نشد (احتمالاً پردازش شده).**")
        except: pass
        return
    
    _save_json(PENDING_ORDERS_FILE, PENDING_ORDERS)

    uid = order_data.get("uid")
    t = order_data.get("tariff")
    inv_id = order_data.get("inv_id")
    wanted_name = order_data.get("desired_name")
    user_info = order_data.get("user_info", {"id": uid, "username": "N/A"})

    if action == "ordno":
        await cq.answer("❌ سفارش رد شد.")
        try: await c.send_message(uid, f"❌ سفارش شما (فاکتور: {inv_id}) توسط مدیریت رد شد.")
        except Exception as e: logger.error(f"Failed to send rejection to user {uid}: {e}")
        
        new_caption = (cq.message.caption or "") + f"\n\n**❌ توسط {cq.from_user.first_name} رد شد.**"
        await smart_edit(cq.message, new_caption)
        return

    await cq.answer("✅ در حال پردازش سفارش...")
    try:
        await smart_edit(cq.message, (cq.message.caption or "") + "\n\n**⏳ در حال پردازش...**")
    except Exception:
        pass

    success = False
    details = ""

    try:
        if t["type"] == "wireguard":
            success, details = await create_single_wireguard_for_order(uid, t["profile"], t["size_mb"], wanted_name)
        else:
            success, details = await create_single_mikrotik_for_order(uid, t["profile"], t["size_mb"], t["shared_users"], wanted_name)
    
    except Exception as e:
        success = False
        details = str(e)
        logger.error(f"CRITICAL: Order approval failed for {reqid} with exception: {e}")

    if success:
        await send_purchase_report(uid, user_info, t, inv_id, "رسید (خرید دستی)")
        users_db.set_has_purchased(uid, True)
        
        new_caption = (cq.message.caption or "") + f"\n\n**✅ با موفقیت توسط {cq.from_user.first_name} تایید شد.**"
        await smart_edit(cq.message, new_caption)
    
    else:
        PENDING_ORDERS[reqid] = order_data
        _save_json(PENDING_ORDERS_FILE, PENDING_ORDERS)
        
        error_msg = f"⚠️ پردازش سفارش {reqid} با خطا مواجه شد:\n{details}\n\Sفارش به لیست انتظار بازگردانده شد. لطفاً خطا را بررسی و مجدداً تلاش کنید."
        await cq.answer(error_msg, show_alert=True)
        
        new_caption = (cq.message.caption or "") + f"\n\n**‼️ خطای پردازش: {details}**"
        await smart_edit(cq.message, new_caption)
        
        try: await c.send_message(uid, f"❌ متاسفانه در پردازش سفارش شما (فاکتور: {inv_id}) خطایی رخ داد. لطفاً با پشتیبانی تماس بگیرید.")
        except Exception as e: logger.error(f"Failed to send failure msg to user {uid}: {e}")

if __name__ == "__main__":
    print("🚀 Bot is running...")
    app.run()
