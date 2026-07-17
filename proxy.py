# Run: mitmdump -s proxy.py --listen-host 0.0.0.0 --listen-port 8080 --set block_global=false
from mitmproxy import http
import datetime, time, json, os, re

LOG_ENABLED = False
LOG_FILE = "mitm_log.txt"

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IPS_FILE = os.path.join(_BASE_DIR, "system", "data", "allowed_ips.json")
FREEZE_STATE_FILE = os.path.join(_BASE_DIR, "system", "data", "freeze_state.json")
PATCHES_DIR = os.path.join(_BASE_DIR, "game_patches", "Drag only")

def log(title, data=""):
    if not LOG_ENABLED:
        return
    t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{t}] {title}: {data[:200]}\n")

def _is_private(ip):
    ip = str(ip).strip().strip("[]")
    if ip in ("127.0.0.1", "::1", "localhost", "0.0.0.0"):
        return True
    parts = ip.split(".")
    if len(parts) == 4:
        try:
            a, b = int(parts[0]), int(parts[1])
            if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127:
                return True
        except ValueError:
            pass
    return False

def get_client_ip(flow):
    peer = str(flow.client_conn.peername[0])
    if peer.startswith("::ffff:"):
        peer = peer[7:]
    if not _is_private(peer):
        return peer
    for h in ("x-forwarded-for", "x-real-ip", "cf-connecting-ip"):
        v = flow.request.headers.get(h, "").split(",")[0].strip()
        if v:
            return v
    return peer

def check_license(ip):
    try:
        if os.path.exists(FREEZE_STATE_FILE):
            with open(FREEZE_STATE_FILE) as f:
                if json.load(f).get("frozen"):
                    return False
        if os.path.exists(IPS_FILE):
            with open(IPS_FILE) as f:
                db = json.load(f)
            return ip in db and db[ip].get("expires_at", 0) > time.time()
        return False
    except:
        return False

def _is_hex(text):
    s = str(text).strip()
    if not re.fullmatch(r"[0-9a-fA-F\s]+", s):
        return False
    cleaned = re.sub(r"\s+", "", s)
    return len(cleaned) >= 2 and len(cleaned) % 2 == 0

def load_patch(name):
    for fname in (name, name + ".txt"):
        path = os.path.join(PATCHES_DIR, fname)
        if os.path.exists(path):
            with open(path, "r", errors="ignore") as f:
                text = f.read().strip()
            if _is_hex(text):
                return bytes.fromhex(re.sub(r"\s+", "", text))
            with open(path, "rb") as f:
                return f.read()
    return None

def request(flow: http.HTTPFlow):
    print(flow.request.pretty_url)

def response(flow: http.HTTPFlow):
    url = flow.request.pretty_url.lower()
    ff_paths = [
        "/fileinfo",
        "/assetindexer",
        "/majorlogin",
        "/checkhackbehavior",
        "/getmatchmakingblacklist",
        "hidereportios",
    ]
    if not any(p in url for p in ff_paths):
        return

    ip = get_client_ip(flow)
    if not check_license(ip):
        flow.response = http.Response.make(
            403,
            json.dumps({"error": "No active license", "ip": ip}).encode(),
            {"Content-Type": "application/json", "Connection": "close"}
        )
        return

    if "/majorlogin" in url:
        return  # pass through

    if "/checkhackbehavior" in url:
        return  # pass through

    if "/getmatchmakingblacklist" in url:
        return  # pass through

    if "hidereportios" in url:
        return  # pass through

    if "/fileinfo" in url:
        patch = load_patch("fileinfo")
        ctype = "application/json; charset=utf-8"
    elif "/assetindexer" in url:
        patch = load_patch("drag")
        ctype = "application/octet-stream"
    else:
        return

    if patch:
        flow.response = http.Response.make(200, patch, {"Content-Type": ctype, "Connection": "close"})
        log("SERVED", f"{url} → drag patch ({len(patch)} bytes, {ip})")
    else:
        log("MISSING", f"patch not found for {url}")
