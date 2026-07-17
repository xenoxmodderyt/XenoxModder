from flask import Flask, request, jsonify, send_from_directory, send_file
import json, os, time, re, traceback

from config import IPS_FILE, ADMIN_PASSWORD, SYSTEM_NAME
from key_manager import (
    bind_key_by_device,
    load_license_keys,
    save_license_keys,
    normalize_key,
    create_pending_key,
    load_ips,
    save_ips,
)

app = Flask(__name__)
MATERIAL_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "game_patches"))
MINIAPP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "miniapp")
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
FREEZE_STATE_FILE = os.path.join(_DATA_DIR, "freeze_state.json")

def _parse_ipv4(s):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", (s or "").strip())
    if not m:
        return None
    parts = [int(x) for x in m.groups()]
    if any(p < 0 or p > 255 for p in parts):
        return None
    return ".".join(str(p) for p in parts)

def is_allowed(ip):
    if not os.path.exists(IPS_FILE):
        return False
    try:
        with open(IPS_FILE, "r") as f:
            db = json.load(f)
        return ip in db and db[ip]['expires_at'] > time.time()
    except:
        return False

def _is_system_frozen():
    try:
        if not os.path.exists(FREEZE_STATE_FILE):
            return False
        with open(FREEZE_STATE_FILE, "r", encoding="utf-8") as f:
            st = json.load(f)
        return bool(st.get("frozen", False))
    except Exception:
        return False

def _check_admin(req):
    """Simple password auth via header or JSON body."""
    auth = req.headers.get("X-Admin-Password", "")
    if auth == ADMIN_PASSWORD:
        return True
    try:
        body = req.get_json(force=True, silent=True) or {}
        return body.get("password") == ADMIN_PASSWORD
    except Exception:
        return False

# ── Public endpoints ──────────────────────────────────────────────────────────

@app.route('/check_auth')
def check_auth():
    ip = request.remote_addr
    if is_allowed(ip):
        return jsonify({"status": "success", "msg": f"{SYSTEM_NAME}: License Active"}), 200
    return jsonify({"status": "fail", "msg": f"IP {ip} is not active!"}), 403

@app.route('/game_patches/<filename>')
def get_material(filename):
    if is_allowed(request.remote_addr):
        return send_from_directory(MATERIAL_DIR, filename)
    return "Unauthorized Access", 403

@app.route('/miniapp')
def miniapp_index():
    return send_from_directory(MINIAPP_DIR, "index.html")

@app.route('/miniapp/tutorial')
def miniapp_tutorial():
    return send_from_directory(MINIAPP_DIR, "tutorial.html")

@app.route('/miniapp/files/<path:filename>')
def miniapp_files(filename):
    files_dir = os.path.join(MINIAPP_DIR, "files")
    lower = str(filename).lower()
    is_video = lower.endswith(".mp4") or lower.endswith(".webm") or lower.endswith(".mov")
    full_path = os.path.join(files_dir, filename)
    if not os.path.isfile(full_path):
        return "File not found", 404
    if not is_video:
        download_filename = "Proxy.crt" if lower.endswith(".pem") or lower.endswith(".crt") else os.path.basename(filename)
        resp = send_file(full_path, as_attachment=True, download_name=download_filename, mimetype="application/octet-stream")
        resp.headers["Content-Disposition"] = f'attachment; filename="{download_filename}"'
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp
    resp = send_file(full_path, as_attachment=False, conditional=True)
    resp.headers["Accept-Ranges"] = "bytes"
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp

@app.route('/miniapp/files')
def miniapp_files_index():
    files_dir = os.path.join(MINIAPP_DIR, "files")
    if not os.path.isdir(files_dir):
        return jsonify({"ok": False, "url": None}), 200
    preferred = ["tutorial.mp4", "video.mp4", "tutorial.webm", "video.webm", "tutorial.mov", "video.mov"]
    for name in preferred:
        if os.path.isfile(os.path.join(files_dir, name)):
            return jsonify({"ok": True, "url": f"/miniapp/files/{name}"}), 200
    for name in sorted(os.listdir(files_dir)):
        if name.lower().endswith((".mp4", ".webm", ".mov", ".m4v")):
            if os.path.isfile(os.path.join(files_dir, name)):
                return jsonify({"ok": True, "url": f"/miniapp/files/{name}"}), 200
    return jsonify({"ok": False, "url": None}), 200

@app.route('/miniapp/activate', methods=['POST'])
def miniapp_activate():
    try:
        payload = request.get_json(force=True, silent=True) or {}
        key_raw = str(payload.get("key", "")).strip()
        ip_raw = str(payload.get("ip", "")).strip()
        device_token = str(payload.get("device_token", "")).strip()
        client_ip = _parse_ipv4(ip_raw) or request.remote_addr

        if not key_raw or not client_ip:
            return jsonify({"ok": False, "error": "missing_fields"}), 400
        if not device_token:
            return jsonify({"ok": False, "error": "missing_device_token"}), 400

        ok, err = bind_key_by_device(key_raw, client_ip, device_token)
        if not ok:
            return jsonify({"ok": False, "error": err}), 403

        key = normalize_key(key_raw)
        keys = load_license_keys()
        rec = keys.get(key, {})
        if device_token:
            rec["device_token"] = device_token
            rec["device_bound_at"] = time.time()
            keys[key] = rec
            save_license_keys(keys)

        return jsonify({
            "ok": True,
            "key": key,
            "ip": rec.get("activated_ip", client_ip),
            "expires_at": rec.get("expires_at", 0),
        }), 200
    except Exception:
        traceback.print_exc()
        return jsonify({"ok": False, "error": "server_error"}), 500

@app.route('/miniapp/status', methods=['POST'])
def miniapp_status():
    try:
        payload = request.get_json(force=True, silent=True) or {}
        ip = _parse_ipv4(str(payload.get("ip", "")).strip())
        device_token = str(payload.get("device_token", "")).strip()

        if not device_token:
            return jsonify({"ok": False, "error": "missing_device_token"}), 400

        now = time.time()
        keys = load_license_keys()
        active = []
        for key, rec in keys.items():
            if rec.get("status") != "active":
                continue
            if float(rec.get("expires_at", 0) or 0) <= now:
                continue
            if str(rec.get("device_token", "")).strip() != device_token:
                continue
            if ip and rec.get("activated_ip") != ip:
                ok, err = bind_key_by_device(key, ip, device_token)
                if ok:
                    rec = load_license_keys().get(key, rec)
            active.append({
                "key": key,
                "ip": rec.get("activated_ip"),
                "expires_at": rec.get("expires_at", 0),
                "duration_days": rec.get("duration_days", 0),
            })

        return jsonify({"ok": True, "active": active, "frozen": _is_system_frozen()}), 200
    except Exception:
        traceback.print_exc()
        return jsonify({"ok": False, "error": "server_error"}), 500

# ── Admin endpoints (password protected) ─────────────────────────────────────

@app.route('/admin/create_key', methods=['POST'])
def admin_create_key():
    if not _check_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    payload = request.get_json(force=True, silent=True) or {}
    duration_type = payload.get("duration_type", "day")
    days = int(payload.get("days", 1))
    cost = float(payload.get("cost", 0))
    key = create_pending_key("admin", duration_type, days, cost)
    return jsonify({"ok": True, "key": key, "days": days}), 200

@app.route('/admin/list_keys', methods=['POST'])
def admin_list_keys():
    if not _check_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    keys = load_license_keys()
    now = time.time()
    result = []
    for k, rec in keys.items():
        result.append({
            "key": k,
            "status": rec.get("status"),
            "ip": rec.get("activated_ip"),
            "expires_at": rec.get("expires_at", 0),
            "expired": float(rec.get("expires_at", 0) or 0) < now,
            "duration_days": rec.get("duration_days", 0),
        })
    return jsonify({"ok": True, "keys": result}), 200

@app.route('/admin/revoke_key', methods=['POST'])
def admin_revoke_key():
    if not _check_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    payload = request.get_json(force=True, silent=True) or {}
    key_raw = str(payload.get("key", "")).strip()
    key = normalize_key(key_raw)
    keys = load_license_keys()
    if key not in keys:
        return jsonify({"ok": False, "error": "not_found"}), 404
    rec = keys[key]
    old_ip = rec.get("activated_ip")
    rec["status"] = "revoked"
    rec["banned"] = True
    save_license_keys(keys)
    if old_ip:
        ips = load_ips()
        ips.pop(old_ip, None)
        save_ips(ips)
    return jsonify({"ok": True, "key": key}), 200

@app.route('/admin/freeze', methods=['POST'])
def admin_freeze():
    if not _check_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    payload = request.get_json(force=True, silent=True) or {}
    frozen = bool(payload.get("frozen", True))
    os.makedirs(_DATA_DIR, exist_ok=True)
    with open(FREEZE_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"frozen": frozen}, f)
    return jsonify({"ok": True, "frozen": frozen}), 200

@app.route('/admin/list_ips', methods=['POST'])
def admin_list_ips():
    if not _check_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    ips = load_ips()
    now = time.time()
    result = {ip: {**data, "expired": float(data.get("expires_at", 0) or 0) < now} for ip, data in ips.items()}
    return jsonify({"ok": True, "ips": result}), 200

if __name__ == '__main__':
    print(f"\n{'='*50}")
    print(f"  {SYSTEM_NAME} - Auth Server")
    print(f"{'='*50}")
    print("  Running on http://0.0.0.0:5000")
    print(f"{'='*50}\n")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
