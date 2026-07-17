"""
License keys (XXXX-XXXX-XXXX): pending until user activates; then IP is bound in allowed_ips.json
"""
import json
import os
import secrets
import time

_BASE = os.path.dirname(os.path.abspath(__file__))


def _path(rel):
    return os.path.join(_BASE, rel)


def _load_json(rel, default):
    p = _path(rel)
    if not os.path.exists(p):
        return default
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(rel, data):
    p = _path(rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_ips():
    return _load_json("data/allowed_ips.json", {})


def save_ips(data):
    _save_json("data/allowed_ips.json", data)


def load_license_keys():
    return _load_json("data/license_keys.json", {})


def save_license_keys(data):
    _save_json("data/license_keys.json", data)


def load_db():
    return _load_json("data/database.json", {"admins": {}, "keys": {}, "users": {}})


def save_db(data):
    _save_json("data/database.json", data)

def is_system_frozen():
    st = _load_json("data/freeze_state.json", {"frozen": False})
    return bool(st.get("frozen", False))


def _rand_seg(n=4):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def generate_license_key():
    return f"{_rand_seg()}-{_rand_seg()}-{_rand_seg()}"


def normalize_key(s):
    if not s:
        return ""
    return "".join(s.split()).upper()


def create_pending_key(admin_id, duration_type, days, cost):
    keys = load_license_keys()
    k = generate_license_key()
    while k in keys:
        k = generate_license_key()
    keys[k] = {
        "status": "pending",
        "admin": str(admin_id),
        "duration_days": int(days),
        "duration_type": duration_type,
        "created_at": time.time(),
        "cost_paid": float(cost),
    }
    save_license_keys(keys)
    return k

def _bind_ip_to_key(key, rec, public_ip, expires):
    """Update allowed_ips + database mapping for this key/ip."""
    ips = load_ips()
    old_ip = rec.get("activated_ip")
    admin = rec.get("admin")

    # Prevent stealing an IP currently used by another active key.
    existing = ips.get(public_ip)
    if existing and existing.get("license_key") != key and float(existing.get("expires_at", 0) or 0) > time.time():
        return False, "ip_in_use"

    # Enforce single-IP-per-key strictly: remove any stale old mappings.
    stale_ips = [ip for ip, data in ips.items() if data.get("license_key") == key and ip != public_ip]
    for sip in stale_ips:
        ips.pop(sip, None)
    if old_ip and old_ip in ips and old_ip != public_ip and ips[old_ip].get("license_key") == key:
        ips.pop(old_ip, None)
    ips[public_ip] = {
        "expires_at": expires,
        "admin": admin,
        "license_key": key,
    }
    save_ips(ips)

    db = load_db()
    if admin in db.get("admins", {}):
        if "keys" not in db["admins"][admin]:
            db["admins"][admin]["keys"] = []
        admin_keys = db["admins"][admin]["keys"]
        for sip in stale_ips:
            if sip in admin_keys:
                admin_keys[:] = [x for x in admin_keys if x != sip]
        if old_ip in admin_keys and old_ip != public_ip:
            admin_keys[:] = [x for x in admin_keys if x != old_ip]
        if public_ip not in admin_keys:
            admin_keys.append(public_ip)
    if "keys" not in db:
        db["keys"] = {}
    for sip in stale_ips:
        db["keys"].pop(sip, None)
    if old_ip in db["keys"] and old_ip != public_ip:
        db["keys"].pop(old_ip, None)
    db["keys"][public_ip] = {
        "admin": admin,
        "created": db["keys"].get(public_ip, {}).get("created", time.time()),
        "license_key": key,
    }
    save_db(db)
    return True, None

def bind_key_by_device(key_str, public_ip, device_token, user_id=None):
    """
    Device-token-first activation/rebind flow used by mini app.
    - pending key: activate and bind to device_token + ip
    - active key: rebind ip only if same device_token
    Returns (True, None) or (False, error_code).
    """
    key = normalize_key(key_str)
    if len(key.replace("-", "")) != 12 or key.count("-") != 2:
        return False, "bad_format"
    if not device_token:
        return False, "missing_device_token"
    if is_system_frozen():
        return False, "frozen"

    keys = load_license_keys()
    if key not in keys:
        return False, "not_found"

    rec = keys[key]
    if rec.get("banned"):
        return False, "banned"

    # First-time activation
    if rec.get("status") == "pending":
        days = int(rec["duration_days"])
        expires = time.time() + days * 86400
        ok, err = _bind_ip_to_key(key, rec, public_ip, expires)
        if not ok:
            return False, err

        rec["status"] = "active"
        rec["activated_ip"] = public_ip
        rec["activated_at"] = time.time()
        rec["expires_at"] = expires
        rec["device_token"] = str(device_token)
        rec["device_bound_at"] = time.time()
        if user_id is not None:
            rec["user_id"] = str(user_id)
        save_license_keys(keys)
        return True, None

    # Active: require matching device token
    if rec.get("status") == "active":
        expires = float(rec.get("expires_at", 0) or 0)
        if expires <= time.time():
            return False, "expired"

        bound = str(rec.get("device_token", "") or "")
        incoming = str(device_token)
        if bound and bound != incoming:
            return False, "device_mismatch"
        if not bound:
            # One-time migration: attach a token to older keys.
            rec["device_token"] = incoming
            rec["device_bound_at"] = time.time()

        ok, err = _bind_ip_to_key(key, rec, public_ip, expires)
        if not ok:
            return False, err

        rec["activated_ip"] = public_ip
        rec["last_rebind_at"] = time.time()
        rec["rebind_count"] = int(rec.get("rebind_count", 0)) + 1
        if user_id is not None and not rec.get("user_id"):
            rec["user_id"] = str(user_id)
        save_license_keys(keys)
        return True, None

    return False, "already_used"


def activate_license_key(key_str, public_ip, user_id):
    """
    Bind public_ip (from ipify on same phone/network as proxy) to this license.
    Returns (True, None) or (False, error_code).
    """
    key = normalize_key(key_str)
    if len(key.replace("-", "")) != 12 or key.count("-") != 2:
        return False, "bad_format"
    if is_system_frozen():
        return False, "frozen"

    keys = load_license_keys()
    if key not in keys:
        return False, "not_found"

    rec = keys[key]
    user_id = str(user_id)
    if rec.get("banned"):
        return False, "banned"
    if rec.get("status") != "pending":
        # Legacy path: allow same telegram user to rebind.
        if rec.get("status") == "active" and rec.get("user_id") == user_id:
            expires = float(rec.get("expires_at", 0) or 0)
            if expires <= time.time():
                return False, "expired"
            ok, err = _bind_ip_to_key(key, rec, public_ip, expires)
            if not ok:
                return False, err
            rec["activated_ip"] = public_ip
            rec["last_rebind_at"] = time.time()
            rec["rebind_count"] = int(rec.get("rebind_count", 0)) + 1
            save_license_keys(keys)
            return True, None
        return False, "already_used"

    days = int(rec["duration_days"])
    admin = rec["admin"]
    expires = time.time() + days * 86400

    ok, err = _bind_ip_to_key(key, rec, public_ip, expires)
    if not ok:
        return False, err

    keys[key]["status"] = "active"
    keys[key]["activated_ip"] = public_ip
    keys[key]["activated_at"] = time.time()
    keys[key]["expires_at"] = expires
    keys[key]["user_id"] = user_id
    save_license_keys(keys)
    return True, None
