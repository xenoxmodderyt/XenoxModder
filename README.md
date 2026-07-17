# Proxy System - Setup Guide

## Structure
```
Main/
├── proxy.py              # mitmproxy script (intercepts game traffic)
├── proxy_config.py       # port → mod mapping
├── requirements.txt      # proxy deps
├── game_patches/         # your patch files go here
│   ├── Drag only/
│   ├── Antenna hand/
│   ├── Magic Bullet/
│   ├── Body 90%/
│   └── DragwithAntenna/
└── system/
    ├── auth_server.py    # Flask license server
    ├── config.py         # change ADMIN_PASSWORD here
    ├── key_manager.py    # key generation & binding
    ├── requirements.txt  # server deps
    ├── miniapp/          # user web interface
    └── data/             # JSON databases (auto-created)
```

## Install

```bash
# Proxy
pip install -r requirements.txt

# Auth server
cd system
pip install -r requirements.txt
```

## Run

```bash
# Start auth server (port 5000)
cd system && python auth_server.py

# Start proxy - one port per mod
PROXY_PORT=9999 mitmdump -s proxy.py --listen-host 0.0.0.0 --listen-port 9999 --set block_global=false
PROXY_PORT=9998 mitmdump -s proxy.py --listen-host 0.0.0.0 --listen-port 9998 --set block_global=false
# ... etc
```

## Admin API

Set `X-Admin-Password: yourpassword` header (or pass `"password"` in JSON body).

| Endpoint | Method | Description |
|---|---|---|
| `/admin/create_key` | POST | Create a new license key |
| `/admin/list_keys` | POST | List all keys |
| `/admin/revoke_key` | POST | Revoke/ban a key |
| `/admin/list_ips` | POST | List active IPs |
| `/admin/freeze` | POST | Freeze all keys (`{"frozen": true}`) |

### Create key example
```bash
curl -X POST http://localhost:5000/admin/create_key \
  -H "Content-Type: application/json" \
  -H "X-Admin-Password: changeme123" \
  -d '{"duration_type": "week", "days": 7, "cost": 3.0}'
```

## Config

Edit `system/config.py`:
- `ADMIN_PASSWORD` — change before deploying
- `PRICING` / `DURATIONS` — adjust as needed
- `SYSTEM_NAME` — your branding
