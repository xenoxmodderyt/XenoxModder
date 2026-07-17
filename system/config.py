"""
Proxy System Configuration
"""
import os

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_BASE_DIR, "data")

# Admin password for web panel (change this!)
ADMIN_PASSWORD = "changeme123"

# Pricing (in USD)
PRICING = {
    "day": 1.0,
    "week": 3.0,
    "month": 5.0
}

# Duration in days
DURATIONS = {
    "day": 1,
    "week": 7,
    "month": 30
}

# Files
DB_FILE = os.path.join(_DATA_DIR, "database.json")
IPS_FILE = os.path.join(_DATA_DIR, "allowed_ips.json")
KEYS_FILE = os.path.join(_DATA_DIR, "license_keys.json")

# Settings
MAX_KEYS_PER_ADMIN = 1000
IP_API_URL = "https://api.ipify.org?format=json"
SYSTEM_NAME = "Proxy System"
