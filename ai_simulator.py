import os
import random
import time

import requests

try:   # optional: share the server's .env file (WEBHOOK_API_KEY, WEBHOOK_URL)
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

WEBHOOK_URL = os.getenv("WEBHOOK_URL", "http://127.0.0.1:8000/api/ai_webhook")
# Must match WEBHOOK_API_KEY on the server (demo mode default: dev-webhook-key)
HEADERS = {"X-API-Key": os.getenv("WEBHOOK_API_KEY", "dev-webhook-key")}

BASE_URL = WEBHOOK_URL.rsplit("/api/", 1)[0]

# Offline fallback only. Normally the layout is read from the server (GET /api/cameras), the single source of truth.
FALLBACK_NEIGHBORS = {
    "Main Gate":      ["Lorong 1"],
    "Side Gate":      ["Lorong 3", "Lorong 4 East"],
    "Community Park": ["Lorong 1", "Lorong 4 West"],
    "Lorong 1":       ["Main Gate", "Community Park", "Lorong 4 West", "Lorong 2"],
    "Lorong 2":       ["Lorong 1", "Lorong 3", "Lorong 4 East"],
    "Lorong 3":       ["Side Gate", "Lorong 2"],
    "Lorong 4 West":  ["Lorong 1", "Community Park", "Lorong 4 East"],
    "Lorong 4 East":  ["Lorong 4 West", "Lorong 2", "Side Gate"],
}


def load_neighbors():
    try:
        r = requests.get(f"{BASE_URL}/api/cameras", headers=HEADERS, timeout=8)
        r.raise_for_status()
        return {c["name"]: c["neighbors"] for c in r.json()["cameras"]}
    except Exception as exc:
        print(f"[ℹ️ Using built-in camera layout] could not read {BASE_URL}/api/cameras ({exc})")
        return FALLBACK_NEIGHBORS


NEIGHBORS = load_neighbors()

IMAGES = {
    "suspicious_person": "https://images.unsplash.com/photo-1506794778202-cad84cf45f1d?w=200",
    "unregistered_vehicle": "https://images.unsplash.com/photo-1533473359331-0135ef1b58bf?w=200",
    "lost_pet": "https://images.unsplash.com/photo-1543466835-00a7907e9de1?w=200",
}

start_at = {"suspicious_person": "Side Gate", "unregistered_vehicle": "Main Gate", "lost_pet": "Community Park"}
target_positions = {t: (cam if cam in NEIGHBORS else next(iter(NEIGHBORS))) for t, cam in start_at.items()}
active_plate = f"DEMO-{random.randint(1000, 9999)}"

print("🚀 SimeGuard Edge AI Node Simulator Started! (Press Ctrl+C to stop)\n")

while True:
    alert_type = random.choice(list(IMAGES))

    # Step to a camera that is actually adjacent on the map
    location = random.choice(NEIGHBORS[target_positions[alert_type]])
    target_positions[alert_type] = location

    payload = {"type": alert_type, "location": location, "image_url": IMAGES[alert_type]}
    if alert_type == "unregistered_vehicle":
        payload["plate_number"] = active_plate

    try:
        response = requests.post(WEBHOOK_URL, json=payload, headers=HEADERS, timeout=8)
        if response.status_code == 401:
            print("[🔒 Rejected] Wrong or missing API key. Set WEBHOOK_API_KEY to match the server (dev-webhook-key only works while the server runs with DEMO_MODE=1).")
        elif response.status_code == 422:
            print(f"[❌ Rejected] Server validation failed: {response.text[:200]}")
        elif response.status_code == 200:
            res_data = response.json()
            if res_data.get("status") == "ignored":
                print(f"[⏳ Debounced] {alert_type} at {location} (Duplicate suppressed)")
            else:
                print(f"[✅ Alert Sent] Detected {alert_type} at {location} ({res_data.get('timestamp')})")
        else:
            print(f"[❌ Failed to Send] Status Code: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("[⚠️ Connection Error] Backend seems down. Please ensure Uvicorn is running on port 8000!")
    except requests.exceptions.RequestException as exc:
        print(f"[⚠️ Request Error] {exc}")

    time.sleep(random.randint(4, 7))