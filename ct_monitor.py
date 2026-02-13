import websocket
import json
import time
import requests
import threading
from datetime import datetime, timedelta

DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS"

DOMAINS_FILE = '/app/domains.txt'
RECENT_DAYS = 2
WS_URL = "wss://certstream.calidog.io/domains-only"

print("=== DÉMARRAGE DU SCRIPT DEBUG ===")

try:
    with open(DOMAINS_FILE, 'r') as f:
        targets = {line.strip().lower() for line in f if line.strip()}
    print(f"Domaines chargés : {len(targets)} ({', '.join(sorted(targets))})")
except Exception as e:
    print(f"ERREUR domains.txt : {e}")
    targets = set()

def send_alert(matched):
    print(f"ALERTE POTENTIELLE : {matched}")
    payload = {
        "embeds": [{
            "title": f"🚨 TEST ALERT ({len(matched)} domaines)",
            "description": "\n".join(sorted(matched)),
            "color": 0xff0000,
            "footer": {"text": "DEBUG MODE"},
            "timestamp": datetime.utcnow().isoformat()
        }]
    }
    try:
        r = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        print(f"Discord réponse : {r.status_code} - {r.text[:100]}")
    except Exception as e:
        print(f"Erreur Discord : {e}")

def on_message(ws, message):
    print(f"Message reçu (raw) : {message[:300]}...")  # log brut
    try:
        data = json.loads(message)
        msg_type = data.get("message_type")
        print(f"Type de message : {msg_type}")
        if msg_type == "heartbeat":
            print("Heartbeat reçu")
        elif msg_type == "certificate_update":
            domains = data.get("data", {}).get("leaf_cert", {}).get("all_domains", [])
            print(f"Certificat reçu - Domaines : {domains[:5]}...")
            # ... le reste du filtre
        else:
            print("Autre type de message")
    except Exception as e:
        print(f"Erreur parsing JSON : {e}")

def on_open(ws):
    print("=== WEBSOCKET OUVERT AVEC SUCCÈS ===")
    print("En attente de messages (heartbeats ou certs)...")

def on_error(ws, error):
    print(f"Erreur websocket : {error}")

def on_close(ws, code, msg):
    print(f"Déconnexion ({code}): {msg}. Reconnexion dans 5s...")

def heartbeat_log():
    while True:
        print(f"Script toujours vivant - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        time.sleep(60)

threading.Thread(target=heartbeat_log, daemon=True).start()

while True:
    try:
        ws = websocket.WebSocketApp(
            WS_URL,
            on_message=on_message,
            on_open=on_open,
            on_error=on_error,
            on_close=on_close
        )
        ws.run_forever(ping_interval=30, ping_timeout=10)
    except Exception as e:
        print(f"Erreur globale : {e}")
        time.sleep(5)
