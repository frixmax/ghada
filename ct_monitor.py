import websocket
import json
import time
import requests
import threading
from datetime import datetime, timedelta

print("=== DÉMARRAGE MONITORING CERTSTREAM (Background Worker) ===")

DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS"

DOMAINS_FILE = '/app/domains.txt'
RECENT_DAYS = 2
WS_URL = "wss://certstream.calidog.io/domains-only"

try:
    with open(DOMAINS_FILE, 'r') as f:
        targets = {line.strip().lower() for line in f if line.strip()}
    print(f"Domaines surveillés : {len(targets)}")
except Exception as e:
    print(f"Erreur domains.txt : {e}")
    targets = set()

def send_alert(matched):
    payload = {
        "embeds": [{
            "title": f"🚨 Nouveau certificat ({len(matched)} domaines)",
            "description": "\n".join(sorted(matched)[:15]),
            "color": 0xff0000,
            "footer": {"text": "Gungnir CT Monitor"},
            "timestamp": datetime.utcnow().isoformat()
        }]
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        print("Alerte envoyée")
    except Exception as e:
        print(f"Erreur Discord : {e}")

def on_message(ws, message):
    try:
        data = json.loads(message)
        if data.get("message_type") != "certificate_update":
            return

        domains = [d.lower() for d in data.get("data", {}).get("leaf_cert", {}).get("all_domains", [])]
        domains_str = " ".join(domains)

        if not any(t in domains_str for t in targets):
            return

        not_before_str = data["data"]["leaf_cert"].get("not_before")
        if not_before_str:
            try:
                not_before = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))
                if (datetime.utcnow() - not_before).days > RECENT_DAYS:
                    return
            except:
                pass

        matched = [d for d in domains if any(t in d for t in targets)]
        if matched:
            send_alert(list(set(matched)))
    except:
        pass

def on_open(ws):
    print("Connecté au flux CertStream !")

def on_error(ws, error):
    print(f"Erreur websocket : {error}")

def on_close(ws, code, msg):
    print(f"Déconnexion ({code}): {msg}")

def heartbeat():
    while True:
        print(f"Vivant - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        time.sleep(60)

threading.Thread(target=heartbeat, daemon=True).start()

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
