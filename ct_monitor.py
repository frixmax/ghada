import websocket
import json
import time
import requests
import threading
from datetime import datetime, timedelta
from flask import Flask

app = Flask(__name__)

DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS"

DOMAINS_FILE = '/app/domains.txt'
RECENT_DAYS = 2
WS_URL = "wss://certstream.calidog.io/domains-only"

stats = {"connected": False, "last_heartbeat": "N/A", "alerts_sent": 0}

try:
    with open(DOMAINS_FILE, 'r') as f:
        targets = {line.strip().lower() for line in f if line.strip()}
    print(f"Surveillance de {len(targets)} domaines")
except Exception as e:
    print(f"Erreur domains.txt : {e}")
    targets = set()

def send_alert(matched):
    global stats
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
        stats["alerts_sent"] += 1
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
    stats["connected"] = True
    stats["last_heartbeat"] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    print("Connecté au flux CertStream domains-only !")

    # Test de démarrage : afficher 20 premiers certs
    print("=== TEST DE DÉMARRAGE : 20 premiers certificats ===")
    test_count = 0
    MAX_TEST = 20

    def test_handler(ws, message):
        nonlocal test_count
        try:
            data = json.loads(message)
            if data.get("message_type") != "certificate_update":
                return

            test_count += 1
            domains = data.get("data", {}).get("leaf_cert", {}).get("all_domains", [])
            not_before = data.get("data", {}).get("leaf_cert", {}).get("not_before", "N/A")

            print(f"Cert #{test_count}: Date {not_before} - Domaines {domains[:10]} {'...' if len(domains) > 10 else ''}")
            print("-" * 70)

            if test_count >= MAX_TEST:
                print("Test terminé. Passage au mode normal.")
                ws.on_message = on_message
        except:
            pass

    ws.on_message = test_handler

def on_error(ws, error):
    print(f"Erreur websocket : {error}")

def on_close(ws, code, msg):
    stats["connected"] = False
    print(f"Déconnexion ({code}): {msg}")

def heartbeat():
    while True:
        stats["last_heartbeat"] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        print(f"Heartbeat vivant : {stats['last_heartbeat']}")
        time.sleep(60)

threading.Thread(target=heartbeat, daemon=True).start()

# Page web simple
@app.route('/')
def home():
    status = "Connecté" if stats["connected"] else "Reconnexion..."
    return f"""
    <h1>Gungnir CT Monitor</h1>
    <p><strong>Status :</strong> {status}</p>
    <p><strong>Dernier heartbeat :</strong> {stats['last_heartbeat']}</p>
    <p><strong>Alertes envoyées :</strong> {stats['alerts_sent']}</p>
    <p><strong>Domaines surveillés :</strong> {len(targets)}</p>
    """

# Lancer Flask en thread séparé
def run_flask():
    app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)

threading.Thread(target=run_flask, daemon=True).start()

# Boucle websocket
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
