import websocket
import json
import time
import requests
import threading
from datetime import datetime, timedelta
from flask import Flask, jsonify

app = Flask(__name__)

# Ton webhook Discord
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS"

DOMAINS_FILE = '/app/domains.txt'
RECENT_DAYS = 2
WS_URL = "wss://certstream.calidog.io/domains-only"

# Stats globales pour la page web et debug
stats = {
    "connected": False,
    "last_heartbeat": "N/A",
    "alerts_sent": 0,
    "first_certs": []  # stocke les 20 premiers pour le test
}

# Charger domaines
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
            "footer": {"text": "Gungnir CT Monitor - CertStream"},
            "timestamp": datetime.utcnow().isoformat()
        }]
    }
    try:
        r = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        if r.status_code == 204:
            stats["alerts_sent"] += 1
            print("Alerte envoyée")
        else:
            print(f"Erreur Discord {r.status_code}: {r.text[:200]}")
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
    except Exception as e:
        print(f"Erreur parsing : {e}")

def on_open(ws):
    stats["connected"] = True
    stats["last_heartbeat"] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    print("Connecté au flux CertStream domains-only !")

    # Test de démarrage : afficher les 20 premiers certs
    print("=== TEST DE DÉMARRAGE : affichage des 20 premiers certificats ===")
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

            print(f"Cert #{test_count}:")
            print(f"  Date : {not_before}")
            print(f"  Domaines : {', '.join(domains[:10])} {'...' if len(domains) > 10 else ''}")
            print("-" * 70)

            if test_count >= MAX_TEST:
                print(f"\nTest terminé ({MAX_TEST} certs affichés). Monitoring normal activé.")
                ws.on_message = on_message  # repasse au mode normal

        except Exception as e:
            print(f"Erreur test : {e}")

    ws.on_message = test_handler  # active le test temporairement

def on_error(ws, error):
    print(f"Erreur websocket : {error}")

def on_close(ws, code, msg):
    stats["connected"] = False
    print(f"Déconnexion ({code}): {msg}. Reconnexion...")

def heartbeat():
    while True:
        stats["last_heartbeat"] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        print(f"Heartbeat : {stats['last_heartbeat']}")
        time.sleep(60)

# Mini page web pour Render
@app.route('/')
def home():
    status = "Connecté" if stats["connected"] else "Reconnexion..."
    return f"""
    <h1>Gungnir CT Monitor</h1>
    <p><strong>Status :</strong> {status}</p>
    <p><strong>Dernier heartbeat :</strong> {stats['last_heartbeat']}</p>
    <p><strong>Alertes envoyées :</strong> {stats['alerts_sent']}</p>
    <p><strong>Domaines surveillés :</strong> {len(targets)}</p>
    <hr>
    <p>Le script tourne en continu et surveille les nouveaux certificats.</p>
    """

# Lancer Flask en thread
def run_flask():
    app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)

threading.Thread(target=run_flask, daemon=True).start()
threading.Thread(target=heartbeat, daemon=True).start()

# Boucle websocket avec reconnexion auto
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
        print(f"Erreur globale : {e}. Reconnexion dans 5s...")
        time.sleep(5)
