import websocket
import json
import time
import requests
import os
from datetime import datetime, timedelta

# Ton webhook Discord (copié directement)
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS"

DOMAINS_FILE = '/app/domains.txt'
RECENT_DAYS = 2  # Ignore les certs plus vieux que 2 jours
WS_URL = "wss://certstream.calidog.io/domains-only"  # Flux léger (recommandé)

# Charger les domaines à surveiller
try:
    with open(DOMAINS_FILE, 'r') as f:
        targets = {line.strip().lower() for line in f if line.strip()}
    print(f"Surveillance de {len(targets)} domaines : {', '.join(sorted(targets))}")
except FileNotFoundError:
    print("ERREUR : domains.txt introuvable !")
    targets = set()
    exit(1)

def send_discord_alert(matched_domains):
    payload = {
        "embeds": [{
            "title": f"🚨 Nouveau certificat détecté ({len(matched_domains)} domaines)",
            "description": "\n".join(sorted(matched_domains)[:20]),
            "color": 0xff0000,
            "footer": {"text": "Gungnir CT Monitor - CertStream"},
            "timestamp": datetime.utcnow().isoformat()
        }]
    }
    try:
        r = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        if r.status_code == 204:
            print("Alerte Discord envoyée avec succès")
        else:
            print(f"Erreur Discord {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"Erreur envoi Discord : {e}")

def on_message(ws, message):
    try:
        data = json.loads(message)
        if data.get("message_type") != "certificate_update":
            return

        domains = [d.lower() for d in data.get("data", {}).get("leaf_cert", {}).get("all_domains", [])]
        domains_str = " ".join(domains)

        # Filtre rapide (économie CPU/bande)
        if not any(t in domains_str for t in targets):
            return

        # Filtre date d'émission
        not_before_str = data["data"]["leaf_cert"].get("not_before")
        if not_before_str:
            try:
                not_before = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))
                if (datetime.utcnow() - not_before).days > RECENT_DAYS:
                    return
            except:
                pass  # date invalide → on continue

        # Match réel
        matched = [d for d in domains if any(t in d for t in targets)]
        if matched:
            send_discord_alert(list(set(matched)))

    except Exception as e:
        print(f"Erreur parsing message : {e}")

def on_open(ws):
    print("Connecté au flux CertStream domains-only ! Ping auto toutes 30s.")

def on_error(ws, error):
    print(f"Erreur websocket : {error}")

def on_close(ws, code, msg):
    print(f"Déconnexion ({code}): {msg}. Reconnexion dans 10s...")

ws = websocket.WebSocketApp(
    WS_URL,
    on_message=on_message,
    on_open=on_open,
    on_error=on_error,
    on_close=on_close
)

ws.run_forever(ping_interval=30, ping_timeout=10)
