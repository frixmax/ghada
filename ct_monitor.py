#!/usr/bin/env python3
import websocket
import json
import time
import requests
import threading
from datetime import datetime, timedelta
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
import os

print("=== DÉMARRAGE MONITORING CERTSTREAM ===")
print(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

# Port pour Render (requis)
PORT = int(os.environ.get('PORT', 10000))

# Configuration
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK', "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS")
DOMAINS_FILE = '/app/domains.txt'
RECENT_DAYS = 2
WS_URL = "wss://certstream.calidog.io/"
MAX_RECONNECT_DELAY = 60
reconnect_delay = 5

# Chargement des domaines à surveiller
try:
    with open(DOMAINS_FILE, 'r') as f:
        targets = {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
    print(f"✓ {len(targets)} domaines chargés pour surveillance")
    if targets:
        print(f"  Exemples: {', '.join(list(targets)[:3])}")
except FileNotFoundError:
    print(f"✗ ERREUR: Fichier {DOMAINS_FILE} introuvable")
    sys.exit(1)
except Exception as e:
    print(f"✗ Erreur lors du chargement de domains.txt: {e}")
    sys.exit(1)

if not targets:
    print("✗ ERREUR: Aucun domaine à surveiller")
    sys.exit(1)

# Validation du webhook Discord
if not DISCORD_WEBHOOK or DISCORD_WEBHOOK == "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS":
    print("⚠️  ATTENTION: Utilisez votre propre webhook Discord!")
if "discord.com/api/webhooks" not in DISCORD_WEBHOOK:
    print("✗ ERREUR: Le webhook Discord semble invalide")
    sys.exit(1)
print(f"✓ Webhook Discord configuré")

# Stats
stats = {
    'certificats_analysés': 0,
    'alertes_envoyées': 0,
    'dernière_alerte': None,
    'connexion': None,
    'démarrage': datetime.utcnow(),
    'reconnexions': 0,
    'dernière_reconnexion': None
}

class HealthCheckHandler(BaseHTTPRequestHandler):
    """Handler HTTP simple pour les health checks de Render"""
    
    def log_message(self, format, *args):
        """Supprime les logs HTTP standards"""
        pass
    
    def do_GET(self):
        """Répond aux requêtes GET"""
        if self.path == '/health' or self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            uptime = (datetime.utcnow() - stats['démarrage']).total_seconds()
            current_session = 0
            if stats['connexion']:
                current_session = (datetime.utcnow() - stats['connexion']).total_seconds()
            
            status = {
                'status': 'healthy',
                'uptime_seconds': int(uptime),
                'current_session_seconds': int(current_session),
                'certificats_analysés': stats['certificats_analysés'],
                'alertes_envoyées': stats['alertes_envoyées'],
                'reconnexions': stats['reconnexions'],
                'dernière_alerte': stats['dernière_alerte'].isoformat() if stats['dernière_alerte'] else None,
                'connecté': stats['connexion'] is not None,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.wfile.write(json.dumps(status, indent=2).encode())
        else:
            self.send_response(404)
            self.end_headers()

def start_http_server():
    """Démarre le serveur HTTP pour Render"""
    server = HTTPServer(('0.0.0.0', PORT), HealthCheckHandler)
    print(f"✓ Serveur HTTP démarré sur le port {PORT}")
    server.serve_forever()

def send_alert(matched, cert_info=None):
    """Envoie une alerte Discord avec les domaines matchés"""
    try:
        description = "\n".join([f"• `{d}`" for d in sorted(set(matched))[:20]])
        
        if len(matched) > 20:
            description += f"\n\n... et {len(matched) - 20} autre(s) domaine(s)"
        
        embed = {
            "title": f"🚨 Nouveau certificat SSL détecté",
            "description": description,
            "color": 0xff0000,
            "fields": [
                {
                    "name": "Nombre de domaines",
                    "value": str(len(matched)),
                    "inline": True
                }
            ],
            "footer": {"text": "Gungnir CT Monitor"},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if cert_info:
            if cert_info.get('not_before'):
                embed["fields"].append({
                    "name": "Date émission",
                    "value": cert_info['not_before'],
                    "inline": True
                })
            if cert_info.get('issuer'):
                embed["fields"].append({
                    "name": "Émetteur",
                    "value": cert_info['issuer'][:100],
                    "inline": False
                })
        
        payload = {"embeds": [embed]}
        
        response = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        response.raise_for_status()
        
        stats['alertes_envoyées'] += 1
        stats['dernière_alerte'] = datetime.utcnow()
        print(f"✓ Alerte envoyée: {len(matched)} domaine(s) - Total alertes: {stats['alertes_envoyées']}")
        
    except requests.exceptions.RequestException as e:
        print(f"✗ Erreur Discord (réseau): {e}")
    except Exception as e:
        print(f"✗ Erreur Discord (inattendue): {e}")

def on_message(ws, message):
    """Traite les messages reçus du flux CertStream"""
    try:
        data = json.loads(message)
        
        # Debug: log le premier message reçu
        if stats['certificats_analysés'] == 0:
            print(f"📥 Premier message reçu - Type: {data.get('message_type')}")
        
        # On ne traite que les mises à jour de certificats
        if data.get("message_type") != "certificate_update":
            return
        
        stats['certificats_analysés'] += 1
        
        # Log tous les 100 certificats
        if stats['certificats_analysés'] % 100 == 0:
            print(f"📊 {stats['certificats_analysés']} certificats analysés")
        
        leaf_cert = data.get("data", {}).get("leaf_cert", {})
        all_domains = leaf_cert.get("all_domains", [])
        
        if not all_domains:
            return
        
        # Normalisation des domaines
        domains = [d.lower().strip() for d in all_domains]
        domains_str = " ".join(domains)
        
        # Vérification rapide si un de nos targets est présent
        if not any(target in domains_str for target in targets):
            return
        
        # Filtrage par date si spécifié
        not_before_str = leaf_cert.get("not_before")
        if not_before_str and RECENT_DAYS > 0:
            try:
                # Format: timestamp Unix ou ISO
                if isinstance(not_before_str, (int, float)):
                    not_before = datetime.fromtimestamp(not_before_str)
                else:
                    not_before = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))
                
                age_days = (datetime.utcnow() - not_before.replace(tzinfo=None)).days
                if age_days > RECENT_DAYS:
                    return
            except Exception as e:
                # En cas d'erreur de parsing, on continue quand même
                pass
        
        # Identification des domaines qui matchent exactement
        matched = []
        for domain in domains:
            for target in targets:
                if target in domain:
                    matched.append(domain)
                    break
        
        if matched:
            cert_info = {
                'not_before': not_before_str,
                'issuer': leaf_cert.get("issuer", {}).get("CN", "Inconnu")
            }
            send_alert(matched, cert_info)
            
    except json.JSONDecodeError:
        pass
    except Exception as e:
        print(f"✗ Erreur traitement message: {e}")

def on_open(ws):
    """Callback lors de la connexion"""
    global reconnect_delay
    reconnect_delay = 5
    
    # Compter les reconnexions (sauf la première)
    if stats['connexion'] is not None:
        stats['reconnexions'] += 1
        stats['dernière_reconnexion'] = datetime.utcnow()
    
    stats['connexion'] = datetime.utcnow()
    print(f"✓ Connecté au flux CertStream à {stats['connexion'].strftime('%H:%M:%S UTC')}")
    print(f"  Attente de messages...")

def on_error(ws, error):
    """Callback en cas d'erreur"""
    # Ne log que les vraies erreurs, pas les fermetures normales
    error_str = str(error)
    if "Connection to remote host was lost" not in error_str:
        print(f"✗ Erreur WebSocket: {error}")

def on_close(ws, close_status_code, close_msg):
    """Callback lors de la fermeture"""
    if close_status_code and close_status_code != 1000:  # 1000 = fermeture normale
        print(f"⚠ Connexion fermée (code: {close_status_code})")
        if close_msg:
            print(f"   Message: {close_msg}")

def heartbeat():
    """Thread qui affiche régulièrement l'état du monitoring"""
    while True:
        time.sleep(300)  # Toutes les 5 minutes
        uptime = "N/A"
        if stats['connexion']:
            uptime_seconds = (datetime.utcnow() - stats['connexion']).total_seconds()
            uptime = f"{int(uptime_seconds // 3600)}h {int((uptime_seconds % 3600) // 60)}m"
        
        print(f"\n--- Statistiques ---")
        print(f"  Uptime: {uptime}")
        print(f"  Certificats analysés: {stats['certificats_analysés']}")
        print(f"  Alertes envoyées: {stats['alertes_envoyées']}")
        print(f"  Reconnexions: {stats['reconnexions']}")
        if stats['dernière_alerte']:
            print(f"  Dernière alerte: {stats['dernière_alerte'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"--------------------\n")

# Démarrage du thread de heartbeat
threading.Thread(target=heartbeat, daemon=True).start()

# Démarrage du serveur HTTP pour Render (obligatoire)
http_thread = threading.Thread(target=start_http_server, daemon=True)
http_thread.start()
time.sleep(1)  # Laisser le serveur démarrer

# Test de connectivité CertStream
print("\n🧪 Test de connectivité CertStream...")
try:
    test_response = requests.get("https://certstream.calidog.io/", timeout=5)
    print(f"✓ CertStream accessible (status: {test_response.status_code})")
except Exception as e:
    print(f"⚠️  Avertissement: Impossible de contacter CertStream via HTTP: {e}")

# Boucle principale de reconnexion
print("\n🔄 Démarrage de la surveillance...")
connection_attempts = 0
last_connection_time = None

while True:
    try:
        connection_attempts += 1
        
        # Log seulement si déconnexion depuis plus de 30 secondes
        if last_connection_time is None or (datetime.utcnow() - last_connection_time).total_seconds() > 30:
            print(f"⚡ Tentative de connexion à {WS_URL}... (essai #{connection_attempts})")
        
        ws = websocket.WebSocketApp(
            WS_URL,
            on_message=on_message,
            on_open=on_open,
            on_error=on_error,
            on_close=on_close
        )
        
        last_connection_time = datetime.utcnow()
        
        # run_forever bloque jusqu'à déconnexion
        # Ping plus fréquent et timeout plus court pour détecter les déconnexions rapidement
        ws.run_forever(
            ping_interval=20,  # Ping toutes les 20s au lieu de 30s
            ping_timeout=8,    # Timeout de 8s au lieu de 10s
            reconnect=3        # Essaie de se reconnecter 3 fois automatiquement
        )
        
    except KeyboardInterrupt:
        print("\n⚠ Arrêt demandé par l'utilisateur")
        break
    except Exception as e:
        print(f"✗ Erreur globale: {e}")
    
    # Petite pause avant reconnexion (pas de backoff exponentiel, reconnexion rapide)
    time.sleep(2)

print("=== ARRÊT DU MONITORING ===")
