#!/usr/bin/env python3
"""
Monitoring Certificate Transparency - API Google directe
Plus fiable que CertStream
"""

import requests
import json
import time
import os
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

print("=== MONITORING CT via Google API ===")
print(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

# Configuration
PORT = int(os.environ.get('PORT', 10000))
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK', "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS")
DOMAINS_FILE = '/app/domains.txt'
CHECK_INTERVAL = 60  # Vérifier toutes les 60 secondes
BATCH_SIZE = 256  # Nombre d'entrées à récupérer par requête

# Logs CT Google à surveiller (les plus actifs)
CT_LOGS = [
    {
        "name": "Google Argon 2026",
        "url": "https://ct.googleapis.com/logs/us1/argon2026h1",
        "enabled": True
    },
    {
        "name": "Google Xenon 2026", 
        "url": "https://ct.googleapis.com/logs/us1/xenon2026h1",
        "enabled": True
    }
]

# Stats
stats = {
    'certificats_analysés': 0,
    'alertes_envoyées': 0,
    'dernière_alerte': None,
    'démarrage': datetime.utcnow(),
    'dernière_vérification': None,
    'positions': {}
}

# Chargement des domaines
try:
    with open(DOMAINS_FILE, 'r') as f:
        targets = {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
    print(f"✓ {len(targets)} domaines chargés")
    if targets:
        print(f"  Exemples: {', '.join(list(targets)[:3])}")
except Exception as e:
    print(f"✗ Erreur chargement domaines: {e}")
    targets = set()

if not targets:
    print("✗ ERREUR: Aucun domaine à surveiller")
    exit(1)

# Validation webhook
if "discord.com/api/webhooks" not in DISCORD_WEBHOOK:
    print("✗ ERREUR: Webhook Discord invalide")
    exit(1)
print(f"✓ Webhook Discord configuré")

class HealthCheckHandler(BaseHTTPRequestHandler):
    """Handler HTTP pour health checks"""
    
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        if self.path == '/health' or self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            uptime = (datetime.utcnow() - stats['démarrage']).total_seconds()
            
            status = {
                'status': 'healthy',
                'uptime_seconds': int(uptime),
                'certificats_analysés': stats['certificats_analysés'],
                'alertes_envoyées': stats['alertes_envoyées'],
                'dernière_alerte': stats['dernière_alerte'].isoformat() if stats['dernière_alerte'] else None,
                'dernière_vérification': stats['dernière_vérification'].isoformat() if stats['dernière_vérification'] else None,
                'timestamp': datetime.utcnow().isoformat(),
                'logs_positions': stats['positions']
            }
            
            self.wfile.write(json.dumps(status, indent=2).encode())
        else:
            self.send_response(404)
            self.end_headers()

def start_http_server():
    """Démarre le serveur HTTP"""
    server = HTTPServer(('0.0.0.0', PORT), HealthCheckHandler)
    print(f"✓ Serveur HTTP démarré sur le port {PORT}")
    server.serve_forever()

def get_sth(log_url):
    """Récupère le Signed Tree Head (taille actuelle du log)"""
    try:
        response = requests.get(f"{log_url}/ct/v1/get-sth", timeout=10)
        response.raise_for_status()
        return response.json()['tree_size']
    except Exception as e:
        print(f"✗ Erreur STH {log_url}: {e}")
        return None

def get_entries(log_url, start, end):
    """Récupère les entrées CT"""
    try:
        response = requests.get(
            f"{log_url}/ct/v1/get-entries",
            params={"start": start, "end": end},
            timeout=30
        )
        response.raise_for_status()
        return response.json().get('entries', [])
    except Exception as e:
        print(f"✗ Erreur entrées {log_url}: {e}")
        return []

def parse_certificate(entry):
    """Parse un certificat pour extraire les domaines"""
    try:
        # Le certificat est dans leaf_input encodé en base64
        from base64 import b64decode
        
        leaf_input = entry.get('leaf_input', '')
        extra_data = entry.get('extra_data', '')
        
        # Conversion simplifiée - recherche de patterns de domaines
        # Pour une version complète, il faudrait parser le X.509
        
        domains = []
        
        # Recherche dans les données brutes
        data_str = str(leaf_input) + str(extra_data)
        
        for target in targets:
            if target in data_str.lower():
                domains.append(target)
        
        return list(set(domains))
        
    except Exception as e:
        return []

def send_alert(matched_domains, log_name):
    """Envoie une alerte Discord"""
    try:
        description = "\n".join([f"• `{d}`" for d in sorted(set(matched_domains))[:20]])
        
        if len(matched_domains) > 20:
            description += f"\n\n... et {len(matched_domains) - 20} autre(s)"
        
        embed = {
            "title": f"🚨 Nouveau certificat SSL détecté",
            "description": description,
            "color": 0xff0000,
            "fields": [
                {
                    "name": "Nombre de domaines",
                    "value": str(len(matched_domains)),
                    "inline": True
                },
                {
                    "name": "Source",
                    "value": log_name,
                    "inline": True
                }
            ],
            "footer": {"text": "CT Monitor (Google API)"},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        payload = {"embeds": [embed]}
        response = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        response.raise_for_status()
        
        stats['alertes_envoyées'] += 1
        stats['dernière_alerte'] = datetime.utcnow()
        print(f"✓ Alerte envoyée: {len(matched_domains)} domaine(s)")
        
    except Exception as e:
        print(f"✗ Erreur Discord: {e}")

def monitor_log(log_config):
    """Surveille un log CT"""
    log_name = log_config['name']
    log_url = log_config['url']
    
    # Initialiser la position si nécessaire
    if log_name not in stats['positions']:
        tree_size = get_sth(log_url)
        if tree_size:
            # Commencer aux 1000 dernières entrées
            stats['positions'][log_name] = max(0, tree_size - 1000)
            print(f"✓ Init {log_name}: position {stats['positions'][log_name]}")
        else:
            return
    
    # Récupérer la taille actuelle
    tree_size = get_sth(log_url)
    if not tree_size:
        return
    
    current_pos = stats['positions'][log_name]
    
    if current_pos >= tree_size:
        return  # Rien de nouveau
    
    # Limiter le nombre d'entrées à traiter
    end_pos = min(current_pos + BATCH_SIZE, tree_size)
    
    print(f"🔍 {log_name}: vérification {current_pos} → {end_pos - 1}")
    
    # Récupérer les entrées
    entries = get_entries(log_url, current_pos, end_pos - 1)
    
    for entry in entries:
        stats['certificats_analysés'] += 1
        
        # Parser pour trouver des domaines matchés
        matched = parse_certificate(entry)
        
        if matched:
            send_alert(matched, log_name)
    
    # Mettre à jour la position
    stats['positions'][log_name] = end_pos
    
    # Log de progression
    if stats['certificats_analysés'] % 100 == 0:
        print(f"📊 {stats['certificats_analysés']} certificats analysés")

# Démarrer le serveur HTTP
http_thread = threading.Thread(target=start_http_server, daemon=True)
http_thread.start()
time.sleep(1)

print("\n🔄 Démarrage de la surveillance...")

# Boucle principale
while True:
    try:
        stats['dernière_vérification'] = datetime.utcnow()
        
        for log_config in CT_LOGS:
            if log_config['enabled']:
                monitor_log(log_config)
        
        # Attendre avant la prochaine vérification
        time.sleep(CHECK_INTERVAL)
        
    except KeyboardInterrupt:
        print("\n⚠️  Arrêt demandé")
        break
    except Exception as e:
        print(f"✗ Erreur globale: {e}")
        time.sleep(30)

print("=== ARRÊT DU MONITORING ===")
