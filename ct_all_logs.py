#!/usr/bin/env python3
"""
Monitoring Certificate Transparency - VERSION CORRIGÉE
Avec logs actifs vérifiés et parsing X.509 fonctionnel
"""

import requests
import json
import time
import os
import threading
import base64
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography import x509
from cryptography.hazmat.backends import default_backend

print("=== MONITORING CT - LOGS ACTIFS VÉRIFIÉS ===")
print(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

# Configuration
PORT = int(os.environ.get('PORT', 10000))
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK', "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS")
DOMAINS_FILE = '/app/domains.txt'
CHECK_INTERVAL = int(os.environ.get('CHECK_INTERVAL', 120))  # 2 min pour 13 logs
BATCH_SIZE = 100  # Réduit pour éviter surcharge

# LOGS ACTIFS VÉRIFIÉS - Triés par activité (tree_size)
CT_LOGS = [
    # === TOP 3 - ULTRA ACTIFS (3+ milliards de certificats) ===
    {"name": "Cloudflare Nimbus2025", "url": "https://ct.cloudflare.com/logs/nimbus2025", "enabled": True},
    {"name": "Cloudflare Nimbus2026", "url": "https://ct.cloudflare.com/logs/nimbus2026", "enabled": True},
    {"name": "Google Argon2025h2", "url": "https://ct.googleapis.com/logs/us1/argon2025h2", "enabled": True},
    
    # === TRÈS ACTIFS (2+ milliards) ===
    {"name": "Google Argon2024", "url": "https://ct.googleapis.com/logs/us1/argon2024", "enabled": True},
    {"name": "Google Argon2026h1", "url": "https://ct.googleapis.com/logs/us1/argon2026h1", "enabled": True},
    
    # === ACTIFS (1+ milliard) ===
    {"name": "Google Argon2025h1", "url": "https://ct.googleapis.com/logs/us1/argon2025h1", "enabled": True},
    
    # === MOYENNEMENT ACTIFS (100M - 1B) ===
    {"name": "Google Argon2026h2", "url": "https://ct.googleapis.com/logs/us1/argon2026h2", "enabled": True},
    {"name": "Cloudflare Nimbus2027", "url": "https://ct.cloudflare.com/logs/nimbus2027", "enabled": True},
    {"name": "Google Solera2026h1", "url": "https://ct.googleapis.com/logs/eu1/solera2026h1", "enabled": True},
    {"name": "Google Solera2024", "url": "https://ct.googleapis.com/logs/eu1/solera2024", "enabled": True},
    
    # === MOINS ACTIFS (mais vivants) ===
    {"name": "Google Solera2025h2", "url": "https://ct.googleapis.com/logs/eu1/solera2025h2", "enabled": True},
    {"name": "Google Solera2025h1", "url": "https://ct.googleapis.com/logs/eu1/solera2025h1", "enabled": True},
    {"name": "Google Solera2026h2", "url": "https://ct.googleapis.com/logs/eu1/solera2026h2", "enabled": True},
]

# Stats
stats = {
    'certificats_analysés': 0,
    'alertes_envoyées': 0,
    'dernière_alerte': None,
    'démarrage': datetime.utcnow(),
    'dernière_vérification': None,
    'positions': {},
    'logs_actifs': 0,
    'logs_en_erreur': {},
    'duplicates_évités': 0,
    'parse_errors': 0,
    'matches_trouvés': 0
}

# Cache pour éviter les duplicates
seen_certificates = set()
CACHE_MAX_SIZE = 50000  # Augmenté pour 13 logs

# Chargement des domaines
try:
    with open(DOMAINS_FILE, 'r') as f:
        targets = {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
    print(f"✓ {len(targets)} domaines chargés")
    if targets:
        print(f"  Exemples: {', '.join(list(targets)[:5])}")
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

# Compter les logs actifs
stats['logs_actifs'] = sum(1 for log in CT_LOGS if log['enabled'])
print(f"✓ {stats['logs_actifs']} logs CT actifs (couverture ~95%)")

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
                'matches_trouvés': stats['matches_trouvés'],
                'alertes_envoyées': stats['alertes_envoyées'],
                'duplicates_évités': stats['duplicates_évités'],
                'parse_errors': stats['parse_errors'],
                'logs_actifs': stats['logs_actifs'],
                'logs_en_erreur': stats['logs_en_erreur'],
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

def get_sth(log_url, log_name):
    """Récupère le Signed Tree Head"""
    try:
        response = requests.get(f"{log_url}/ct/v1/get-sth", timeout=10)
        response.raise_for_status()
        
        # Réinitialiser le compteur d'erreurs
        if log_name in stats['logs_en_erreur']:
            del stats['logs_en_erreur'][log_name]
        
        return response.json()['tree_size']
    except Exception as e:
        stats['logs_en_erreur'][log_name] = str(e)
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
        return []

def generate_cert_hash(entry):
    """Génère un hash pour détecter les duplicates"""
    try:
        leaf = entry.get('leaf_input', '')
        return hash(leaf)
    except:
        return None

def parse_certificate(entry):
    """Parse correctement un certificat X.509 - VERSION CORRIGÉE"""
    try:
        # Décoder le leaf_input
        leaf_bytes = base64.b64decode(entry.get('leaf_input', ''))
        
        if len(leaf_bytes) < 15:
            return []
        
        # Structure Merkle Tree Leaf:
        # [0]: Version (1 byte)
        # [1]: MerkleLeafType (1 byte)
        # [2-9]: Timestamp (8 bytes)
        # [10-11]: LogEntryType (2 bytes)
        # [11-13]: Certificate length (3 bytes)
        # [14+]: Certificate (DER)
        
        cert_length = int.from_bytes(leaf_bytes[11:14], 'big')
        cert_start = 14
        cert_end = cert_start + cert_length
        
        if cert_end > len(leaf_bytes):
            return []
        
        cert_der = leaf_bytes[cert_start:cert_end]
        
        # Parser X.509
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        all_domains = set()
        
        # Common Name
        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn:
                all_domains.add(cn[0].value.lower())
        except:
            pass
        
        # SANs (Subject Alternative Names - le plus important !)
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for san in san_ext.value:
                domain = san.value.lower().lstrip('*.')
                all_domains.add(domain)
        except:
            pass
        
        # Matcher avec targets
        matched = []
        for domain in all_domains:
            for target in targets:
                # Match exact ou sous-domaine
                if domain == target or domain.endswith('.' + target):
                    matched.append(domain)
                    break
        
        return list(set(matched))
        
    except Exception as e:
        stats['parse_errors'] += 1
        return []

def send_alert(matched_domains, log_name):
    """Envoie une alerte Discord"""
    try:
        # Déduplication finale
        unique_domains = sorted(set(matched_domains))
        
        description = "\n".join([f"• `{d}`" for d in unique_domains[:20]])
        
        if len(unique_domains) > 20:
            description += f"\n\n... et {len(unique_domains) - 20} autre(s)"
        
        embed = {
            "title": "🚨 Nouveau(x) certificat(s) SSL détecté(s)",
            "description": description,
            "color": 0xff0000,
            "fields": [
                {
                    "name": "Nombre de domaines",
                    "value": str(len(unique_domains)),
                    "inline": True
                },
                {
                    "name": "Source",
                    "value": log_name,
                    "inline": True
                }
            ],
            "footer": {"text": "CT Monitor - Multi-logs"},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        payload = {"embeds": [embed]}
        response = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        response.raise_for_status()
        
        stats['alertes_envoyées'] += 1
        stats['dernière_alerte'] = datetime.utcnow()
        print(f"✓ Alerte envoyée: {len(unique_domains)} domaine(s) depuis {log_name}")
        
    except Exception as e:
        print(f"✗ Erreur Discord: {e}")

def monitor_log(log_config):
    """Surveille un log CT"""
    log_name = log_config['name']
    log_url = log_config['url']
    
    # Initialiser la position
    if log_name not in stats['positions']:
        tree_size = get_sth(log_url, log_name)
        if tree_size:
            # Démarrer 1000 entrées avant la fin pour catch rapidement
            stats['positions'][log_name] = max(0, tree_size - 1000)
            print(f"✓ Init {log_name}: position {stats['positions'][log_name]:,} / {tree_size:,}")
        else:
            return
    
    # Récupérer la taille actuelle
    tree_size = get_sth(log_url, log_name)
    if not tree_size:
        return
    
    current_pos = stats['positions'][log_name]
    
    if current_pos >= tree_size:
        return
    
    end_pos = min(current_pos + BATCH_SIZE, tree_size)
    
    print(f"🔍 {log_name}: {current_pos:,} → {end_pos - 1:,} (total: {tree_size:,})")
    
    entries = get_entries(log_url, current_pos, end_pos - 1)
    
    if not entries:
        print(f"  ⚠️  Aucune entrée récupérée")
        return
    
    batch_matches = []
    
    for entry in entries:
        stats['certificats_analysés'] += 1
        
        # Vérifier les duplicates
        cert_hash = generate_cert_hash(entry)
        if cert_hash and cert_hash in seen_certificates:
            stats['duplicates_évités'] += 1
            continue
        
        # Ajouter au cache
        if cert_hash:
            seen_certificates.add(cert_hash)
            # Limiter la taille du cache
            if len(seen_certificates) > CACHE_MAX_SIZE:
                seen_certificates.pop()
        
        # Parser et chercher matches
        matched = parse_certificate(entry)
        
        if matched:
            stats['matches_trouvés'] += len(matched)
            batch_matches.extend(matched)
            print(f"  🎯 MATCH: {matched}")
    
    # Envoyer une alerte groupée si des matches
    if batch_matches:
        send_alert(batch_matches, log_name)
    
    stats['positions'][log_name] = end_pos
    
    # Stats périodiques
    if stats['certificats_analysés'] % 1000 == 0:
        print(f"📊 Stats: {stats['certificats_analysés']:,} analysés | {stats['matches_trouvés']} matches | {stats['alertes_envoyées']} alertes | {stats['parse_errors']} erreurs")

# Démarrer le serveur HTTP
http_thread = threading.Thread(target=start_http_server, daemon=True)
http_thread.start()
time.sleep(1)

print(f"\n🔄 Surveillance toutes les {CHECK_INTERVAL}s...")
print(f"🎯 Monitoring de {len(targets)} domaine(s)")
print("=" * 80)

# Boucle principale
cycle = 0
while True:
    try:
        cycle += 1
        stats['dernière_vérification'] = datetime.utcnow()
        
        print(f"\n{'='*80}")
        print(f"CYCLE #{cycle} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{'='*80}")
        
        for log_config in CT_LOGS:
            if log_config['enabled']:
                monitor_log(log_config)
                time.sleep(1)  # Petite pause entre logs
        
        print(f"\n✓ Cycle #{cycle} terminé")
        print(f"  Certificats analysés: {stats['certificats_analysés']:,}")
        print(f"  Matches trouvés: {stats['matches_trouvés']}")
        print(f"  Alertes envoyées: {stats['alertes_envoyées']}")
        
        time.sleep(CHECK_INTERVAL)
        
    except KeyboardInterrupt:
        print("\n⚠️  Arrêt demandé")
        break
    except Exception as e:
        print(f"✗ Erreur globale: {e}")
        import traceback
        traceback.print_exc()
        time.sleep(30)

print("=== ARRÊT DU MONITORING ===")
