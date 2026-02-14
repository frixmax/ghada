#!/usr/bin/env python3
"""
Monitoring Certificate Transparency - VERSION ANTI-BACKLOG
Optimise pour traiter tous les certificats sans accumulation de retard
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
from concurrent.futures import ThreadPoolExecutor, as_completed

print("=" * 80)
print("MONITORING CT - VERSION ANTI-BACKLOG OPTIMISEE")
print(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
print("=" * 80)

# ==================== CONFIGURATION OPTIMISEE ====================
PORT = int(os.environ.get('PORT', 10000))
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK', 
    "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS")
DOMAINS_FILE = '/app/domains.txt'

# PARAMETRES ANTI-BACKLOG (OPTIMISES)
CHECK_INTERVAL = 45              # 45s (plus rapide)
BATCH_SIZE = 400                 # Batches plus gros
MAX_BATCHES_PER_CYCLE = 25       # Plus de batches par cycle
PARALLEL_LOGS = 10               # Plus de parallelisme
CACHE_MAX_SIZE = 200000          # Cache plus grand
BACKLOG_WARNING_THRESHOLD = 500  # Alerte precoce
TIMEOUT_PER_LOG = 180            # 3 minutes max par log

# Capacite theorique: 13 logs x 25 batches x 400 = 130,000 certs/cycle
# 130,000 / 45s = 2,889 certs/seconde

# LOGS ACTIFS - Top 6 uniquement pour performance maximale
CT_LOGS = [
    # TOP 6 - ULTRA ACTIFS SEULEMENT
    {"name": "Cloudflare Nimbus2025", "url": "https://ct.cloudflare.com/logs/nimbus2025", "enabled": True, "priority": "HIGH"},
    {"name": "Cloudflare Nimbus2026", "url": "https://ct.cloudflare.com/logs/nimbus2026", "enabled": True, "priority": "HIGH"},
    {"name": "Google Argon2025h2", "url": "https://ct.googleapis.com/logs/us1/argon2025h2", "enabled": True, "priority": "HIGH"},
    {"name": "Google Argon2024", "url": "https://ct.googleapis.com/logs/us1/argon2024", "enabled": True, "priority": "HIGH"},
    {"name": "Google Argon2026h1", "url": "https://ct.googleapis.com/logs/us1/argon2026h1", "enabled": True, "priority": "HIGH"},
    {"name": "Google Argon2025h1", "url": "https://ct.googleapis.com/logs/us1/argon2025h1", "enabled": True, "priority": "HIGH"},
    
    # DESACTIVE pour reduire la charge (reactiver une fois backlog sous controle)
    {"name": "Google Argon2026h2", "url": "https://ct.googleapis.com/logs/us1/argon2026h2", "enabled": False, "priority": "MEDIUM"},
    {"name": "Cloudflare Nimbus2027", "url": "https://ct.cloudflare.com/logs/nimbus2027", "enabled": False, "priority": "MEDIUM"},
    {"name": "Google Solera2026h1", "url": "https://ct.googleapis.com/logs/eu1/solera2026h1", "enabled": False, "priority": "MEDIUM"},
    {"name": "Google Solera2024", "url": "https://ct.googleapis.com/logs/eu1/solera2024", "enabled": False, "priority": "LOW"},
    {"name": "Google Solera2025h2", "url": "https://ct.googleapis.com/logs/eu1/solera2025h2", "enabled": False, "priority": "LOW"},
    {"name": "Google Solera2025h1", "url": "https://ct.googleapis.com/logs/eu1/solera2025h1", "enabled": False, "priority": "LOW"},
    {"name": "Google Solera2026h2", "url": "https://ct.googleapis.com/logs/eu1/solera2026h2", "enabled": False, "priority": "LOW"},
]

# ==================== STATS ====================
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
    'matches_trouvés': 0,
    'total_backlog': 0,
    'batches_processed': 0,
    'max_backlog_seen': 0,
    'backlog_history': [],
}

# Cache anti-duplicates
seen_certificates = set()

# Lock pour thread-safety
stats_lock = threading.Lock()

# ==================== CHARGEMENT DOMAINES ====================
try:
    with open(DOMAINS_FILE, 'r') as f:
        targets = {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
    print(f"[OK] {len(targets)} domaines charges")
    if targets:
        print(f"     Premiers: {', '.join(list(targets)[:5])}")
except Exception as e:
    print(f"[ERREUR] Chargement domaines: {e}")
    targets = set()

if not targets:
    print("[ERREUR] Aucun domaine a surveiller")
    exit(1)

if "discord.com/api/webhooks" not in DISCORD_WEBHOOK:
    print("[ERREUR] Webhook Discord invalide")
    exit(1)

stats['logs_actifs'] = sum(1 for log in CT_LOGS if log['enabled'])
print(f"[OK] {stats['logs_actifs']} logs CT actifs")
print(f"[OK] Webhook Discord configure")
print(f"[OK] Capacite: {MAX_BATCHES_PER_CYCLE} batches x {BATCH_SIZE} = {MAX_BATCHES_PER_CYCLE * BATCH_SIZE} certs max/log/cycle")
print(f"[OK] Intervalle: {CHECK_INTERVAL}s entre cycles")
print("=" * 80)

# ==================== HTTP HEALTH CHECK ====================
class HealthCheckHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        if self.path == '/health' or self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            uptime = (datetime.utcnow() - stats['démarrage']).total_seconds()
            
            # Calculer moyenne backlog sur 10 derniers cycles
            avg_backlog = 0
            if stats['backlog_history']:
                recent = stats['backlog_history'][-10:]
                avg_backlog = sum(recent) // len(recent) if recent else 0
            
            status = {
                'status': 'healthy',
                'uptime_seconds': int(uptime),
                'uptime_human': f"{int(uptime//3600)}h {int((uptime%3600)//60)}m",
                'certificats_analysés': stats['certificats_analysés'],
                'matches_trouvés': stats['matches_trouvés'],
                'alertes_envoyées': stats['alertes_envoyées'],
                'duplicates_évités': stats['duplicates_évités'],
                'parse_errors': stats['parse_errors'],
                'batches_processed': stats['batches_processed'],
                'total_backlog': stats['total_backlog'],
                'max_backlog_seen': stats['max_backlog_seen'],
                'avg_backlog_10_cycles': avg_backlog,
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
    server = HTTPServer(('0.0.0.0', PORT), HealthCheckHandler)
    print(f"[OK] Serveur HTTP sur port {PORT}")
    server.serve_forever()

# ==================== CT API FUNCTIONS ====================
def get_sth(log_url, log_name):
    """Recupere le Signed Tree Head"""
    try:
        response = requests.get(f"{log_url}/ct/v1/get-sth", timeout=10)
        response.raise_for_status()
        
        with stats_lock:
            if log_name in stats['logs_en_erreur']:
                del stats['logs_en_erreur'][log_name]
        
        return response.json()['tree_size']
    except Exception as e:
        with stats_lock:
            stats['logs_en_erreur'][log_name] = str(e)[:100]
        return None

def get_entries(log_url, start, end):
    """Recupere les entrees CT avec retry"""
    for attempt in range(3):
        try:
            response = requests.get(
                f"{log_url}/ct/v1/get-entries",
                params={"start": start, "end": end},
                timeout=30
            )
            response.raise_for_status()
            return response.json().get('entries', [])
        except Exception as e:
            if attempt == 2:
                print(f"       [ERREUR] get_entries apres 3 tentatives: {str(e)[:50]}")
                return []
            time.sleep(1)
    return []

def generate_cert_hash(entry):
    """Genere hash pour detecter duplicates"""
    try:
        return hash(entry.get('leaf_input', ''))
    except:
        return None

def parse_certificate(entry):
    """Parse certificat X.509"""
    try:
        leaf_bytes = base64.b64decode(entry.get('leaf_input', ''))
        
        if len(leaf_bytes) < 15:
            return []
        
        cert_length = int.from_bytes(leaf_bytes[11:14], 'big')
        cert_start = 14
        cert_end = cert_start + cert_length
        
        if cert_end > len(leaf_bytes):
            return []
        
        cert_der = leaf_bytes[cert_start:cert_end]
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        all_domains = set()
        
        # Common Name
        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn:
                all_domains.add(cn[0].value.lower())
        except:
            pass
        
        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for san in san_ext.value:
                domain = san.value.lower().lstrip('*.')
                all_domains.add(domain)
        except:
            pass
        
        # Match avec targets
        matched = []
        for domain in all_domains:
            for target in targets:
                if domain == target or domain.endswith('.' + target):
                    matched.append(domain)
                    break
        
        return list(set(matched))
        
    except Exception as e:
        with stats_lock:
            stats['parse_errors'] += 1
        return []

def send_alert(matched_domains, log_name):
    """Envoie alerte Discord"""
    try:
        unique_domains = sorted(set(matched_domains))
        
        # Grouper par domaine principal
        by_base_domain = {}
        for domain in unique_domains:
            for target in targets:
                if domain == target or domain.endswith('.' + target):
                    if target not in by_base_domain:
                        by_base_domain[target] = []
                    by_base_domain[target].append(domain)
                    break
        
        # Construire description
        description_parts = []
        for base, subs in sorted(by_base_domain.items()):
            description_parts.append(f"**{base}** ({len(subs)})")
            for sub in sorted(subs)[:5]:
                description_parts.append(f"  - `{sub}`")
            if len(subs) > 5:
                description_parts.append(f"  ... +{len(subs)-5} autres")
        
        description = "\n".join(description_parts[:30])
        
        if len(description_parts) > 30:
            description += f"\n\n... et {len(description_parts)-30} lignes supplementaires"
        
        embed = {
            "title": "[ALERTE] Nouveaux certificats SSL detectes",
            "description": description,
            "color": 0xff0000,
            "fields": [
                {"name": "Total domaines", "value": str(len(unique_domains)), "inline": True},
                {"name": "Domaines principaux", "value": str(len(by_base_domain)), "inline": True},
                {"name": "Source", "value": log_name, "inline": True}
            ],
            "footer": {"text": "CT Monitor - Anti-Backlog"},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        payload = {"embeds": [embed]}
        response = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        response.raise_for_status()
        
        with stats_lock:
            stats['alertes_envoyées'] += 1
            stats['dernière_alerte'] = datetime.utcnow()
        
        print(f"       [ALERT] Discord: {len(unique_domains)} domaine(s)")
        
    except Exception as e:
        print(f"       [ERREUR] Discord: {str(e)[:100]}")

# ==================== MONITORING CORE ====================
def monitor_log(log_config):
    """Surveille un log CT - VERSION ANTI-BACKLOG"""
    log_name = log_config['name']
    log_url = log_config['url']
    priority = log_config.get('priority', 'MEDIUM')
    
    # Init position
    if log_name not in stats['positions']:
        tree_size = get_sth(log_url, log_name)
        if tree_size:
            stats['positions'][log_name] = max(0, tree_size - 1000)
            print(f"  [INIT] {log_name}: position {stats['positions'][log_name]:,} / {tree_size:,}")
        else:
            print(f"  [ERREUR] {log_name}: Impossible recuperer tree_size")
            return
    
    # Recuperer taille actuelle
    tree_size = get_sth(log_url, log_name)
    if not tree_size:
        print(f"  [ERREUR] {log_name}: get_sth failed")
        return
    
    current_pos = stats['positions'][log_name]
    
    if current_pos >= tree_size:
        print(f"  [OK] {log_name}: A jour ({current_pos:,} / {tree_size:,})")
        return
    
    # Calculer backlog
    backlog = tree_size - current_pos
    
    with stats_lock:
        stats['total_backlog'] += backlog
        if backlog > stats['max_backlog_seen']:
            stats['max_backlog_seen'] = backlog
    
    # MODE DYNAMIQUE selon backlog
    if backlog > 20000:
        max_batches = 100
        batch_size = 500
        print(f"  [URGENCE] {log_name}: Backlog {backlog:,} -> Mode Turbo Max ({max_batches} batches)")
    elif backlog > 10000:
        max_batches = 50
        batch_size = 450
        print(f"  [TURBO] {log_name}: Backlog {backlog:,} -> Mode Accelere ({max_batches} batches)")
    elif backlog > 5000:
        max_batches = 35
        batch_size = 400
        print(f"  [RAPIDE] {log_name}: Backlog {backlog:,} -> Mode Rapide ({max_batches} batches)")
    elif backlog > BACKLOG_WARNING_THRESHOLD:
        max_batches = MAX_BATCHES_PER_CYCLE
        batch_size = BATCH_SIZE
        print(f"  [WARN] {log_name}: Backlog {backlog:,} -> Mode Normal ({max_batches} batches)")
    else:
        max_batches = MAX_BATCHES_PER_CYCLE
        batch_size = BATCH_SIZE
    
    # TRAITER BACKLOG
    batches_processed = 0
    total_matches = []
    
    while current_pos < tree_size and batches_processed < max_batches:
        end_pos = min(current_pos + batch_size, tree_size)
        remaining = tree_size - end_pos
        
        if batches_processed % 5 == 0:  # Log tous les 5 batches
            print(f"  [SCAN] {log_name} [{batches_processed+1}/{max_batches}]: {current_pos:,} -> {end_pos-1:,} (reste: {remaining:,})")
        
        entries = get_entries(log_url, current_pos, end_pos - 1)
        
        if not entries:
            print(f"       [WARN] Aucune entree, skip batch")
            break
        
        # Parser certificats
        for entry in entries:
            with stats_lock:
                stats['certificats_analysés'] += 1
            
            cert_hash = generate_cert_hash(entry)
            if cert_hash:
                if cert_hash in seen_certificates:
                    with stats_lock:
                        stats['duplicates_évités'] += 1
                    continue
                
                seen_certificates.add(cert_hash)
                
                if len(seen_certificates) > CACHE_MAX_SIZE:
                    seen_certificates.pop()
            
            matched = parse_certificate(entry)
            
            if matched:
                with stats_lock:
                    stats['matches_trouvés'] += len(matched)
                total_matches.extend(matched)
        
        current_pos = end_pos
        stats['positions'][log_name] = current_pos
        batches_processed += 1
        
        with stats_lock:
            stats['batches_processed'] += 1
        
        time.sleep(0.2)  # Petite pause
    
    # Alerte groupee
    if total_matches:
        print(f"  [MATCH] {log_name}: {len(total_matches)} match(es) trouve(s)")
        send_alert(total_matches, log_name)
    
    # Stats finales
    final_backlog = tree_size - current_pos
    if final_backlog > 0:
        print(f"  [STATS] {log_name}: {batches_processed} batches traites, {final_backlog:,} certs restants")
    
    return batches_processed

# ==================== MAIN LOOP ====================
def monitor_all_logs_parallel():
    """Traite tous les logs en parallele"""
    enabled_logs = [log for log in CT_LOGS if log['enabled']]
    
    results = {}
    
    with ThreadPoolExecutor(max_workers=PARALLEL_LOGS) as executor:
        futures = {executor.submit(monitor_log, log): log['name'] for log in enabled_logs}
        
        for future in as_completed(futures):
            log_name = futures[future]
            try:
                batches = future.result(timeout=TIMEOUT_PER_LOG)
                results[log_name] = batches if batches else 0
            except Exception as e:
                print(f"  [ERREUR] {log_name}: Exception - {str(e)[:100]}")
                results[log_name] = -1
    
    return results

# ==================== STARTUP ====================
http_thread = threading.Thread(target=start_http_server, daemon=True)
http_thread.start()
time.sleep(1)

print(f"\n[START] Demarrage surveillance (intervalle: {CHECK_INTERVAL}s)")
print(f"[START] {len(targets)} domaine(s) surveille(s)")
print(f"[START] Parallelisation: {PARALLEL_LOGS} logs simultanes")
print("=" * 80)

# ==================== MAIN LOOP ====================
cycle = 0

while True:
    try:
        cycle += 1
        cycle_start = time.time()
        
        with stats_lock:
            stats['dernière_vérification'] = datetime.utcnow()
            stats['total_backlog'] = 0
        
        print(f"\n{'='*80}")
        print(f"CYCLE #{cycle} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{'='*80}")
        
        # Traiter logs
        results = monitor_all_logs_parallel()
        
        # Stats cycle
        cycle_duration = int(time.time() - cycle_start)
        successful_logs = sum(1 for v in results.values() if v >= 0)
        total_batches_this_cycle = sum(v for v in results.values() if v > 0)
        
        # Historique backlog
        with stats_lock:
            stats['backlog_history'].append(stats['total_backlog'])
            if len(stats['backlog_history']) > 100:
                stats['backlog_history'].pop(0)
        
        # Tendance backlog
        backlog_trend = "STABLE"
        if len(stats['backlog_history']) >= 3:
            recent = stats['backlog_history'][-3:]
            if recent[-1] > recent[0] * 1.2:
                backlog_trend = "AUGMENTE"
            elif recent[-1] < recent[0] * 0.8:
                backlog_trend = "DIMINUE"
        
        print(f"\n{'='*80}")
        print(f"CYCLE #{cycle} TERMINE en {cycle_duration}s")
        print(f"  Logs traites: {successful_logs}/{len(results)}")
        print(f"  Batches traites: {total_batches_this_cycle}")
        print(f"  Certificats analyses (total): {stats['certificats_analysés']:,}")
        print(f"  Matches trouves (total): {stats['matches_trouvés']}")
        print(f"  Alertes envoyees (total): {stats['alertes_envoyées']}")
        print(f"  Backlog actuel: {stats['total_backlog']:,} ({backlog_trend})")
        print(f"  Max backlog vu: {stats['max_backlog_seen']:,}")
        print(f"{'='*80}")
        
        # Alerte si backlog critique
        if stats['total_backlog'] > 50000:
            print(f"\n[CRITIQUE] Backlog tres eleve ! Augmenter capacite ou desactiver logs.")
        
        print(f"\n[WAIT] Attente {CHECK_INTERVAL}s avant cycle #{cycle+1}...")
        time.sleep(CHECK_INTERVAL)
        
    except KeyboardInterrupt:
        print("\n\n[STOP] Arret demande par utilisateur")
        break
    except Exception as e:
        print(f"\n[ERREUR] GLOBALE: {e}")
        import traceback
        traceback.print_exc()
        print("\n[PAUSE] Attente 60s avant retry...")
        time.sleep(60)

print("\n" + "="*80)
print("ARRET DU MONITORING")
print(f"Uptime: {int((datetime.utcnow() - stats['démarrage']).total_seconds() / 3600)}h")
print(f"Certificats analyses: {stats['certificats_analysés']:,}")
print(f"Alertes envoyees: {stats['alertes_envoyées']}")
print("="*80)
