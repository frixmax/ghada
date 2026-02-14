#!/usr/bin/env python3
"""
Monitoring Certificate Transparency - VERSION CORRIGEE AVEC PRECERT
Gestion correcte des X509Entry ET PreCertificate
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
print("MONITORING CT - VERSION CORRIGEE (X509 + PreCert)")
print(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
print("=" * 80)

# ==================== CONFIGURATION ====================
PORT = int(os.environ.get('PORT', 10000))
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK', 
    "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS")
DOMAINS_FILE = '/app/domains.txt'

# PARAMETRES OPTIMISES
CHECK_INTERVAL = 60              # 60s
BATCH_SIZE = 300                 # Batches moyens
MAX_BATCHES_PER_CYCLE = 20       # 20 batches max
PARALLEL_LOGS = 8                # 8 logs paralleles
CACHE_MAX_SIZE = 200000          
BACKLOG_WARNING_THRESHOLD = 1000
TIMEOUT_PER_LOG = 180

# LOGS ACTIFS - Top 6
CT_LOGS = [
    {"name": "Cloudflare Nimbus2025", "url": "https://ct.cloudflare.com/logs/nimbus2025", "enabled": True, "priority": "HIGH"},
    {"name": "Cloudflare Nimbus2026", "url": "https://ct.cloudflare.com/logs/nimbus2026", "enabled": True, "priority": "HIGH"},
    {"name": "Google Argon2025h2", "url": "https://ct.googleapis.com/logs/us1/argon2025h2", "enabled": True, "priority": "HIGH"},
    {"name": "Google Argon2024", "url": "https://ct.googleapis.com/logs/us1/argon2024", "enabled": True, "priority": "HIGH"},
    {"name": "Google Argon2026h1", "url": "https://ct.googleapis.com/logs/us1/argon2026h1", "enabled": True, "priority": "HIGH"},
    {"name": "Google Argon2025h1", "url": "https://ct.googleapis.com/logs/us1/argon2025h1", "enabled": True, "priority": "HIGH"},
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
    'x509_count': 0,
    'precert_count': 0,
}

seen_certificates = set()
stats_lock = threading.Lock()

# ==================== CHARGEMENT DOMAINES ====================
try:
    with open(DOMAINS_FILE, 'r') as f:
        targets = {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
    print(f"[OK] {len(targets)} domaines charges")
    if targets:
        print(f"     Exemples: {', '.join(list(targets)[:5])}")
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
            
            avg_backlog = 0
            if stats['backlog_history']:
                recent = stats['backlog_history'][-10:]
                avg_backlog = sum(recent) // len(recent) if recent else 0
            
            status = {
                'status': 'healthy',
                'uptime_seconds': int(uptime),
                'uptime_human': f"{int(uptime//3600)}h {int((uptime%3600)//60)}m",
                'certificats_analysés': stats['certificats_analysés'],
                'x509_count': stats['x509_count'],
                'precert_count': stats['precert_count'],
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
    """Parse certificat X.509 - VERSION CORRIGEE avec X509Entry ET PreCertificate"""
    try:
        leaf_bytes = base64.b64decode(entry.get('leaf_input', ''))
        
        if len(leaf_bytes) < 12:
            return []
        
        # Lire LogEntryType (bytes 10-11, big-endian uint16)
        # 0 = X509Entry
        # 1 = PreCertificate
        log_entry_type = int.from_bytes(leaf_bytes[10:12], 'big')
        
        cert_der = None
        
        if log_entry_type == 0:
            # X509Entry - certificat complet dans leaf_input
            with stats_lock:
                stats['x509_count'] += 1
            
            if len(leaf_bytes) < 15:
                return []
            
            # Lire la longueur du certificat (3 bytes)
            cert_length = int.from_bytes(leaf_bytes[12:15], 'big')
            cert_start = 15
            cert_end = cert_start + cert_length
            
            if cert_end <= len(leaf_bytes):
                cert_der = leaf_bytes[cert_start:cert_end]
        
        elif log_entry_type == 1:
            # PreCertificate - certificat dans extra_data
            with stats_lock:
                stats['precert_count'] += 1
            
            try:
                extra_data = base64.b64decode(entry.get('extra_data', ''))
                if len(extra_data) > 3:
                    # Les 3 premiers bytes = longueur du certificat
                    cert_length = int.from_bytes(extra_data[0:3], 'big')
                    if len(extra_data) >= 3 + cert_length:
                        cert_der = extra_data[3:3+cert_length]
            except:
                pass
        
        if not cert_der:
            with stats_lock:
                stats['parse_errors'] += 1
            return []
        
        # Parser le certificat X.509
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        all_domains = set()
        
        # Common Name
        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn:
                all_domains.add(cn[0].value.lower())
        except:
            pass
        
        # SANs (Subject Alternative Names) - LE PLUS IMPORTANT
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
                # Match exact ou sous-domaine
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
            "title": "[ALERTE] Nouveaux certificats SSL",
            "description": description,
            "color": 0xff0000,
            "fields": [
                {"name": "Total domaines", "value": str(len(unique_domains)), "inline": True},
                {"name": "Domaines principaux", "value": str(len(by_base_domain)), "inline": True},
                {"name": "Source", "value": log_name, "inline": True}
            ],
            "footer": {"text": "CT Monitor"},
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
    """Surveille un log CT"""
    log_name = log_config['name']
    log_url = log_config['url']
    priority = log_config.get('priority', 'MEDIUM')
    
    # Init position
    if log_name not in stats['positions']:
        tree_size = get_sth(log_url, log_name)
        if tree_size:
            # Demarrer 5000 entrees avant la fin pour avoir plus de chances
            stats['positions'][log_name] = max(0, tree_size - 5000)
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
    
    # Ajuster selon backlog
    if backlog > 10000:
        max_batches = 50
        batch_size = 400
        print(f"  [TURBO] {log_name}: Backlog {backlog:,} -> Mode Accelere")
    elif backlog > 5000:
        max_batches = 30
        batch_size = 350
    elif backlog > BACKLOG_WARNING_THRESHOLD:
        max_batches = MAX_BATCHES_PER_CYCLE
        batch_size = BATCH_SIZE
        print(f"  [WARN] {log_name}: Backlog {backlog:,}")
    else:
        max_batches = MAX_BATCHES_PER_CYCLE
        batch_size = BATCH_SIZE
    
    # TRAITER BACKLOG
    batches_processed = 0
    total_matches = []
    
    while current_pos < tree_size and batches_processed < max_batches:
        end_pos = min(current_pos + batch_size, tree_size)
        remaining = tree_size - end_pos
        
        if batches_processed % 5 == 0:
            print(f"  [SCAN] {log_name} [{batches_processed+1}/{max_batches}]: {current_pos:,} -> {end_pos-1:,} (reste: {remaining:,})")
        
        entries = get_entries(log_url, current_pos, end_pos - 1)
        
        if not entries:
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
        
        time.sleep(0.2)
    
    # Alerte groupee
    if total_matches:
        print(f"  [MATCH] {log_name}: {len(total_matches)} match(es) trouve(s)")
        send_alert(total_matches, log_name)
    
    # Stats finales
    final_backlog = tree_size - current_pos
    if final_backlog > 0:
        print(f"  [STATS] {log_name}: {batches_processed} batches, {final_backlog:,} certs restants")
    
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
                print(f"  [ERREUR] {log_name}: {str(e)[:100]}")
                results[log_name] = -1
    
    return results

# ==================== STARTUP ====================
http_thread = threading.Thread(target=start_http_server, daemon=True)
http_thread.start()
time.sleep(1)

print(f"\n[START] Surveillance (intervalle: {CHECK_INTERVAL}s)")
print(f"[START] {len(targets)} domaine(s)")
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
        
        results = monitor_all_logs_parallel()
        
        cycle_duration = int(time.time() - cycle_start)
        successful_logs = sum(1 for v in results.values() if v >= 0)
        total_batches = sum(v for v in results.values() if v > 0)
        
        with stats_lock:
            stats['backlog_history'].append(stats['total_backlog'])
            if len(stats['backlog_history']) > 100:
                stats['backlog_history'].pop(0)
        
        backlog_trend = "STABLE"
        if len(stats['backlog_history']) >= 3:
            recent = stats['backlog_history'][-3:]
            if recent[-1] > recent[0] * 1.2:
                backlog_trend = "AUGMENTE"
            elif recent[-1] < recent[0] * 0.8:
                backlog_trend = "DIMINUE"
        
        parse_success_rate = 0
        if stats['certificats_analysés'] > 0:
            parse_success_rate = 100 * (1 - stats['parse_errors'] / stats['certificats_analysés'])
        
        print(f"\n{'='*80}")
        print(f"CYCLE #{cycle} TERMINE en {cycle_duration}s")
        print(f"  Logs traites: {successful_logs}/{len(results)}")
        print(f"  Batches: {total_batches}")
        print(f"  Certificats analyses: {stats['certificats_analysés']:,}")
        print(f"    - X509Entry: {stats['x509_count']:,}")
        print(f"    - PreCert: {stats['precert_count']:,}")
        print(f"    - Parse success: {parse_success_rate:.1f}%")
        print(f"  Matches trouves: {stats['matches_trouvés']}")
        print(f"  Alertes envoyees: {stats['alertes_envoyées']}")
        print(f"  Backlog: {stats['total_backlog']:,} ({backlog_trend})")
        print(f"{'='*80}")
        
        if stats['total_backlog'] > 50000:
            print(f"\n[CRITIQUE] Backlog tres eleve !")
        
        print(f"\n[WAIT] Attente {CHECK_INTERVAL}s avant cycle #{cycle+1}...")
        time.sleep(CHECK_INTERVAL)
        
    except KeyboardInterrupt:
        print("\n\n[STOP] Arret demande")
        break
    except Exception as e:
        print(f"\n[ERREUR] GLOBALE: {e}")
        import traceback
        traceback.print_exc()
        print("\n[PAUSE] 60s...")
        time.sleep(60)

print("\n" + "="*80)
print("ARRET DU MONITORING")
print(f"Certificats analyses: {stats['certificats_analysés']:,}")
print(f"Alertes envoyees: {stats['alertes_envoyées']}")
print("="*80)
