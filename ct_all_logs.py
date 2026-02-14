#!/usr/bin/env python3
"""
Monitoring Certificate Transparency - VERSION LISTE COMPLETE DISCORD
Envoie la liste complete des domaines (meme si 300+)
VERSION 13 LOGS - SURVEILLANCE MAXIMALE
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
print("MONITORING CT - VERSION LISTE COMPLETE - 13 LOGS ACTIFS")
print(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
print("=" * 80)

# ==================== CONFIGURATION ====================
PORT = int(os.environ.get('PORT', 10000))
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK', 
    "https://discord.com/api/webhooks/1471764024797433872/WpHl_7qk5u9mocNYd2LbnFBp0qXbff3RXAIsrKVNXspSQJHJOp_e4_XhWOaq4jrSjKtS")
DOMAINS_FILE = '/app/domains.txt'

# PARAMETRES OPTIMISES POUR 13 LOGS
CHECK_INTERVAL = 60
BATCH_SIZE = 300
MAX_BATCHES_PER_CYCLE = 20
PARALLEL_LOGS = 13  # 13 logs en parallèle
CACHE_MAX_SIZE = 200000
BACKLOG_WARNING_THRESHOLD = 1000
TIMEOUT_PER_LOG = 180

# LOGS ACTIFS - TOP 13 COMPLETS
CT_LOGS = [
    # CLOUDFLARE (3 logs actifs) - PRIORITE MAXIMALE
    {"name": "Cloudflare Nimbus2025", "url": "https://ct.cloudflare.com/logs/nimbus2025", "enabled": True, "priority": "CRITICAL"},
    {"name": "Cloudflare Nimbus2026", "url": "https://ct.cloudflare.com/logs/nimbus2026", "enabled": True, "priority": "CRITICAL"},
    {"name": "Cloudflare Nimbus2027", "url": "https://ct.cloudflare.com/logs/nimbus2027", "enabled": True, "priority": "HIGH"},
    
    # GOOGLE US ARGON (5 logs actifs) - TRES HAUT VOLUME
    {"name": "Google Argon2024", "url": "https://ct.googleapis.com/logs/us1/argon2024", "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Argon2025h1", "url": "https://ct.googleapis.com/logs/us1/argon2025h1", "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Argon2025h2", "url": "https://ct.googleapis.com/logs/us1/argon2025h2", "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Argon2026h1", "url": "https://ct.googleapis.com/logs/us1/argon2026h1", "enabled": True, "priority": "CRITICAL"},
    {"name": "Google Argon2026h2", "url": "https://ct.googleapis.com/logs/us1/argon2026h2", "enabled": True, "priority": "HIGH"},
    
    # GOOGLE EU SOLERA (5 logs actifs) - VOLUME EUROPEEN
    {"name": "Google Solera2024", "url": "https://ct.googleapis.com/logs/eu1/solera2024", "enabled": True, "priority": "MEDIUM"},
    {"name": "Google Solera2025h1", "url": "https://ct.googleapis.com/logs/eu1/solera2025h1", "enabled": True, "priority": "MEDIUM"},
    {"name": "Google Solera2025h2", "url": "https://ct.googleapis.com/logs/eu1/solera2025h2", "enabled": True, "priority": "MEDIUM"},
    {"name": "Google Solera2026h1", "url": "https://ct.googleapis.com/logs/eu1/solera2026h1", "enabled": True, "priority": "MEDIUM"},
    {"name": "Google Solera2026h2", "url": "https://ct.googleapis.com/logs/eu1/solera2026h2", "enabled": True, "priority": "LOW"},
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
    'logs_stats': {},  # Stats par log
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

# Initialiser stats par log
for log in CT_LOGS:
    if log['enabled']:
        stats['logs_stats'][log['name']] = {
            'certs_processed': 0,
            'matches_found': 0,
            'errors': 0,
            'last_position': 0,
            'tree_size': 0,
            'response_time_avg': 0
        }

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
                'version': '13_LOGS_COMPLETE',
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
                'logs_positions': stats['positions'],
                'logs_stats': stats['logs_stats']
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
        start_time = time.time()
        response = requests.get(f"{log_url}/ct/v1/get-sth", timeout=10)
        response.raise_for_status()
        response_time = time.time() - start_time
        
        with stats_lock:
            if log_name in stats['logs_en_erreur']:
                del stats['logs_en_erreur'][log_name]
            if log_name in stats['logs_stats']:
                stats['logs_stats'][log_name]['response_time_avg'] = response_time
        
        return response.json()['tree_size']
    except Exception as e:
        with stats_lock:
            stats['logs_en_erreur'][log_name] = str(e)[:100]
            if log_name in stats['logs_stats']:
                stats['logs_stats'][log_name]['errors'] += 1
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
        
        log_entry_type = int.from_bytes(leaf_bytes[10:12], 'big')
        
        cert_der = None
        
        if log_entry_type == 0:
            with stats_lock:
                stats['x509_count'] += 1
            
            if len(leaf_bytes) < 15:
                return []
            
            cert_length = int.from_bytes(leaf_bytes[12:15], 'big')
            cert_start = 15
            cert_end = cert_start + cert_length
            
            if cert_end <= len(leaf_bytes):
                cert_der = leaf_bytes[cert_start:cert_end]
        
        elif log_entry_type == 1:
            with stats_lock:
                stats['precert_count'] += 1
            
            try:
                extra_data = base64.b64decode(entry.get('extra_data', ''))
                if len(extra_data) > 3:
                    cert_length = int.from_bytes(extra_data[0:3], 'big')
                    if len(extra_data) >= 3 + cert_length:
                        cert_der = extra_data[3:3+cert_length]
            except:
                pass
        
        if not cert_der:
            with stats_lock:
                stats['parse_errors'] += 1
            return []
        
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        all_domains = set()
        
        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn:
                all_domains.add(cn[0].value.lower())
        except:
            pass
        
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for san in san_ext.value:
                domain = san.value.lower().lstrip('*.')
                all_domains.add(domain)
        except:
            pass
        
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
    """Envoie alerte Discord avec LISTE COMPLETE - Messages multiples si necessaire"""
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
        
        # CONSTRUIRE LA LISTE COMPLETE
        full_list = []
        for base, subs in sorted(by_base_domain.items()):
            full_list.append(f"\n**{base}** ({len(subs)} sous-domaines)")
            for sub in sorted(subs):
                full_list.append(f"`{sub}`")
        
        full_text = "\n".join(full_list)
        
        # Discord limite: 4096 caracteres par embed
        # Si trop long, decouper en plusieurs messages
        MAX_LENGTH = 3900  # Marge de securite
        
        messages_to_send = []
        
        if len(full_text) <= MAX_LENGTH:
            # UN SEUL MESSAGE
            embed = {
                "title": f"🚨 [ALERTE] {len(unique_domains)} nouveaux certificats SSL",
                "description": full_text,
                "color": 0xff0000,
                "fields": [
                    {"name": "Domaines principaux", "value": str(len(by_base_domain)), "inline": True},
                    {"name": "Source", "value": log_name, "inline": True}
                ],
                "footer": {"text": "CT Monitor - 13 Logs Actifs"},
                "timestamp": datetime.utcnow().isoformat()
            }
            messages_to_send.append({"embeds": [embed]})
        
        else:
            # PLUSIEURS MESSAGES
            # Message 1: Header avec resume
            header_embed = {
                "title": f"🚨 [ALERTE] {len(unique_domains)} nouveaux certificats SSL",
                "description": f"**LISTE COMPLETE EN PLUSIEURS PARTIES**\n\nDomaines principaux detectes: {len(by_base_domain)}\nSource: {log_name}\n\n" + 
                               "\n".join([f"- **{base}**: {len(subs)} sous-domaines" for base, subs in sorted(by_base_domain.items())]),
                "color": 0xff0000,
                "footer": {"text": "CT Monitor - 13 Logs - Partie 1"},
                "timestamp": datetime.utcnow().isoformat()
            }
            messages_to_send.append({"embeds": [header_embed]})
            
            # Messages suivants: Listes completes par domaine principal
            part_number = 2
            for base, subs in sorted(by_base_domain.items()):
                domain_text = f"**{base}** ({len(subs)} sous-domaines)\n\n"
                domain_text += "\n".join([f"`{sub}`" for sub in sorted(subs)])
                
                # Si un domaine seul depasse la limite, le decouper
                if len(domain_text) > MAX_LENGTH:
                    chunks = []
                    current_chunk = f"**{base}** (suite)\n\n"
                    
                    for sub in sorted(subs):
                        line = f"`{sub}`\n"
                        if len(current_chunk) + len(line) > MAX_LENGTH:
                            chunks.append(current_chunk)
                            current_chunk = f"**{base}** (suite)\n\n" + line
                        else:
                            current_chunk += line
                    
                    if current_chunk:
                        chunks.append(current_chunk)
                    
                    for chunk in chunks:
                        embed = {
                            "description": chunk,
                            "color": 0xff8800,
                            "footer": {"text": f"CT Monitor - 13 Logs - Partie {part_number}"}
                        }
                        messages_to_send.append({"embeds": [embed]})
                        part_number += 1
                else:
                    embed = {
                        "description": domain_text,
                        "color": 0xff8800,
                        "footer": {"text": f"CT Monitor - 13 Logs - Partie {part_number}"}
                    }
                    messages_to_send.append({"embeds": [embed]})
                    part_number += 1
        
        # ENVOYER TOUS LES MESSAGES
        for i, payload in enumerate(messages_to_send):
            try:
                response = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
                response.raise_for_status()
                
                # Pause entre messages pour eviter rate limit Discord
                if i < len(messages_to_send) - 1:
                    time.sleep(1)
                    
            except Exception as e:
                print(f"       [ERREUR] Discord message {i+1}: {str(e)[:100]}")
                # Continuer meme si un message echoue
        
        with stats_lock:
            stats['alertes_envoyées'] += 1
            stats['dernière_alerte'] = datetime.utcnow()
        
        print(f"       [ALERT] Discord: {len(unique_domains)} domaines en {len(messages_to_send)} message(s)")
        
    except Exception as e:
        print(f"       [ERREUR] Discord: {str(e)[:100]}")

# ==================== MONITORING CORE ====================
def monitor_log(log_config):
    """Surveille un log CT"""
    log_name = log_config['name']
    log_url = log_config['url']
    priority = log_config.get('priority', 'MEDIUM')
    
    if log_name not in stats['positions']:
        tree_size = get_sth(log_url, log_name)
        if tree_size:
            stats['positions'][log_name] = max(0, tree_size - 5000)
            if log_name in stats['logs_stats']:
                stats['logs_stats'][log_name]['tree_size'] = tree_size
            print(f"  [INIT] {log_name}: position {stats['positions'][log_name]:,} / {tree_size:,}")
        else:
            print(f"  [ERREUR] {log_name}: Impossible recuperer tree_size")
            return
    
    tree_size = get_sth(log_url, log_name)
    if not tree_size:
        print(f"  [ERREUR] {log_name}: get_sth failed")
        return
    
    if log_name in stats['logs_stats']:
        stats['logs_stats'][log_name]['tree_size'] = tree_size
    
    current_pos = stats['positions'][log_name]
    
    if current_pos >= tree_size:
        print(f"  [OK] {log_name}: A jour ({current_pos:,} / {tree_size:,})")
        return
    
    backlog = tree_size - current_pos
    
    with stats_lock:
        stats['total_backlog'] += backlog
        if backlog > stats['max_backlog_seen']:
            stats['max_backlog_seen'] = backlog
    
    # Ajustement dynamique selon priorité et backlog
    if priority == "CRITICAL":
        if backlog > 10000:
            max_batches = 50
            batch_size = 400
        else:
            max_batches = MAX_BATCHES_PER_CYCLE
            batch_size = BATCH_SIZE
    elif priority == "HIGH":
        max_batches = MAX_BATCHES_PER_CYCLE
        batch_size = BATCH_SIZE
    elif priority == "MEDIUM":
        max_batches = 15
        batch_size = 250
    else:  # LOW
        max_batches = 10
        batch_size = 200
    
    if backlog > BACKLOG_WARNING_THRESHOLD:
        print(f"  [WARN] {log_name}: Backlog {backlog:,}")
    
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
        
        for entry in entries:
            with stats_lock:
                stats['certificats_analysés'] += 1
                if log_name in stats['logs_stats']:
                    stats['logs_stats'][log_name]['certs_processed'] += 1
            
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
                    if log_name in stats['logs_stats']:
                        stats['logs_stats'][log_name]['matches_found'] += len(matched)
                total_matches.extend(matched)
        
        current_pos = end_pos
        stats['positions'][log_name] = current_pos
        if log_name in stats['logs_stats']:
            stats['logs_stats'][log_name]['last_position'] = current_pos
        batches_processed += 1
        
        with stats_lock:
            stats['batches_processed'] += 1
        
        time.sleep(0.2)
    
    if total_matches:
        print(f"  [MATCH] {log_name}: {len(total_matches)} match(es) trouve(s)")
        send_alert(total_matches, log_name)
    
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

print(f"\n[START] Surveillance avec 13 LOGS ACTIFS (intervalle: {CHECK_INTERVAL}s)")
print(f"[START] {len(targets)} domaine(s)")
print(f"[START] Cloudflare: 3 logs | Google US: 5 logs | Google EU: 5 logs")
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
                backlog_trend = "AUGMENTE ⬆️"
            elif recent[-1] < recent[0] * 0.8:
                backlog_trend = "DIMINUE ⬇️"
        
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
        
        # Stats détaillées par log (top 5)
        if stats['logs_stats']:
            print(f"\n[TOP 5 LOGS - MATCHES]")
            sorted_logs = sorted(stats['logs_stats'].items(), 
                               key=lambda x: x[1]['matches_found'], 
                               reverse=True)[:5]
            for log_name, log_stat in sorted_logs:
                print(f"  {log_name}: {log_stat['matches_found']} matches, "
                      f"{log_stat['certs_processed']:,} certs, "
                      f"pos: {log_stat['last_position']:,}/{log_stat['tree_size']:,}")
        
        if stats['total_backlog'] > 50000:
            print(f"\n⚠️ [CRITIQUE] Backlog tres eleve !")
        
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
print("ARRET DU MONITORING - 13 LOGS")
print(f"Certificats analyses: {stats['certificats_analysés']:,}")
print(f"Alertes envoyees: {stats['alertes_envoyées']}")
print("="*80)
