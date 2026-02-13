#!/usr/bin/env python3
"""
Script de test CertStream
Vérifie que le flux CertStream envoie bien des données
"""

import websocket
import json
import sys
from datetime import datetime

print("🧪 Test de connexion CertStream")
print("=" * 50)

message_count = 0
start_time = datetime.utcnow()

def on_message(ws, message):
    global message_count
    message_count += 1
    
    try:
        data = json.loads(message)
        msg_type = data.get('message_type', 'unknown')
        
        if message_count == 1:
            print(f"\n✅ Premier message reçu!")
            print(f"   Type: {msg_type}")
            print(f"   Clés: {list(data.keys())}")
        
        if msg_type == "certificate_update":
            domains = data.get('data', {}).get('leaf_cert', {}).get('all_domains', [])
            if domains and message_count <= 5:
                print(f"\n📜 Certificat #{message_count}: {domains[0]}")
        
        if message_count >= 10:
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            rate = message_count / elapsed
            print(f"\n✅ TEST RÉUSSI!")
            print(f"   Messages reçus: {message_count}")
            print(f"   Temps écoulé: {elapsed:.1f}s")
            print(f"   Débit: {rate:.1f} msg/s")
            ws.close()
            sys.exit(0)
            
    except Exception as e:
        print(f"❌ Erreur de parsing: {e}")

def on_error(ws, error):
    print(f"❌ Erreur: {error}")

def on_close(ws, code, msg):
    print(f"\n⚠️  Connexion fermée")

def on_open(ws):
    print("✅ Connecté à CertStream!")
    print("   Attente de messages (max 30s)...\n")

try:
    ws = websocket.WebSocketApp(
        "wss://certstream.calidog.io/",
        on_message=on_message,
        on_open=on_open,
        on_error=on_error,
        on_close=on_close
    )
    
    # Timeout de 30s
    import threading
    def timeout():
        if message_count == 0:
            print(f"\n❌ TIMEOUT: Aucun message reçu après 30s")
            print("   Le flux CertStream semble ne pas envoyer de données")
            ws.close()
            sys.exit(1)
    
    timer = threading.Timer(30.0, timeout)
    timer.start()
    
    ws.run_forever()
    timer.cancel()
    
except KeyboardInterrupt:
    print("\n⚠️  Test interrompu")
except Exception as e:
    print(f"\n❌ Erreur: {e}")
    sys.exit(1)
