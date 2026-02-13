#!/usr/bin/env python3
"""
Script de test du webhook Discord
Permet de vérifier que le webhook fonctionne correctement avant le déploiement
"""

import requests
import sys
import os
from datetime import datetime

def test_webhook(webhook_url):
    """Teste le webhook Discord en envoyant un message de test"""
    
    if not webhook_url:
        print("❌ Erreur: Webhook URL manquante")
        print("\nUtilisation:")
        print("  python test_webhook.py <WEBHOOK_URL>")
        print("  ou")
        print("  export DISCORD_WEBHOOK='<URL>' && python test_webhook.py")
        return False
    
    if "discord.com/api/webhooks" not in webhook_url:
        print("❌ Erreur: L'URL ne semble pas être un webhook Discord valide")
        return False
    
    print(f"🧪 Test du webhook Discord...")
    print(f"📍 URL: {webhook_url[:50]}...")
    
    payload = {
        "embeds": [{
            "title": "✅ Test de connexion réussi",
            "description": "Votre webhook Discord fonctionne correctement!\n\nVous pouvez maintenant déployer votre monitoring CertStream.",
            "color": 0x00ff00,
            "fields": [
                {
                    "name": "Date du test",
                    "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "inline": True
                },
                {
                    "name": "Status",
                    "value": "✅ Opérationnel",
                    "inline": True
                }
            ],
            "footer": {
                "text": "CertStream Monitor - Test"
            },
            "timestamp": datetime.utcnow().isoformat()
        }]
    }
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        
        print("✅ Webhook testé avec succès!")
        print(f"📨 Code de réponse: {response.status_code}")
        print("\n✨ Vous devriez voir un message dans votre canal Discord")
        return True
        
    except requests.exceptions.HTTPError as e:
        print(f"❌ Erreur HTTP: {e}")
        print(f"   Code: {response.status_code}")
        
        if response.status_code == 404:
            print("   → Le webhook n'existe pas ou a été supprimé")
        elif response.status_code == 401:
            print("   → Token du webhook invalide")
        elif response.status_code == 429:
            print("   → Rate limit atteint, réessayez dans quelques secondes")
        
        return False
        
    except requests.exceptions.Timeout:
        print("❌ Timeout: Discord ne répond pas")
        return False
        
    except requests.exceptions.ConnectionError:
        print("❌ Erreur de connexion: Vérifiez votre connexion internet")
        return False
        
    except Exception as e:
        print(f"❌ Erreur inattendue: {e}")
        return False

if __name__ == "__main__":
    # Récupération du webhook depuis les arguments ou l'environnement
    webhook = None
    
    if len(sys.argv) > 1:
        webhook = sys.argv[1]
    else:
        webhook = os.environ.get('DISCORD_WEBHOOK')
    
    success = test_webhook(webhook)
    sys.exit(0 if success else 1)
