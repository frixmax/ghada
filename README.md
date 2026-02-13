# CertStream Monitor - Surveillance de certificats SSL

Monitor en temps réel des nouveaux certificats SSL/TLS via CertStream avec notifications Discord.

## 🚀 Déploiement

### Option 1: Déploiement sur Render (Recommandé)

Render est une plateforme cloud gratuite parfaite pour ce type de monitoring.

#### Configuration rapide sur Render:

1. **Créer un compte sur [Render.com](https://render.com)**

2. **Créer un nouveau Web Service:**
   - Connectez votre repository GitHub/GitLab
   - Ou utilisez "Deploy from Git URL"
   - Sélectionnez "Docker" comme environnement

3. **Configuration:**
   - **Name:** `certstream-monitor`
   - **Region:** Choisissez la plus proche
   - **Branch:** `main`
   - **Plan:** Free

4. **Variables d'environnement (dans le dashboard Render):**
   ```
   DISCORD_WEBHOOK = https://discord.com/api/webhooks/VOTRE_WEBHOOK
   PORT = 10000
   ```

5. **Modifier `domains.txt`** avec vos domaines à surveiller

6. **Déployer** - Render va automatiquement:
   - Builder l'image Docker
   - Démarrer le monitoring
   - Exposer le port 10000
   - Effectuer des health checks sur `/health`

#### Health Check
Render vérifie automatiquement l'état du service via:
```
GET http://votre-app.onrender.com/health
```

Réponse:
```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "certificats_analysés": 1234,
  "alertes_envoyées": 5,
  "dernière_alerte": "2025-02-13T10:30:00",
  "connecté": true,
  "timestamp": "2025-02-13T11:00:00"
}
```

⚠️ **Note importante:** Le plan gratuit de Render met le service en veille après 15 minutes d'inactivité. Le serveur HTTP maintient le service actif grâce aux health checks.

### Option 2: Docker Local

### Prérequis
- Docker et Docker Compose installés
- Un webhook Discord configuré

### Configuration (pour Docker Local)

1. **Tester votre webhook Discord** (recommandé):
```bash
python test_webhook.py "https://discord.com/api/webhooks/VOTRE_WEBHOOK"
```

2. **Modifier le webhook Discord** dans `ct_monitor.py`:
```python
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK', "VOTRE_WEBHOOK_DISCORD_ICI")
```

Ou via variable d'environnement:
```bash
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
```

2. **Configurer les domaines à surveiller** dans `domains.txt`:
```
example.com
monsite.fr
autredomaine.com
```

3. **Ajuster les paramètres** (optionnel) dans `ct_monitor.py`:
```python
RECENT_DAYS = 2  # Nombre de jours max pour l'ancienneté du certificat (0 = désactivé)
```

### Démarrage

```bash
# Construction et démarrage
docker-compose up -d --build

# Voir les logs en temps réel
docker-compose logs -f

# Arrêter le monitoring
docker-compose down
```

## 📊 Fonctionnalités

✅ Surveillance en temps réel via CertStream  
✅ Notifications Discord avec embeds formatés  
✅ Filtrage par domaines cibles  
✅ Filtrage par date d'émission du certificat  
✅ Reconnexion automatique en cas de déconnexion  
✅ Statistiques périodiques  
✅ Gestion d'erreurs robuste  

## 🔧 Dépannage

### Le conteneur ne démarre pas
```bash
docker-compose logs ct-monitor
```

### Tester la connexion Discord
```bash
curl -X POST "VOTRE_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{"content": "Test de connexion"}'
```

### Vérifier les domaines surveillés
```bash
docker-compose exec ct-monitor cat /app/domains.txt
```

### Redémarrer le monitoring
```bash
docker-compose restart
```

## 📝 Format des notifications

Les alertes Discord incluent:
- Liste des domaines détectés
- Nombre total de domaines
- Date d'émission du certificat
- Nom de l'autorité émettrice
- Timestamp de détection

## ⚠️ Notes importantes

- Le flux CertStream peut générer beaucoup de données (tous les nouveaux certificats SSL mondiaux)
- Choisissez des domaines spécifiques pour éviter trop de faux positifs
- Le webhook Discord a des rate limits (30 messages/minute)
- Les logs sont automatiquement limités à 10MB par fichier

## 🔒 Sécurité

⚠️ **Ne commitez JAMAIS votre webhook Discord dans un dépôt public**

Pour une meilleure sécurité, utilisez des variables d'environnement:

```yaml
# docker-compose.yml
environment:
  - DISCORD_WEBHOOK=${DISCORD_WEBHOOK}
```

```bash
# .env
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
```

## 📈 Exemples d'utilisation

### Surveiller vos propres domaines
```
# domains.txt
monentreprise.com
monentreprise.fr
monentreprise.net
```

### Surveiller des domaines de phishing potentiels
```
# domains.txt
paypa1.com
faceb00k.com
amaz0n.com
```

## 🛠️ Personnalisation

### Modifier les intervalles de heartbeat
Dans `ct_monitor.py`:
```python
time.sleep(300)  # Statistiques toutes les 5 minutes
```

### Changer le nombre max de domaines affichés
Dans la fonction `send_alert()`:
```python
description = "\n".join([f"• `{d}`" for d in sorted(set(matched))[:20]])  # Limite à 20
```

## 📚 Ressources

- [CertStream API](https://certstream.calidog.io/)
- [Discord Webhooks](https://discord.com/developers/docs/resources/webhook)
- [Certificate Transparency](https://certificate.transparency.dev/)
