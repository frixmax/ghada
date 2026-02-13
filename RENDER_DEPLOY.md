# 🚀 Guide de déploiement sur Render

## Prérequis
- Un compte GitHub/GitLab (gratuit)
- Un compte Render (gratuit)
- Un webhook Discord configuré

## Étapes de déploiement

### 1. Préparer votre repository

```bash
# Cloner ou créer votre repository
git init
git add .
git commit -m "Initial commit - CertStream Monitor"
git branch -M main

# Pusher vers GitHub
git remote add origin https://github.com/VOTRE_USERNAME/certstream-monitor.git
git push -u origin main
```

### 2. Configurer vos domaines

Éditez le fichier `domains.txt` avec les domaines à surveiller:

```
# Vos domaines
example.com
votresite.fr
autredomaine.net
```

Commitez les changements:
```bash
git add domains.txt
git commit -m "Add domains to monitor"
git push
```

### 3. Créer un Web Service sur Render

1. Allez sur [dashboard.render.com](https://dashboard.render.com)
2. Cliquez sur **"New +"** → **"Web Service"**
3. Connectez votre repository GitHub/GitLab
4. Sélectionnez votre repository `certstream-monitor`

### 4. Configuration du service

**Settings:**
- **Name:** `certstream-monitor` (ou votre choix)
- **Region:** Choisissez la région la plus proche
- **Branch:** `main`
- **Runtime:** `Docker`
- **Plan:** `Free`

**Build & Deploy:**
- Build Command: (vide - Docker gère tout)
- Start Command: (vide - défini dans Dockerfile)

### 5. Variables d'environnement

Dans l'onglet **"Environment"**, ajoutez:

| Key | Value |
|-----|-------|
| `DISCORD_WEBHOOK` | `https://discord.com/api/webhooks/VOTRE_ID/VOTRE_TOKEN` |
| `PORT` | `10000` |

⚠️ **Important:** Cochez "Secret" pour `DISCORD_WEBHOOK`

### 6. Déploiement

1. Cliquez sur **"Create Web Service"**
2. Render va:
   - Cloner votre repository
   - Builder l'image Docker
   - Déployer le conteneur
   - Exposer le port 10000
   - Commencer les health checks

### 7. Vérification

Une fois déployé, vous pouvez:

**Voir les logs:**
```
Dashboard → Votre service → Logs
```

**Tester le health check:**
```bash
curl https://votre-app.onrender.com/health
```

**Réponse attendue:**
```json
{
  "status": "healthy",
  "uptime_seconds": 123,
  "certificats_analysés": 0,
  "alertes_envoyées": 0,
  "connecté": true,
  "timestamp": "2025-02-13T10:00:00"
}
```

## 📊 Monitoring

### Dashboard Render
- **Logs:** Voir les certificats détectés en temps réel
- **Metrics:** CPU, mémoire, requêtes HTTP
- **Events:** Redémarrages, builds, deployments

### Exemple de logs:
```
✓ Serveur HTTP démarré sur le port 10000
✓ 3 domaines chargés pour surveillance
✓ Webhook Discord configuré
✓ Connecté au flux CertStream à 10:00:15 UTC
✓ Alerte envoyée: 2 domaine(s) - Total alertes: 1
```

## 🔄 Mise à jour

Pour mettre à jour les domaines surveillés:

```bash
# Modifier domains.txt
nano domains.txt

# Commit et push
git add domains.txt
git commit -m "Update monitored domains"
git push
```

Render va automatiquement redéployer!

## ⚠️ Limitations du plan gratuit

- **Mise en veille:** Le service se met en veille après 15 minutes d'inactivité
- **Solution:** Le serveur HTTP avec health checks maintient le service actif
- **750 heures/mois:** Suffisant pour un monitoring 24/7
- **Redémarrage:** Le service redémarre automatiquement en cas d'erreur

## 🐛 Dépannage

### Le service ne démarre pas
1. Vérifiez les logs dans le dashboard
2. Assurez-vous que `domains.txt` existe et n'est pas vide
3. Vérifiez que `DISCORD_WEBHOOK` est configuré

### Pas d'alertes reçues
1. Testez le webhook Discord:
```bash
curl -X POST "$DISCORD_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{"content": "Test"}'
```
2. Vérifiez que vos domaines sont corrects dans `domains.txt`
3. Regardez les logs pour voir si des certificats sont analysés

### Service inactif
1. Visitez `https://votre-app.onrender.com/health` pour le réveiller
2. Les health checks automatiques devraient le maintenir actif

### Redéployer manuellement
```
Dashboard → Votre service → Manual Deploy → Deploy latest commit
```

## 💡 Conseils

1. **Domaines spécifiques:** Utilisez des domaines spécifiques pour éviter trop de faux positifs
2. **Notifications:** Ne surveillez pas trop de domaines génériques (risque de spam)
3. **Logs:** Consultez régulièrement les logs pour voir l'activité
4. **Webhook:** Ne partagez JAMAIS votre webhook Discord publiquement

## 🔗 Ressources

- [Documentation Render](https://render.com/docs)
- [Render Status](https://status.render.com/)
- [Support Render](https://render.com/support)
- [CertStream API](https://certstream.calidog.io/)

## 📝 Checklist de déploiement

- [ ] Repository Git créé et pushé
- [ ] `domains.txt` configuré avec vos domaines
- [ ] Compte Render créé
- [ ] Web Service créé sur Render
- [ ] Variable `DISCORD_WEBHOOK` configurée
- [ ] Service déployé avec succès
- [ ] Health check accessible
- [ ] Première alerte test reçue sur Discord
- [ ] Logs vérifiés dans le dashboard

✅ Votre monitoring CertStream est opérationnel!
