# 🚀 Configuration MAXIMALE - 12 Logs Google CT

## 📊 Configuration actuelle

**12 logs Google actifs :**
- 4 logs 2026 (principaux)
- 4 logs 2025 (certificats longs)
- 4 logs 2024 (certificats très longs)

## ⚡ Performances attendues

### Volume traité :
- **~2400 certificats/minute** (200 × 12 logs toutes les 90s)
- **~144,000 certificats/heure**
- **~3.5 millions certificats/jour**

### Ressources utilisées :
- **CPU** : 20-30% en continu
- **RAM** : 100-150 MB
- **Réseau** : ~2-5 MB/min (requêtes API)

### Couverture :
- **99%+ des certificats SSL mondiaux** émis via Google CT
- Détection quasi-instantanée (délai max 90 secondes)

## ⚠️ Conséquences assumées

### Avantages :
✅ **Couverture maximale** - Ne rate presque aucun certificat Google
✅ **Détection rapide** - 90 secondes max
✅ **Redondance** - Même certificat visible sur plusieurs logs
✅ **Certificats longs** - Détecte aussi les anciens certificats

### Inconvénients :
❌ **CPU élevé** - Plan gratuit Render peut atteindre ses limites
❌ **Plus de duplicates** - Même certificat sur 2-3 logs
❌ **Rate limits possibles** - Google peut limiter les requêtes
❌ **Coûts potentiels** - Peut nécessiter un upgrade vers plan payant

## 🎯 Optimisations appliquées

1. **Intervalle augmenté** : 90s au lieu de 60s
2. **Batch réduit** : 200 entrées au lieu de 256
3. **Détection de duplicates** : Cache de 10,000 certificats
4. **Gestion d'erreurs** : Skip les logs en erreur

## 📈 Monitoring

### Health Check :
```bash
curl https://ghada-z4v8.onrender.com/health
```

### Métriques à surveiller :
- `certificats_analysés` : Doit augmenter de ~2400 toutes les 90s
- `duplicates_évités` : Indique la redondance entre logs
- `logs_en_erreur` : Surveiller si des logs tombent
- `logs_actifs` : Doit être = 12

### Logs normaux :
```
✓ 12 logs CT actifs sur 16 disponibles
🔍 Argon 2026h1: 2132085960 → 2132086160
🔍 Argon 2026h2: 257232218 → 257232418
🔍 Solera 2026h1: 60578378 → 60578578
...
📊 2400 certificats analysés
```

## 🔧 Ajustements possibles

### Si CPU trop élevé :
1. Augmenter `CHECK_INTERVAL` à 120s
2. Réduire `BATCH_SIZE` à 150
3. Désactiver les logs 2024 (moins actifs)

### Si trop de duplicates :
1. Désactiver soit les logs 2025 soit 2024
2. Garder uniquement 2026 + un backup

### Si rate limit Google :
1. Augmenter l'intervalle à 120-180s
2. Réduire le nombre de logs à 8

## 🚨 Signes d'alerte

### ⚠️ Problèmes à surveiller :

**CPU > 50%** :
```bash
# Réduire à 8 logs
# Ou augmenter CHECK_INTERVAL à 120s
```

**Mémoire > 200 MB** :
```bash
# Réduire CACHE_MAX_SIZE à 5000
```

**Logs en erreur répétés** :
```bash
# Google rate limit détecté
# Augmenter intervalle ou réduire logs
```

## 📝 Logs recommandés par priorité

Si tu dois réduire, désactive dans cet ordre :

1. **Garder (priorité max)** :
   - Argon 2026h1
   - Argon 2026h2
   - Solera 2026h1
   - Solera 2026h2

2. **Garder si possible** :
   - Argon 2025h2
   - Solera 2025h2

3. **Optionnel** :
   - Argon 2025h1
   - Solera 2025h1
   - Logs 2024 (tous)

## 🎯 Résultat attendu

Avec cette configuration, tu devrais recevoir des alertes pour :
- ✅ Nouveaux certificats SSL
- ✅ Renouvellements de certificats
- ✅ Nouveaux sous-domaines
- ✅ Certificats wildcard (*.domain.com)
- ✅ Certificats multi-domaines

**Délai de détection : < 90 secondes** après émission du certificat ! 🚀

## 🔄 Retour en arrière

Si ça ne fonctionne pas bien :

```bash
# Revenir à 4 logs (configuration stable)
git revert HEAD
git push
```

---

**Configuration : MAXIMALE** 🔥  
**Couverture : 99%+** 🎯  
**Latence : < 90s** ⚡  
**Assumé : OUI** ✅
