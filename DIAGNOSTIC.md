# 🔍 Diagnostic : 0 Certificats Analysés

## Symptôme observé

```
✓ Connecté au flux CertStream à 19:41:38 UTC
--- Statistiques ---
 Certificats analysés: 0
 Alertes envoyées: 0
--------------------
```

**Problème** : Le service se connecte mais n'analyse aucun certificat, ce qui signifie qu'aucun message n'est reçu du flux CertStream.

## 🧪 Diagnostic

### Causes possibles :

1. **Le flux CertStream est en panne**
   - Status : https://certstream.calidog.io/
   - Twitter : https://twitter.com/Cali_Dog

2. **Problème de pare-feu/réseau Render**
   - Render bloque les connexions WebSocket sortantes
   - Problème de proxy/NAT

3. **Problème de la bibliothèque websocket-client**
   - Version incompatible
   - Bug de parsing

4. **Le handler on_message n'est jamais appelé**
   - Connexion établie mais aucun message reçu
   - Problème de subscription au flux

## ✅ Tests à effectuer

### Test 1 : Vérifier le status de CertStream

```bash
# Vérifier que le site répond
curl -I https://certstream.calidog.io/

# Devrait retourner : HTTP/2 200
```

### Test 2 : Tester localement (sur votre machine)

```bash
# Installer les dépendances
pip install websocket-client

# Lancer le test
python test_certstream.py

# Devrait afficher des certificats en quelques secondes
```

### Test 3 : Vérifier dans les logs Render

Recherchez dans les logs :
- `📥 Premier message reçu` → Si présent, on_message est appelé ✅
- `📊 X certificats analysés` → Si présent, le traitement fonctionne ✅

## 🔧 Solutions

### Solution 1 : Forcer la version du protocole WebSocket

```python
# Dans ct_monitor.py, modifier :
ws.run_forever(
    ping_interval=20,
    ping_timeout=8,
    reconnect=3,
    skip_utf8_validation=True  # ← Ajouter cette ligne
)
```

### Solution 2 : Utiliser un autre endpoint CertStream

CertStream a plusieurs endpoints :

```python
# Essayer l'endpoint "full"
WS_URL = "wss://certstream.calidog.io/full-stream"

# Ou l'endpoint "domains-only"  
WS_URL = "wss://certstream.calidog.io/domains-only"
```

### Solution 3 : Ajouter plus de debug

```python
def on_message(ws, message):
    print(f"🔍 Message brut reçu: {len(message)} bytes")
    # ... reste du code
```

### Solution 4 : Vérifier les restrictions réseau Render

Render peut avoir des restrictions sur les WebSockets. Vérifier :
- Dashboard Render → Settings → Network
- Documentation Render sur WebSockets

## 📊 Logs de debug ajoutés

La nouvelle version inclut :

```python
# Au premier message reçu
📥 Premier message reçu - Type: certificate_update

# Tous les 100 certificats
📊 100 certificats analysés
📊 200 certificats analysés
...
```

Si vous ne voyez AUCUN de ces logs, cela signifie que `on_message` n'est jamais appelé.

## 🎯 Action immédiate recommandée

1. **Redéployer** avec la nouvelle version (qui inclut les logs de debug)

```bash
git add ct_monitor.py test_certstream.py
git commit -m "Add debug logs for certstream"
git push
```

2. **Observer les logs Render** pendant 2-3 minutes

3. **Résultats attendus** :

   **SI vous voyez** `📥 Premier message reçu` :
   - ✅ La connexion fonctionne
   - ✅ Les messages sont reçus
   - → Le problème est dans le traitement

   **SI vous NE voyez PAS** ce message :
   - ❌ Aucun message n'est reçu
   - → Problème de connexion/réseau/CertStream

4. **Tester localement** avec `test_certstream.py` pour comparer

## 🆘 Si rien ne fonctionne

### Alternative 1 : Utiliser l'API Certificate Transparency directement

Au lieu de CertStream, interroger les logs CT directement :
- Google CT : `https://ct.googleapis.com/logs/`
- Cloudflare CT : `https://ct.cloudflare.com/`

### Alternative 2 : Utiliser crt.sh

API publique de recherche de certificats :
```bash
curl "https://crt.sh/?q=example.com&output=json"
```

Peut être interrogé via polling (toutes les 5 minutes).

### Alternative 3 : Contacter le support

- **Render Support** : Vérifier les restrictions WebSocket
- **CertStream** : Vérifier si le service est opérationnel

## 📝 Checklist de diagnostic

- [ ] CertStream accessible via HTTP
- [ ] Test local fonctionne (`test_certstream.py`)
- [ ] Logs Render montrent la connexion
- [ ] Message `📥 Premier message reçu` visible
- [ ] Compteur de certificats augmente
- [ ] Pas d'erreur de parsing JSON
- [ ] Webhook Discord configuré correctement

---

**Prochaine étape** : Redéployez avec les logs de debug et observez pendant 2-3 minutes. Partagez les nouveaux logs ici pour diagnostic plus précis.
