# Scénario d'incident : une version de `requests` utilisée par MiniShop est annoncée compromise

Hypothèse : un avis (GHSA / presse) annonce que certaines versions de `requests` ont été publiées sur
PyPI par un compte compromis (même schéma que LiteLLM, mars 2026). Notre dépôt épingle une version
exacte avec hashes dans `app/requirements.txt`.

## 1. Détecter
- Alerte Dependabot / GitHub Security (onglet *Security*), échec du job `pip-audit` du cron quotidien,
  avis GHSA/OSV ou presse.
```bash
pip-audit -r app/requirements.txt --desc      # la version épinglée est-elle listée ?
```

## 2. Évaluer l'exposition
- Quelle version exactement ? Dans quels environnements (dev, CI, images Docker, prod) ? Quand a-t-elle été installée ?
```bash
grep -A1 '^requests==' app/requirements.txt             # version verrouillée dans le dépôt
git log -p --follow -S'requests==' -- app/requirements.txt   # depuis quand ?
pip freeze | grep -i requests                            # version dans l'environnement local
pipdeptree -r -p requests                                # qui dépend de requests (transitif) ?
docker run --rm minishop:latest pip show requests        # version dans l'image déployée
```
- Vérifier si la version compromise a été installée : date de build de l'image / des jobs CI par rapport à la
  fenêtre de publication de la version malveillante.
- Le SBOM (`sbom.json`, job CI) indique ce que contient chaque build.
- Priorisation : CVSS + EPSS + catalogue CISA KEV + code atteignable (`/fetch` utilise `requests`).

## 3. Contenir
- Geler les déploiements et bloquer la version (contrainte dans `requirements.in`, ex. `requests!=X.Y.Z`).
- Si malware avéré : isoler les hôtes/conteneurs concernés, couper l'egress réseau, arrêter les pods/containers.
```bash
docker ps --filter ancestor=minishop:latest -q | xargs -r docker stop
pip download requests==X.Y.Z --no-deps -d /tmp/inspect   # inspecter sans exécuter (pas d'install)
```
- Chercher des indicateurs de compromission (fichiers `.pth`, services de persistance, connexions sortantes
  vers des domaines inconnus) :
```bash
find / -name "*.pth" -newer app/requirements.txt 2>/dev/null
grep -rE "https?://" /var/log 2>/dev/null | grep -v partenaire.com | head
```

## 4. Corriger
```bash
pip-audit -r app/requirements.txt --fix                  # ou montée manuelle
pip-compile --upgrade-package requests --generate-hashes -o app/requirements.txt app/requirements.in
pip-audit -r app/requirements.txt --strict && pytest -q tests
pip cache purge                                          # purger les caches locaux
docker build --no-cache -t minishop:fixed app            # rebuild propre, environnement neuf
```
- Pinner une version vérifiée (antérieure à la compromission ou publiée après correction), puis redéployer.

## 5. Si la version est malveillante : rotation des secrets
Tout secret accessible au process ou à la CI pendant l'exposition est considéré comme compromis :
- `SECRET_KEY` (invalide toutes les sessions), identifiants base de données, clés cloud, jetons CI/GitHub,
  jetons de publication PyPI, clés SSH.
- Rotation immédiate (pas seulement un upgrade), révocation des anciennes valeurs, analyse des logs réseau
  (exfiltration), rebuild des images depuis un état connu sain, redéploiement.
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"   # nouvelle SECRET_KEY
```

## 6. Retour d'expérience (post-mortem sans blâme)
- Ce qui a aidé : versions exactes + hashes, `pip-audit` planifié, Dependabot, SBOM, actions CI épinglées par SHA.
- Ce qui n'aurait pas aidé : `--require-hashes` seul (le fichier malveillant est légitimement publié par le compte compromis).
- Actions : délai avant d'adopter une nouvelle version (Dependabot `cooldown`), Trusted Publishing (OIDC) plutôt
  que des jetons durables, egress restreint en CI/prod, secrets minimaux dans la CI, SLA de correction
  (critique 24-48 h, haute 7 j), ajout d'une règle de CI si un nouveau contrôle aurait détecté l'incident.
