# RBAC Governance Dashboard

Outil local de gouvernance RBAC / Entra ID composé de :

- un backend FastAPI dans [app.py](/home/marc/openclaw-runtime/workspace/rbac-arch/app.py)
- un dashboard React/Vite dans [dashboard](/home/marc/openclaw-runtime/workspace/rbac-arch/dashboard)
- une policy YAML dans [config/governance-policy.yaml](/home/marc/openclaw-runtime/workspace/rbac-arch/config/governance-policy.yaml)

Le projet a évolué d’un simple prototype de matrice RBAC vers un outil avec :

- synchronisation Azure via `az`
- moteur de recommandations structuré
- catalogue de gouvernance explicite
- overrides applicables depuis l’UI
- `Policy Studio` pour éditer la policy
- pagination et recherche serveur pour mieux tenir la charge

Guide utilisateur simplifié :

- [USER_GUIDE.md](/home/marc/openclaw-runtime/workspace/rbac-arch/USER_GUIDE.md)

## Installation

### Prérequis

- Python 3.11 ou plus récent
- Node.js 20 ou plus récent
- `npm`
- Azure CLI `az` si tu veux utiliser `Sync Azure`

Vérification rapide :

```bash
python3 --version
node --version
npm --version
az version
```

### Backend Python

Le backend dépend de :

- FastAPI
- Uvicorn
- Pydantic
- PyYAML

Le fichier de dépendances est : [requirements.txt](/home/marc/openclaw-runtime/workspace/rbac-arch/requirements.txt)

Installation recommandée :

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Frontend Dashboard

Le frontend React/Vite a déjà ses manifests :

- [dashboard/package.json](/home/marc/openclaw-runtime/workspace/rbac-arch/dashboard/package.json)
- [dashboard/package-lock.json](/home/marc/openclaw-runtime/workspace/rbac-arch/dashboard/package-lock.json)

Installation :

```bash
cd dashboard
npm install
cd ..
```

### Déploiement Docker

La stack Docker est définie dans :

- [Dockerfile.api](/home/marc/openclaw-runtime/workspace/rbac-arch/Dockerfile.api)
- [Dockerfile.dashboard](/home/marc/openclaw-runtime/workspace/rbac-arch/Dockerfile.dashboard)
- [docker-compose.yml](/home/marc/openclaw-runtime/workspace/rbac-arch/docker-compose.yml)

Lancement :

```bash
docker compose up --build
```

Puis ouvrir :

- dashboard : `http://127.0.0.1:8111`
- API : `http://127.0.0.1:8110`

Notes importantes pour Docker :

- le service `api` embarque Azure CLI
- `docker-compose.yml` monte `${HOME}/.azure` en lecture seule dans le conteneur pour réutiliser une session `az login` du poste hôte
- la policy [config/governance-policy.yaml](/home/marc/openclaw-runtime/workspace/rbac-arch/config/governance-policy.yaml) est montée en volume via `./config:/app/config` pour persister les modifications faites depuis `Policy Studio`
- le dataset [aad-groups-rbac.json](/home/marc/openclaw-runtime/workspace/rbac-arch/aad-groups-rbac.json) est aussi monté pour persister les imports locaux

### Azure CLI

Pour que `Sync Azure` fonctionne, il faut :

```bash
az login
az account show
```

Selon ton contexte, il peut aussi être utile de sélectionner explicitement la bonne subscription :

```bash
az account set --subscription "<subscription-id-ou-nom>"
```

## Lancement

Mode local/dev :

```bash
./run-stack-local.sh
```

Mode alternatif :

```bash
./run-stack.sh
```

Mode production dashboard statique :

```bash
./run-stack-local.sh prod
```

Ports par défaut :

- API : `http://127.0.0.1:8110`
- Dashboard : `http://127.0.0.1:8111`

### Démarrage manuel

Si tu ne veux pas utiliser les scripts, tu peux démarrer les deux briques séparément.

Backend :

```bash
source .venv/bin/activate
uvicorn app:app --host 0.0.0.0 --port 8110 --reload
```

Frontend :

```bash
cd dashboard
npm run dev -- --host 0.0.0.0 --port 8111
```

Build production du dashboard :

```bash
cd dashboard
npm run build
cd ..
API_BASE=http://127.0.0.1:8110 DASH_PORT=8111 DIST_DIR=./dashboard/dist node serve-dashboard.mjs
```

Arrêt de la stack Docker :

```bash
docker compose down
```

## Architecture

### Backend

Le backend FastAPI gère :

- le dataset courant des groupes
- la synchronisation Azure
- la policy et le catalogue de gouvernance
- la génération de matrice d’accès
- les findings de conformité et les recommandations

Principaux concepts :

- `CURRENT_GROUPS` : jeu de groupes chargé en mémoire
- `CURRENT_SOURCE` : source active (`default`, `uploaded`, `azure_sync`)
- `DEFAULT_POLICY` : policy par défaut embarquée
- `group_catalog` : matchers + overrides explicites
- `governance_profiles` : profils de gouvernance utilisés par le moteur de décision

### Frontend

Le dashboard React contient :

- un écran principal avec onglets `Overview`, `Findings`, `Matrix`, `Overrides`
- une page séparée `Policy Studio` sur `/policy-studio`

Direction actuelle de l’UI :

- shell translucide et cartes type glass
- header segmenté
- filtres uniformisés
- vues séparées pour éviter l’effet “mur de blocs”

## Endpoints principaux

### Données et sync

- `GET /config`
- `POST /upload-config`
- `POST /aad/load-groups`
- `POST /aad/sync-azure`
- `POST /config/reset`

### Policy et gouvernance

- `GET /policy`
- `PUT /policy`
- `GET /policy/group-catalog`
- `GET /policy/group-catalog/suggest-overrides`
- `PUT /policy/group-catalog/overrides`
- `GET /policy/allowed-roles`
- `GET /policy/domains`
- `POST /policy/naming/preview`
- `POST /policy/groups/export`
- `POST /policy/validate-group`

### Audit et analyse

- `POST /generate-matrix`
- `GET /generate-matrix/json`
- `GET /compliance-check`
- `GET /simulate`
- `GET /export`

## Ce qui a été mis en place

### 1. Correction du proxy API

Problème initial :

- le dashboard Vite appelait `/api/...`
- le backend exposait des routes sans préfixe `/api`
- en dev, le proxy ne réécrivait pas le chemin, ce qui provoquait des `404`

Correctif :

- ajout de la réécriture `/api -> /` dans [dashboard/vite.config.js](/home/marc/openclaw-runtime/workspace/rbac-arch/dashboard/vite.config.js)

### 2. Correction des `403` en local

Problème :

- `access_control.enabled` pouvait être actif dans la policy
- sans headers `x-aad-groups`, le rôle résolu était `none`
- les endpoints protégés renvoyaient `403`

Correctif :

- fallback local dans [app.py](/home/marc/openclaw-runtime/workspace/rbac-arch/app.py)
- si la requête vient du loopback et qu’aucun contexte AAD n’est fourni, le rôle local devient `admin`

But :

- permettre au dashboard local de fonctionner sans reverse proxy d’auth

### 3. Passage à un moteur de recommandations structuré

Avant :

- simples risques + suggestion texte assez vague

Maintenant :

- `findings` structurés avec :
  - `severity`
  - `confidence`
  - `basis`
  - `rule_id`
  - `evidence`
  - `recommendation`
- `recommendations` agrégées
- `recommendation_model` pour expliciter les entrées et limites

Le moteur distingue maintenant :

- ce qui est observé
- ce qui vient de la policy
- ce qui reste dérivé/heuristique

### 4. Ajout d’un référentiel de gouvernance explicite

La policy contient maintenant :

- `governance_profiles`
- `group_catalog.matchers`
- `group_catalog.overrides`

Objectif :

- réduire les heuristiques basées uniquement sur le nom
- rattacher les groupes à des profils explicites
- contrôler :
  - type de groupe
  - domaine
  - environnement
  - criticité
  - scope maximal attendu

### 5. APIs pour gérer les overrides

Ajouts backend :

- `GET /policy/group-catalog`
- `GET /policy/group-catalog/suggest-overrides`
- `PUT /policy/group-catalog/overrides`

Objectif :

- proposer des overrides à partir des groupes synchronisés
- les valider proprement
- éliminer les ambiguïtés de classification

### 6. `Policy Studio`

Une vraie page de gestion de policy a été ajoutée au dashboard :

- route : `/policy-studio`
- menu accessible depuis le header

Contenu :

- édition JSON des blocs techniques :
  - `requirements`
  - `allowed_roles_by_group_type`
  - `forbidden_rules`
  - `access_control`
- édition visuelle des blocs métier :
  - `governance_profiles`
  - `group_catalog.matchers`
  - `group_catalog.overrides`

### 7. Dashboard V2 / V3 / V4

Le dashboard a été retravaillé en plusieurs étapes :

#### V2

- section `Governance catalog overrides`
- suggestions visibles dans l’UI
- application directe d’un override

#### V3

- pagination serveur pour la matrice
- pagination serveur pour les findings
- recherche serveur

#### V4

- onglets :
  - `Overview`
  - `Findings`
  - `Matrix`
  - `Overrides`

Objectif :

- rendre l’outil lisible quand le nombre de groupes augmente

### 8. Refonte visuelle du dashboard

Dernière passe UI :

- fond et surfaces plus travaillés
- header renforcé
- menu principal élargi
- actions harmonisées
- grilles et hauteurs de contrôles uniformisées
- cartes stats plus intentionnelles
- tableau plus lisible

## Pagination et recherche serveur

Les gros volumes sont maintenant gérés côté backend.

`POST /generate-matrix` accepte notamment :

- `search`
- `page`
- `page_size`
- `sort_by`
- `sort_dir`

`GET /compliance-check` accepte notamment :

- `search`
- `findings_page`
- `findings_page_size`
- `findings_severity`

Le dashboard consomme déjà ces paramètres pour éviter de charger toute la matrice ou tous les findings côté navigateur.

## Arborescence utile

- [app.py](/home/marc/openclaw-runtime/workspace/rbac-arch/app.py) : API FastAPI et moteur de recommandations
- [config/governance-policy.yaml](/home/marc/openclaw-runtime/workspace/rbac-arch/config/governance-policy.yaml) : policy active
- [requirements.txt](/home/marc/openclaw-runtime/workspace/rbac-arch/requirements.txt) : dépendances Python
- [run-stack-local.sh](/home/marc/openclaw-runtime/workspace/rbac-arch/run-stack-local.sh) : lancement local principal
- [run-stack.sh](/home/marc/openclaw-runtime/workspace/rbac-arch/run-stack.sh) : variante de lancement
- [docker-compose.yml](/home/marc/openclaw-runtime/workspace/rbac-arch/docker-compose.yml) : stack de déploiement Docker
- [Dockerfile.api](/home/marc/openclaw-runtime/workspace/rbac-arch/Dockerfile.api) : image backend
- [Dockerfile.dashboard](/home/marc/openclaw-runtime/workspace/rbac-arch/Dockerfile.dashboard) : image frontend
- [dashboard/package.json](/home/marc/openclaw-runtime/workspace/rbac-arch/dashboard/package.json) : dépendances frontend
- [dashboard/src/App.jsx](/home/marc/openclaw-runtime/workspace/rbac-arch/dashboard/src/App.jsx) : UI principale
- [dashboard/src/index.css](/home/marc/openclaw-runtime/workspace/rbac-arch/dashboard/src/index.css) : design system léger

## Limitations actuelles

- pas de `requirements-dev.txt` ni de pipeline de tests automatisés
- pas de gestion lockée des dépendances Python
- les scripts d’installation restent simples, sans bootstrap unique
- la sync Azure en Docker dépend de l’état du répertoire hôte `${HOME}/.azure`

### `POST /generate-matrix`

Supporte maintenant :

- `search`
- `page`
- `page_size`
- `sort_by`
- `sort_dir`

Retourne dans `matrix.summary.pagination` :

- `page`
- `page_size`
- `total`
- `total_pages`
- `has_prev`
- `has_next`

### `GET /compliance-check`

Supporte maintenant :

- `search`
- `findings_page`
- `findings_page_size`
- `findings_severity`

Retourne :

- `findings`
- `findings_total`
- `findings_pagination`

## Fichiers importants

- [app.py](/home/marc/openclaw-runtime/workspace/rbac-arch/app.py) : API FastAPI et logique métier
- [config/governance-policy.yaml](/home/marc/openclaw-runtime/workspace/rbac-arch/config/governance-policy.yaml) : policy active
- [dashboard/src/App.jsx](/home/marc/openclaw-runtime/workspace/rbac-arch/dashboard/src/App.jsx) : dashboard et `Policy Studio`
- [dashboard/src/index.css](/home/marc/openclaw-runtime/workspace/rbac-arch/dashboard/src/index.css) : style du dashboard
- [dashboard/vite.config.js](/home/marc/openclaw-runtime/workspace/rbac-arch/dashboard/vite.config.js) : proxy dev
- [run-stack-local.sh](/home/marc/openclaw-runtime/workspace/rbac-arch/run-stack-local.sh) : lancement local recommandé
- [run-stack.sh](/home/marc/openclaw-runtime/workspace/rbac-arch/run-stack.sh) : autre script de lancement
- [serve-dashboard-local.mjs](/home/marc/openclaw-runtime/workspace/rbac-arch/serve-dashboard-local.mjs) : gateway statique/proxy local

## Limites actuelles

Le moteur est meilleur qu’au départ, mais il reste des limites :

- pas encore de logs d’activité Azure / Entra
- pas d’expansion des groupes imbriqués
- pas de données PIM d’éligibilité / activation
- certains groupes peuvent encore tomber sur des heuristiques si aucun matcher ni override ne les couvre
- le dashboard est mieux structuré, mais pas encore virtualisé pour des volumes très élevés

## Prochaines évolutions logiques

- tri cliquable dans la matrice
- regroupement par profil / domaine / owner / criticité
- drill-down entre overview, findings et matrice
- import d’overrides depuis une source externe
- enrichissement du moteur par logs d’usage réels
- support plus fin de PIM

## Vérifications réalisées pendant les changements

Les modifications ont été validées au fil de l’eau avec :

- `python3 -m py_compile app.py`
- `npm run build`

Le projet est actuellement dans un état où :

- le dashboard compile
- la policy est éditable via l’UI
- les suggestions d’overrides sont applicables
- les findings et la matrice sont paginés côté serveur
