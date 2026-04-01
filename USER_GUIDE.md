# Guide Utilisateur

## Objectif

Cet outil permet de :

- charger ou synchroniser des groupes Entra ID / Azure
- visualiser une matrice d’accès RBAC
- détecter des findings de conformité
- obtenir des recommandations de remédiation
- gérer une policy de gouvernance
- classer explicitement les groupes via des overrides

## Démarrage rapide

Lancer la stack locale :

```bash
./run-stack-local.sh
```

Ouvrir :

- dashboard : `http://127.0.0.1:8111`
- API : `http://127.0.0.1:8110`

## Navigation

Le menu principal contient :

- `Dashboard`
- `Policy Studio`

Dans le `Dashboard`, les onglets sont :

- `Overview`
- `Findings`
- `Matrix`
- `Overrides`

## Workflow recommandé

### 1. Charger les données

Deux options :

- `Importer AAD (JSON/CSV)` pour charger un export
- `Sync Azure` pour récupérer les groupes via Azure CLI

Si tu veux repartir de zéro :

- `Reset config`

### 2. Explorer la synthèse

Dans `Overview`, tu peux voir :

- le volume global des groupes
- les groupes à risque
- la distribution des rôles
- le nombre de membres par groupe

### 3. Examiner les findings

Dans `Findings`, tu peux :

- rechercher un groupe, une règle ou un type de finding
- filtrer par sévérité
- parcourir les pages de résultats

Chaque finding contient :

- une sévérité
- un niveau de confiance
- une description
- une action recommandée
- la base de décision

### 4. Vérifier la matrice d’accès

Dans `Matrix`, tu peux :

- rechercher un groupe, owner, scope ou rôle
- parcourir les pages de la matrice
- voir rapidement quels groupes ont des rôles sensibles ou de l’accès data

### 5. Traiter les overrides

Dans `Overrides`, l’outil propose des classifications de groupes.

Usage :

- regarder le profil proposé
- vérifier la confiance
- appliquer l’override si la proposition est correcte

But :

- réduire les heuristiques
- rattacher explicitement les groupes à un profil de gouvernance

## Policy Studio

`Policy Studio` sert à gérer la gouvernance.

Tu peux y modifier :

- les règles globales
- les rôles autorisés par type de groupe
- les règles interdites
- les profils de gouvernance
- les matchers automatiques
- les overrides explicites
- le contrôle d’accès à l’outil

Deux niveaux existent :

- blocs techniques en JSON
- blocs métier via édition visuelle

Quand tu modifies la policy :

- clique sur `Save policy`
- recharge si besoin avec `Reload`

## Comment lire les recommandations

Les recommandations sont meilleures qu’un simple scoring, mais elles ne sont pas magiques.

Elles s’appuient sur :

- les rôles observés
- le scope observé
- l’owner
- la policy
- les profils de gouvernance
- les overrides

Elles sont plus fiables quand :

- les groupes sont bien classés
- les overrides sont renseignés
- les tags métier sont corrects

## Cas d’usage conseillé

Pour un usage propre :

1. lancer un `Sync Azure`
2. ouvrir `Overrides`
3. appliquer ou corriger les classifications proposées
4. ouvrir `Findings`
5. traiter les groupes les plus critiques
6. ajuster la policy dans `Policy Studio` si nécessaire

## Limites à garder en tête

L’outil ne remplace pas une revue IAM complète.

Aujourd’hui, il ne couvre pas encore :

- l’usage réel des permissions dans les logs
- les groupes imbriqués
- PIM en détail
- toutes les exceptions métier automatiquement

## Fichiers utiles

- doc technique : [README.md](/home/marc/openclaw-runtime/workspace/rbac-arch/README.md)
- policy active : [config/governance-policy.yaml](/home/marc/openclaw-runtime/workspace/rbac-arch/config/governance-policy.yaml)

