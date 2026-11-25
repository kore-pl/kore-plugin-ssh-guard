# Divulgation des vulnérabilités de sécurité

Ce fichier décrit la procédure de divulgation des vulnérabilités de ce dépôt de plugin (id `ssh-guard`) ; ce n'est pas un document de conception de sécurité.

## Périmètre

Couvre : l'implémentation de `SSH 加固插件` (id `ssh-guard`), la déclaration des capacités dans `info.json`, le front-end `web/` et les artefacts de `make dist`.

Non couvert : les problèmes du noyau et du protocole — signalez-les selon le [SECURITY.md de kore](https://github.com/kore-pl/kore/blob/main/SECURITY.md) ; signalez également les vulnérabilités connues des dépendances tierces au projet amont.

## Versions prises en charge

| Version | État | Notes |
| --- | --- | --- |
| `0.4.0` (dernière version) | ✅ Acceptée et corrigée | Les correctifs de sécurité ne sont fournis que pour la dernière version de patch |
| Versions `0.x` antérieures | ❌ Non prises en charge | Veuillez d'abord mettre à niveau vers la dernière version |

Pendant `0.x`, la prise en charge est minimale : seul le dernier patch d'une branche minor reçoit des correctifs ; les patchs antérieurs ne sont pas rétroportés.

## Surface d'attaque de ce dépôt

- **Méthodes RPC** : toutes les méthodes `ssh-guard.*` (voir `README.md`) ; une validation de paramètres manquante peut entraîner une élévation de privilèges ou une injection.
- **capabilities** : `info.json.capabilities` est la surface d'autorisation complète du plugin ; chaque déclaration supplémentaire est une voie d'attaque de plus.
- **Processus séparé et UDS** : le plugin s'exécute en processus séparé ; le socket est créé par le shell hôte, `chown kore-<id>`, mode `0600` ; contourner les permissions du socket ou se connecter au socket d'un autre plugin est une vulnérabilité.
- **Surface d'écriture hôte** : toute écriture hors des capabilities réellement accordées (fichiers / processus / réseau / base de données) est une vulnérabilité.
- **Front-end** : `web/` s'exécute dans un iframe d'origine séparée et communique avec le shell hôte via postMessage ; XSS, falsification de messages et lecture de données inter-plugins sont des problèmes de frontière de sécurité.

## Signalement

1. **Préférez un Security Advisory GitHub** : page Security de ce dépôt → "Report a vulnerability" (canal privé, aucun issue public).
2. **E-mail de secours** : `pengtang1024@users.noreply.github.com`, objet `[kore security] ssh-guard`.
3. **N'ouvrez pas d'issue public et ne collez pas de PoC dans les discussions ou PR.**
4. Incluez : version affectée, étapes de reproduction ou PoC, évaluation de l'impact, caractère public éventuel et préférence de crédit.

## Délais et divulgation

- Accusez réception et donnez une première évaluation sous **72 heures** ; un plan suit pour les problèmes complexes.
- Coordinez la divulgation après correction, avec une fenêtre par défaut de **90 jours** ; consultez d'abord si le problème est activement exploité.
- Consignez les correctifs de sécurité dans `CHANGELOG.md` après publication (sans détails d'exploitation) et publiez un avis de sécurité si nécessaire.

## Remerciements

Le crédit est donné dans les notes de version avec le consentement du rapporteur ; anonyme sur demande.
