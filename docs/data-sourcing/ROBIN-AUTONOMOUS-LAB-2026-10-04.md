# Mandat propriétaire — laboratoire autonome Robin

Reçu le 2026-10-04. Ce mandat succède aux restrictions temporaires du pilote
et de la mission de résultat, sans réécrire leurs preuves ni leurs échecs.

## Résultat confié à C0

Reprendre le fonctionnement réel fusionné sur
`0be96131d1c9c6d7337629f906ead3b282304293` et préserver les quinze captures
vérifiées du run GitHub Actions `37153158456`. C0 reste l'unique writer Git et
peut diagnostiquer, corriger, tester, ouvrir une PR, fusionner normalement et
activer la collecte nécessaire sans demander une autorisation par sous-tâche.

Robin doit devenir un laboratoire personnel utilisable : collecte réellement
récurrente sans dépendance à Codex ni à l'ordinateur du propriétaire,
conservation durable, relecture vérifiée, dernier résultat stable, recherche et
filtres, fraîcheur, couverture, consommation et incidents compréhensibles.

Le circuit autorisé reste celui déjà éprouvé : fournisseur The Odds API,
cinq ligues (`soccer_epl`, `soccer_france_ligue_one`,
`soccer_germany_bundesliga`, `soccer_italy_serie_a`,
`soccer_spain_la_liga`), région `eu`, marchés `h2h,totals`, R2 privé pour les
payloads bruts et GitHub Actions pour l'orchestration et l'artifact normalisé.
Aucun nouveau fournisseur, hébergeur public, mécanisme d'attestation, pari,
backfill ni promotion scientifique n'est autorisé.

## Fonctionnement et présentation

La collecte gère créneaux, doublons, redémarrages, échecs et quotas. Une
réservation durable précède chaque effet fournisseur. Un relancement ne duplique
pas une capture et ne remet pas les compteurs à zéro. Une tentative ambiguë
reste comptée. Une ancienne capture ne devient jamais fraîche. Une branche en
échec n'empêche pas les ligues sœurs de finir.

Le tableau distingue :

- panne de collecte ;
- donnée fraîche, ancienne ou indisponible ;
- marché absent chez un bookmaker ;
- marché dupliqué ou incohérent ;
- consommation observée et réservée.

Il fournit une première exploration descriptive des données réellement reçues
(couverture, dispersion des cotes et mouvements observés) sans présenter aucun
edge comme validé.

Le canal d'artifact GitHub Actions normalisé du dépôt public, déjà utilisé par
la mission précédente, peut être réutilisé. Il ne contient ni payload brut, ni
clé, ni URL secrète. Les payloads et rapports privés détaillés restent dans R2.

## Budgets fail-closed

Les plafonds fournisseur cumulatifs sont :

- 140 requêtes HTTP et 280 crédits sur toute fenêtre glissante de 24 heures ;
- 4 000 requêtes HTTP et 8 000 crédits sur toute fenêtre glissante de 30 jours.

Les diagnostics et nouvelles tentatives comptent. La graine historique conserve
16 requêtes cumulées et une borne conservatrice de 34 crédits, dont quatre
crédits réservés pour l'ancien échec incertain. Le compteur fournisseur observé
ne reconstitue pas à lui seul le passé. Toute incohérence de comptabilité,
écriture ambiguë, solde insuffisant ou plafond proche arrête les nouveaux appels
avant émission.

Seuls les services et crédits existants peuvent être utilisés. Achats,
rechargements, changements d'abonnement, renouvellements automatiques, paris et
publication sociale restent interdits.

## Garanties conservées

La provenance, les horodatages, l'absence de fuite temporelle, l'historique des
échecs et le veto du Council restent obligatoires. Les verrous suivants ne sont
pas assouplis : `STORAGE_PAUSED=true`, `P3_P4_PAUSED=true`,
`PRODUCTION_LOCKED=true`, `REAL_BETS=false`, `NO_BET_DEFAULT=true`,
`PROMOTION_LOCKED=true`, `SOCIAL_PUBLISHING_ENABLED=false` et
`DEMO_MODE_ENABLED=false`.

Le manifeste successeur expire le `2026-11-03T23:59:59Z`. La collecte peut
continuer après le rapport final dans cette fenêtre, jusqu'à instruction
contraire. Au-delà, un mandat successeur explicite est requis ; le workflow ne
peut pas prolonger sa propre autorité.

La livraison exige plusieurs runs distincts déclenchés par `schedule`, la
relecture de leurs objets immuables, le tableau rendu et vérifié, ainsi qu'un
bilan qui sépare les données réellement reçues du code simplement préparé.
