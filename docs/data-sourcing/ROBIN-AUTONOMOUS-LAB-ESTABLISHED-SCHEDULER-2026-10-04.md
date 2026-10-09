# Planificateur établi du laboratoire Robin — 2026-10-04

## Autorité successeur

Le mandat utilisateur du 2026-10-04 autorise les corrections de code, tests,
configuration et workflows directement nécessaires à la collecte autonome. Ce
successeur ne remplace que la route de déclenchement. Le runtime Robin, les cinq
ligues, les marchés `h2h` et `totals`, l'espace R2, les compteurs append-only,
les plafonds fournisseur et l'échéance du manifeste parent restent inchangés.
L'historique des deux architectures de déclenchement précédentes reste
immuable.

## Deuxième échec similaire observé

Après la fusion normale de la PR 86, le workflow 92, ID `374470410`, était actif
sur le `main` `2c8cfdd00461b35058dda573e4c64a3cb36711ee`, avec un cron horaire à la
minute 37. GitHub n'a créé aucun run pour les occurrences naturelles
`2026-10-04T17:37:00Z` et `2026-10-04T18:37:00Z`, observées chacune pendant au
moins trente minutes. L'inventaire du workflow est resté vide. L'échec se situe
donc avant tout job et a ajouté zéro lecture de secret, requête fournisseur,
crédit, lecture ou écriture R2 et artifact public.

Ce deuxième échec similaire produit `FAIL_AND_REDESIGN` et un retour à E1. Il
ne prouve pas une cause interne à GitHub; il prouve seulement que l'identité
nouvelle du workflow 92 n'a pas matérialisé les cinq occurrences observées au
total sur ses deux versions.

## Preuve de route établie

Le workflow 61, ID `321915839`, chemin
`.github/workflows/prospective-deep-scheduler.yml`, a matérialisé 139 runs
naturels `schedule` historiques. Les runs `31234773039`, `31311550636` et
`31322020695` proviennent tous du même blob de workflow et du cron exact
`13 * * * *`. Cette histoire prouve que cette identité a déjà reçu les événements
du planificateur; elle ne garantit pas leur matérialisation future.

## Redesign minimal

Pendant que le workflow 61 reste désactivé, son ancien corps API-Football et
PostgreSQL est remplacé intégralement par le collecteur Robin vérifié. Son chemin,
son ID et son cron `13 * * * *` sont conservés. Le déclenchement manuel, les
secrets API-Football et PostgreSQL et l'ancien scheduler prospectif disparaissent
de cette route.

La bascule opérationnelle est ordonnée et fail-closed : désactiver le workflow
92, fusionner et vérifier le `main` exact, vérifier que 61 est toujours lié au
chemin attendu, puis activer uniquement 61. Son gate exige que 92 et toutes les
autres routes capables de lire un secret fournisseur soient désactivées avant
toute lecture de secret. Le groupe de concurrence et les créneaux R2 idempotents
restent identiques. Le fichier 92 est conservé désactivé comme rollback jusqu'à
la preuve naturelle `capture → replay sans fournisseur → capture`.

## Bornes conservées

Ce successeur ajoute zéro requête et zéro crédit aux budgets autorisés. Chaque
run continue d'utiliser les créneaux UTC déterministes de deux heures, le CAS
comptable avant transport, au plus cinq requêtes par nouveau créneau, aucun
retry fournisseur et aucun rattrapage. Les limites restent 140 requêtes et 280
crédits sur 24 heures, puis 4 000 et 8 000 sur 30 jours glissants, avec les 16
requêtes et 34 crédits historiques toujours comptabilisés.

Aucun achat, pari, backfill, promotion, publication sociale, nouveau fournisseur,
nouveau stockage, nouveau runner ou secret exposé n'est autorisé. Le schedule
GitHub reste susceptible de retard ou d'abandon; cette limite de plateforme doit
rester visible et ne doit jamais être masquée par un faux résultat.
