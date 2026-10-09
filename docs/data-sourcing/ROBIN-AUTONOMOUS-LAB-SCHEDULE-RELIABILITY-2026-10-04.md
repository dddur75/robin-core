# Fiabilité du planificateur du laboratoire Robin — 2026-10-04

## Portée

Cette autorisation succède uniquement au déclenchement planifié de
`ROBIN_AUTONOMOUS_LAB_20261004`. Elle ne remplace ni son runtime, ni son espace
R2, ni ses compteurs append-only, ni ses plafonds fournisseur. Le manifeste
parent et son historique restent immuables.

## Observation reproduite

Le workflow 92 était actif sur le `main`
`9b5afa27a039c0434934fda6f951102f555481d9`, les onze anciennes routes
fournisseur étaient désactivées et aucun run du workflow 92 n'existait. GitHub
n'a matérialisé aucun événement `schedule` pour les occurrences nominales
10:17 UTC et 12:17 UTC. C0 a ensuite désactivé puis réactivé le workflow à
12:47 UTC afin de réenregistrer son planificateur; l'occurrence 14:17 UTC n'a
pas davantage produit de run dans les trente minutes suivantes.

Ces absences se situent avant tout job: aucun secret n'a été lu, aucune requête
fournisseur ni écriture R2 n'a été émise et aucun crédit n'a été consommé. La
documentation GitHub indique qu'un événement planifié peut être retardé ou
abandonné avant création de run.

## Correctif autorisé

Le workflow existant reste `schedule`-only, sur `main`, sérialisé globalement et
sans `workflow_dispatch`. Son unique cron devient horaire à la minute 37. Le
runtime conserve des créneaux UTC déterministes de deux heures. Un run horaire
répété dans un créneau déjà fermé est résolu par l'idempotence durable avant
lecture du secret et avant transport; il n'ajoute donc aucune capture, requête
ou réservation.

Cette redondance offre deux occasions de planification par créneau de données,
sans nouveau runner, fournisseur, stockage, canal public, retry fournisseur ou
backfill.

## Bornes conservées

Avec les bornes inclusives du calcul glissant, treize créneaux de deux heures
peuvent intersecter une fenêtre de vingt-quatre heures et 361 une fenêtre de
trente jours. En conservant aussi les 16 requêtes et 34 crédits historiques,
les plafonds théoriques sont donc 81 requêtes et 164 crédits sur vingt-quatre
heures, puis 1 821 requêtes et 3 644 crédits sur trente jours. Ils restent
inférieurs aux plafonds autorisés de 140/280 et 4 000/8 000. Les contrôles
runtime restent l'autorité finale et échouent fermés avant tout transport.

Les interdictions demeurent inchangées: aucun achat, pari, promotion,
publication sociale, backfill, exposition de secret ou payload brut dans Git.
L'autorisation expire le 2026-11-03 à 23:59:59 UTC et ne se renouvelle pas
elle-même.
