# Robin — reprise autonome du déclenchement V2 (2026-10-05)

## Autorité et succession

Ce document succède sans réécriture à l'overlay
`ROBIN-AUTONOMOUS-LAB-TRIGGER-RECOVERY-2026-10-05.md`. L'autorité propriétaire,
le writer Git unique C0, les plafonds, l'expiration et les interdictions restent
inchangés. Cette version intègre le run naturel tardif apparu après la coupure du
premier overlay et relève seulement la base comptable conservatrice.

## Nouveau fait observé

- Le workflow établi `321915839` a finalement matérialisé le run naturel
  `37245531093` le 4 octobre 2026 à 23:56:06Z sur `main`
  `563c37901647e5b3cce29a141cea153dabbe5941`.
- Son artifact normalisé `11319146929` a été conservé et vérifié. Le run a
  réservé cinq requêtes et dix crédits, n'a émis aucune requête fournisseur et a
  conservé puis relu son rapport privé R2 avec le statut `VERIFIED`.
- Les cinq branches ont reproduit avant transport le diagnostic expurgé
  `DNS_RESOLUTION / RECURRING_DNS_RESOLUTION_EXPIRED`. Le tableau contient donc
  zéro capture nouvelle et uniquement les 21 759 lignes historiques marquées
  `CARRY_FORWARD_STALE`.
- La base cumulée conservatrice devient 26 requêtes et 54 crédits fournisseur.
  Sur les 24 heures glissantes du receipt, elle est 10 requêtes et 20 crédits;
  sur 30 jours, 26 et 54. Le débit fournisseur réellement facturé pour les runs
  échoués reste non mesuré. Les crédits IA restent non mesurés.

Cette matérialisation tardive ne rétablit pas `schedule` comme horloge primaire :
elle confirme qu'un ancien événement peut arriver après la fenêtre attendue. Le
cron reste seulement un watchdog provider-free. Le correctif d'ordre temporel
DNS reste requis avant tout nouvel appel réel.

## Mécanisme actif après validation

Le workflow établi reste l'unique circuit fournisseur. Un bootstrap manuel ne
fait que semer une sonde provider-free. Deux relais automatiques distincts,
protégés par l'environnement exact `robin-autonomous-relay-v1`, doivent réussir
avant une décision append-only `PASS_AND_SCALE`. L'environnement est limité à
l'unique branche `main`, sans secret, avec un wait timer d'une minute pendant la
sonde puis soixante minutes pendant la collecte.

Bootstrap et watchdog partagent une concurrence de contrôle en file FIFO. Les
relais automatiques valides partagent une concurrence séparée; un dispatch
manuel invalide ne peut pas remplacer leur attente. Chaque relais vérifie son
parent, la génération, le head `main`, l'expiration, le timer et l'unique règle
de branche. Il démontre l'existence exacte de son successeur avant d'autoriser
le job de capture. Le watchdog relit la même configuration avant tout réarmement.

Le job de capture conserve seul les secrets fournisseur et R2. Avant transport,
il relit la comptabilité durable et applique les créneaux R2 idempotents de deux
heures, les plafonds 140/280 sur 24 heures et 4 000/8 000 sur 30 jours, ainsi que
la base cumulée 26/54 sans reset. Une branche indisponible reste incomplète sans
arrêter les autres.

## Bornes inchangées

- Aucun achat, abonnement, pari, backfill, promotion ou nouveau fournisseur.
- Aucun payload fournisseur brut dans Git; R2 reste la source brute immuable.
- Diagnostics publics limités à l'étape, au code stable, à la classe d'exception,
  à `errno` et au statut HTTP lorsqu'ils existent, sans secret ni URL à clé.
- Trois heures de travail actif supplémentaires au maximum, attente passive
  exclue; point de passage le 5 octobre 2026 à 08:00 Europe/Paris.
- Les verrous scientifiques et de sécurité restent inchangés. La stabilité de
  vingt-quatre heures ne sera déclarée qu'après écoulement réel de cette durée.
