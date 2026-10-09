# Bascule 019 — préparation seulement (C4 non accordée)

Source : `dddur75/qg`, main, `file/019-robin-core-extraction.md`, décision C4.
Aucune opération de ce document n’a été exécutée. Qualité relit et fusionne ;
David décide C4. La PR « phase 5 — activation » reste brouillon, attend-C4.

## Secrets de collecte à créer dans robin-core — noms seulement

- `ODDS_API_KEY`
- `R2_ACCOUNT_ID`
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_BUCKET_NAME`

Le secret C2 `NG_ARTIFACTS_READ_TOKEN` existe déjà pour le jumeau. Il est limité
à Actions/Contents en lecture dans robin-stades-ng, et ne sert pas à collecter.
Aucune valeur ne doit entrer dans git, un commentaire, une PR ou un journal.

## Conditions avant toute activation

- C4 explicite de David, les PR précédentes fusionnées par Qualité et tests verts.
- 7 jours consécutifs de jumeau identique **depuis la dernière fusion modifiant
  src/ ou scripts/** ; toute nouvelle fusion de ces chemins remet le compteur à zéro.
- Quota d’artefacts GitHub disponible : l’upload fait partie de la livraison.
- Environnement `robin-autonomous-relay-v1` : attente de 60 minutes, branche
  `main` seulement via politique personnalisée, aucun secret dans cet environnement.
- Variable de dépôt `ROBIN_AUTONOMOUS_RELAY_GENERATION` égale à
  `4c150973fc3d486e3738f80716019839ac2c4126644849d336e267e6929e6d87`.
- Même stock R2 `robin/autonomous-lab/ROBIN_AUTONOMOUS_LAB_20261004`, aucune
  réinitialisation des compteurs à vie ; plafonds 5 requêtes/créneau et
  140 requêtes/280 crédits sur 24 h inchangés.
- Le mandat et le garde-fou de relais expirent le **2026-11-03T23:59:59Z**.
  La collecte au-delà de cette date n’est pas acquise : C4 doit couvrir une
  prolongation du mandat et du garde-fou, sur la même génération et sans
  reset des compteurs, avant une PR distincte relue par Qualité.
- L’explorateur Windows reste configuré pour robin-stades-ng jusqu’à la bascule.
  Après bascule, utiliser `--repository dddur75/robin-core` et comparer Q1/Q3.

## Ordre de bascule — heure creuse, au plus tard le 2026-11-02

1. David crée les cinq secrets de collecte ci-dessus dans robin-core.
2. Arrêter le relais de robin-stades-ng (annuler les runs en cours/en attente)
   et désactiver `.github/workflows/prospective-deep-scheduler.yml`.
3. Qualité vérifie qu’aucune chaîne n’est active dans **les deux dépôts**.
4. Seulement après C4, activer collecte/fraîcheur dans robin-core : Qualité
   peut sortir la PR d’activation du brouillon et la fusionner. Ses seules
   modifications sont les schedules : collecte `13 * * * *`, fraîcheur
   `17 * * * *` et `47 * * * *`, comme les anciens watchdogs/moniteurs.
5. Lancer **un seul bootstrap** dans collecte.yml, sur main, origin=bootstrap,
   mode=collect, génération ci-dessus, chain_id=0, parent_run_id=0, sequence=0.
   Le bootstrap ne touche ni fournisseur ni R2 ; il arme le premier relais.
   Le watchdog peut déjà avoir armé ce relais : vérifier l’inventaire et ne
   pas créer une seconde chaîne ; la réconciliation ignore un relais actif.
6. Qualité constate dans « Relève 019 » : R2 VERIFIED ; au plus 5 nouvelles
   requêtes ; continuité des compteurs à vie ; 24 h ≤140/280 ; au plus un
   créneau manqué ; un seul chain_id actif sur les deux dépôts. Vérifier le
   téléchargement des quatre fichiers livrés et Q1/Q3 dans l’explorateur.

Les jobs ECHEC_LIVRAISON et le moniteur doivent nommer toute livraison en
échec. Le moniteur garde les échecs de toutes les tentatives pendant 24 h,
malgré un rejeu réussi ; le seuil d’âge du créneau est 3 h (2 h + 1 h tolérée).

## Retour arrière C4 — ordre impératif

1. Arrêter le relais de robin-core : annuler tous ses runs en cours/en attente.
2. Désactiver son workflow de collecte.
3. Vérifier qu’aucune chaîne n’est active dans les deux dépôts.
4. Réactiver le workflow de collecte de robin-stades-ng.
5. Y lancer **un seul bootstrap sans fournisseur**.
6. Vérifier qu’une seule chaîne est active et que les compteurs à vie restent continus.

Reconfigurer l’explorateur pour robin-stades-ng pendant le retour arrière.
Ne jamais réamorcer les compteurs R2 ni lancer une capture manuelle directe.

## Après la bascule — C5 distincte

Après 7 jours de production sans incident : décision C5, retrait du jumeau,
de ses scripts/tests et du secret NG_ARTIFACTS_READ_TOKEN, puis archivage
robin-stades-ng par David. Trois workflows restent : tests, collecte, fraîcheur.
