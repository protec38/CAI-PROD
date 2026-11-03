# CAI — suivi opérationnel

Application Flask, PostgreSQL et Redis. Python 3.12.

## Installation locale

Créer un environnement virtuel, puis installer `requirements-dev.txt`. Définir
`FLASK_CONFIG=dev` et `ADMIN_PASSWORD` (au moins 12 caractères), puis exécuter :

```sh
python manage.py init-db
python run.py
```

Le mode développement utilise SQLite dans `instance/cai.db` et un limiteur en mémoire.
Les variables doivent être exportées dans le terminal ; le lancement Python direct
ne charge pas automatiquement `.env`.

## Déploiement Docker

Copier `.env.example` vers `.env`, renseigner une clé `SECRET_KEY` aléatoire,
les identifiants PostgreSQL et l'URL correspondante. Définir `ADMIN_PASSWORD`
pour le premier démarrage ou pour remplacer un ancien mot de passe `admin`.
La commande `docker compose up --build -d` initialise le schéma avant de démarrer
les workers. Toute erreur d'initialisation interrompt le démarrage.

Pour une stack déployée depuis Git dans Portainer, renseigner les variables dans
la section **Environment variables** de la stack, puis récupérer la dernière
révision et redéployer. Aucun fichier `.env` n'est requis dans le dépôt cloné.
`POSTGRES_PASSWORD`, `SECRET_KEY` et `DATABASE_URL` sont obligatoires ; réutiliser
les identifiants de la base existante. `POSTGRES_DB` et `POSTGRES_USER` valent
`cai` par défaut : les renseigner si la base existante utilise d'autres noms.
`ADMIN_PASSWORD` est nécessaire uniquement pour créer le premier administrateur
ou remplacer l'ancien mot de passe par défaut. Toutes ces variables sont
transmises explicitement au service web ; elles ne dépendent plus de `env_file`.
En lancement local, Compose peut toujours lire un `.env` à côté du fichier YAML
pour remplacer les `${VARIABLE}` ([documentation Docker](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/)).

Conserver HTTPS en production. Derrière un reverse proxy, définir
`TRUSTED_PROXY_COUNT=1` uniquement si le proxy écrase les en-têtes transférés
et si les clients ne peuvent pas accéder directement au serveur applicatif.
Le contrôle `/healthz` reste accessible en HTTP pour la sonde Docker et renvoie
503 quand PostgreSQL ou Redis est indisponible.

Le fichier `.env` est retiré du suivi Git et exclu de l'image Docker. Les secrets
déjà enregistrés dans l'historique Git doivent être renouvelés au déploiement,
y compris `SECRET_KEY` et le mot de passe PostgreSQL. Modifier la variable
`POSTGRES_PASSWORD` ne change pas le mot de passe d'une base déjà initialisée :
mettre aussi à jour le rôle PostgreSQL et `DATABASE_URL` de manière coordonnée.

## Interface téléphone et tablette

Les fiches du tableau de bord s’affichent en cartes sur téléphone et tablette,
avec leurs boutons Voir, Modifier, Bagages, Sortie et Supprimer directement
accessibles. Le tableau est conservé sur grand écran. La recherche reste visible,
les filtres utilisent des cases à cocher et les autres commandes de l’évènement
sont regroupées sous **Autres actions**.

Les champs ont des libellés associés, une taille de texte adaptée et un clavier
téléphone pour les numéros. Les commandes tactiles principales mesurent au moins
44 px de haut. Les fenêtres Bagages/Sortie adaptent leur hauteur à l’espace
disponible, retiennent le focus clavier et le rendent au bouton d’origine à la
fermeture. Un lien permet d’aller directement aux fiches et les animations sont
réduites lorsque cette préférence est activée dans le navigateur.

Ces styles et comportements sont aussi disponibles hors ligne. Les tests Edge
vérifient les largeurs 320, 390, 768, 1024, 1280 et 1440 px, les débordements,
les filtres, les champs et la navigation au clavier, avec des tailles d’écran
simulées.

## Fiches hors ligne (téléphone, tablette et ordinateur)

Ouvrir le tableau de bord de chaque évènement avec une connexion sur chaque
appareil, et attendre la pastille verte « Synchronisé au serveur ». Le bouton
**Créer une fiche impliquée** utilise le même formulaire avec ou sans réseau.
Après création, l’application revient toujours au **tableau de bord classique**,
avec les mêmes filtres, colonnes et fenêtres Bagages et Sortie. Ce tableau utilise
la dernière copie du serveur et les modifications locales quand le réseau tombe ;
il n’y a pas de second tableau de bord. Le formulaire et le tableau fonctionnent
sans ressources externes.

Le bouton **Voir** ouvre aussi les fiches sans connexion : identité, coordonnées,
notes, bagages, liens humain/animal et historique sont conservés lors de la
préparation de l’évènement. Une fiche créée sur l’appareil est consultable avant
son premier envoi au serveur.

Le bouton **Supprimer** reste utilisable hors ligne, selon les droits du compte.
Une fiche déjà envoyée reste marquée **Suppression en attente du serveur** jusqu’à
confirmation, puis disparaît du tableau. Une fiche locale jamais envoyée est
retirée immédiatement et ses actions en attente sont annulées. Les reçus de
suppression empêchent les nouvelles tentatives de recréer la fiche ou de supprimer
une autre fiche qui aurait repris le même identifiant numérique.

Les bagages et les sorties peuvent être saisis sans connexion sur une fiche
existante ou créée hors ligne. La ligne devient orange **En attente du serveur** ;
les bagages, le statut de sortie et les compteurs se mettent à jour immédiatement
et restent présents après rechargement. La synchronisation crée d’abord les
fiches, puis applique les actions dans leur ordre de saisie. L’heure de sortie
conservée est celle de sa déclaration sur l’appareil.

Chaque action possède un accusé de réception pour éviter les doublons lors
d’une nouvelle tentative. Un conflit de numéro de bagage conserve la ligne
orange avec son message d’erreur ; il peut être corrigé depuis la même fenêtre.
Les modifications de bagages préservent les ajouts simultanés d’autres opérateurs.

La petite pastille en haut indique **Mode hors ligne** en orange, puis
**Synchronisé au serveur** en vert après confirmation de tous les envois.
Elle reste orange si des fiches attendent encore leur confirmation ; cliquer
sur la pastille affiche les détails et permet de relancer la synchronisation.

Chaque fiche affiche un point **orange : en attente du serveur**, ou **vert :
sur le serveur**. Un numéro `001-LOCAL-…` identifie provisoirement une fiche sur
l'appareil. À la synchronisation, le serveur attribue le prochain numéro libre,
et l'écran affiche le nouveau numéro et l'ancien identifiant provisoire.
Les numéros restent uniques, y compris lors de créations simultanées. Un UUID
rend les tentatives répétées sans doublon si la réponse du serveur est perdue.
L'heure d'arrivée conservée est celle de la saisie, pas celle de la synchronisation.

La synchronisation se relance au retour du réseau, à la réouverture de l'écran,
et toutes les 30 secondes tant que l'application reste ouverte. Si le navigateur
est fermé ou suspendu par le téléphone, rouvrir l'application pour synchroniser.
Une session expirée demande une reconnexion avec le compte d'origine. Les
droits d'accès sont vérifiés à chaque envoi ; une fiche refusée reste orange avec
son message d'erreur. Les envois visent explicitement l'évènement d'origine.

HTTPS est nécessaire (sauf `localhost` en développement). Les fiches en attente
et la copie de la liste sont stockées dans IndexedDB sur cet appareil : utiliser
le même navigateur et conserver ses données jusqu'à la synchronisation. Éviter
la navigation privée ; le navigateur peut effacer ses données locales. La
déconnexion masque l'espace local du compte et conserve ses fiches en attente
pour sa prochaine connexion. Le service worker ne met en cache que l'écran
statique et ses ressources, sans pages authentifiées ni réponses API.

Au déploiement, exécuter `python manage.py init-db` avant de démarrer les
workers (déjà prévu par le démarrage Docker). Cette commande ajoute
`fiche_implique.client_uuid` et son index unique aux bases existantes, et crée
les tables `offline_mutation` et `offline_deletion` des accusés de réception
(incluses dans les sauvegardes). Les tests
de concurrence PostgreSQL sont inclus dans la suite exécutée en CI.

## Sauvegardes et restauration

Les exports contiennent les données opérationnelles, actualités et historiques,
sans les comptes utilisateurs. Une sélection vide n'exporte aucune donnée.
La restauration remplace toutes les données opérationnelles en une transaction ;
un échec conserve les données précédentes. L'option « Forcer » autorise ce
remplacement sur une base non vide. Une sauvegarde partielle remplace donc aussi
les autres événements : conserver une sauvegarde complète avant restauration.

Les comptes existants sont préservés. Les auteurs obligatoires des fiches, tickets
et commentaires doivent exister avec les mêmes identifiants dans la base cible ;
sinon l'import est refusé. Les anciens exports qui omettent actualités et
historiques ne permettent pas de les récupérer. Une restauration réussie ne peut
pas reconstituer des données absentes du fichier source.

## Vérifications

Les nouveaux parcours sont également couverts par `tests/test_features_browser.py`.

```sh
python -m pytest -q
node tests/test_frontend.cjs
python -m playwright install chromium
# Puis CAI_BROWSER_TEST=1 python -m pytest tests/test_offline_browser.py tests/test_responsive_browser.py -q
python -m ruff check app manage.py config.py run.py tests --select E9,F63,F7,F82
python -m pip check
python -m pip_audit -r requirements.txt --no-deps --disable-pip
```

La CI exécute les tests sur SQLite et PostgreSQL 16. Pour PostgreSQL local,
`CAI_TEST_DATABASE_URL` doit désigner une base **réservée aux tests**, car les
tables sont supprimées à la fin de chaque test.

Le test navigateur est aussi exécuté en CI avec Chromium. Sur Windows, définir
`CAI_BROWSER_TEST=1` et `CAI_BROWSER_CHANNEL=msedge` pour utiliser Edge installé.
Il vérifie le rechargement sans réseau, la persistance d'une fiche, la reprise
automatique et la création depuis le formulaire existant.

`requirements.in` liste les dépendances directes ; `requirements.txt` fige les
versions résolues, y compris les dépendances transitives, pour Python 3.12/Linux.
Les bibliothèques inutilisées bcrypt, Flask-Bcrypt, Flask-Migrate et pycountry
ont été retirées. Le parsing ISO utilise désormais la bibliothèque standard.

## Revue du 31 octobre 2026

Corrections : autorisations entre événements, sessions Flask-Login cohérentes,
comptes désactivés ou expirés refusés, suppression et déconnexion par POST avec
CSRF, protection des comptes administrateurs contre les rôles inférieurs,
échappement HTML des fiches/tickets, absence de formules dans les exports Excel,
validation des tickets/actualités, restauration atomique, sauvegardes complètes,
sonde de santé unique, confiance explicite dans le proxy et conteneur sans root.
Les comptes provisoires expirés sont désactivés pour préserver leurs références.

Validation locale : tests Python et JavaScript, analyse des erreurs Python,
résolution Linux des dépendances et audit sans vulnérabilité connue. Docker et
PostgreSQL ne sont pas disponibles localement ; leur validation est configurée
dans la CI et doit être confirmée avant déploiement. Les appels SQLAlchemy
dépréciés et `datetime.utcnow` ont été modernisés en conservant le format UTC
des colonnes existantes.

## Outils supplémentaires et réglages

Depuis le tableau de bord classique, **Outils de l’évènement** rassemble les réglages,
les groupes, les étiquettes, la corbeille et le bilan. **Personnaliser mon affichage**
ouvre les préférences du compte. **Disponibilité hors ligne** indique les évènements
conservés sur cet appareil, la dernière actualisation et les envois en attente.

| Idée | Fonction disponible |
| --- | --- |
| 1 | Modification des champs dans le formulaire habituel, avec ou sans réseau. |
| 2 | Avertissement de doublon sur nom, prénom et date de naissance, avec confirmation avant enregistrement. |
| 3 | Familles / groupes communs aux fiches, liste des membres et recherche dans le tableau de bord. |
| 4 | QR individuel protégé par connexion et autorisation d’évènement, consultable dans le détail. |
| 5 | Étiquettes de fiche ou de bagage : sélection et exemplaires, PDF A4 de 24 étiquettes de 63 × 34 mm, impression à 100 %. |
| 6 | Recherche sur identité, téléphones, Sinus, numéros de fiche et PEC, bagages et groupe. |
| 7 | Corbeille et restauration. Numéro réattribué si nécessaire ; restauration refusée sans perte si un bagage est déjà attribué ailleurs. |
| 8 | Historique avec auteur, date, anciennes et nouvelles valeurs pour les nouvelles opérations. Le suivi antérieur reste conservé. |
| 9 | Brouillon automatique sur cet appareil, reprise ou abandon après rechargement, effacement après enregistrement durable. |
| 10 | Fusion des champs distincts ; choix des valeurs locales ou serveur pour chaque champ en conflit, y compris les champs personnalisés. |
| 11 | État de préparation hors ligne par évènement, dernière actualisation, envois en attente et actualisation à la demande. |
| 14 | Capacité d’accueil des personnes et seuil d’alerte configurable, avec prise en compte des envois locaux en attente. |
| 17 | Jusqu’à 20 champs personnalisés par évènement : texte, nombre, date, liste ou case à cocher ; obligatoires ou facultatifs, pour personnes et/ou animaux. |
| 18 | Listes de destinations, transports, zones et compétences. Destinations et transports acceptent aussi la saisie libre. |
| 21 | Verrouillage manuel ou après inactivité (1, 5, 10, 15 ou 30 minutes), déverrouillage par mot de passe avec connexion. |
| 23 | Bilan PDF des accueils, sorties, bagages, arrivées et orientations reçus par le serveur. Synchroniser les appareils avant le bilan définitif. |
| 24 | Préférences personnelles : colonnes facultatives, compteurs et affichage compact. |

Avant le redémarrage des workers, lancer la commande de mise à jour existante
`python manage.py init-db` pour créer les nouvelles tables. Les réglages d’évènement,
métadonnées, historiques et éléments de corbeille sont inclus dans les sauvegardes
opérationnelles ; les préférences restent liées aux comptes préservés.

Ouvrir une fois le tableau de bord avec une connexion sur chaque appareil pour
préparer les nouveaux formulaires et scripts. Les réessais conservent leurs
identifiants stables. Une fiche restaurée conserve son QR et reçoit une nouvelle
identité : une ancienne suppression hors ligne ne peut pas la supprimer à nouveau.
Les fiches locales supprimées avant leur premier envoi sont récupérables depuis
**Disponibilité hors ligne**, dans la corbeille de cet appareil. Après envoi, utiliser
la corbeille de l’évènement.
