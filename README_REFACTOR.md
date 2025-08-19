# Refactor qualité de code & structure (partie 3)

Modifs faites :
- Extraction de TOUT le CSS inline des templates Jinja2 vers `app/static/app.css` (charge unique, cache navigateur).
- Ajout du `<link rel="stylesheet" ...>` dans tous les templates et suppression des balises `<style>`.
- Découpage des routes en modules par domaine sous `app/blueprints/` **sans casser les endpoints existants** :
  - `blueprints/auth.py` (`/`, `/logout`)
  - `blueprints/evenements.py` (`/evenement*`)
  - `blueprints/fiches.py` (`/fiche*`)
  - `blueprints/tickets.py` (`/tickets*`)
  - `blueprints/admin.py` (`/admin*`)
  - `blueprints/public.py` (`/autorite*`, `/share*`)
- `app/routes.py` devient un simple agrégateur qui crée `main_bp` et appelle `register()` dans chaque module.
- Aucune modification des noms d’endpoints (`main_bp.*`) -> compatibilité avec les `url_for('main_bp.xxx')` existants.

Déploiement :
1) Remplacer le dossier `app/` par celui de ce répertoire _ou_ fusionner les fichiers modifiés.
2) Rebuilder l'image Docker si vous l'utilisez.

Tests rapides :
- Démarrer: `python run.py` puis naviguer sur les pages principales (login, dashboard, fiches, tickets).
- Les exports PDF/CSV, sauvegarde/restauration et liens d’autorité doivent fonctionner comme avant.

Prochaines étapes possibles :
- Ajouter des schémas de validation (pydantic/marshmallow) pour les endpoints JSON.
- Centraliser les décorateurs d’authz/roles dans un module `app/security.py` et les réutiliser dans les blueprints.
- Pagination serveur + filtres sur les tableaux.
