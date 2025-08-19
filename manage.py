import click
from werkzeug.security import generate_password_hash
import importlib

try:
    from app import create_app
except Exception as e:
    raise

# Try to import db from extensions first (preferred), fallback to app
try:
    from app.extensions import db  # type: ignore
except Exception:
    from app import db  # type: ignore

app = create_app()

@click.group()
def cli():
    pass

def _find_user_model():
    # Import app.models to register mappers
    try:
        import app.models as models
    except Exception as e:
        raise RuntimeError(f"Impossible d'importer app.models: {e}")
    # Try common class names
    for name in ("Utilisateur", "User", "Users", "Account", "Compte"):
        if hasattr(models, name):
            return getattr(models, name)
    # Last resort: find first class with likely attributes
    for attr in dir(models):
        obj = getattr(models, attr)
        if getattr(obj, '__tablename__', None) in ("utilisateur", "user", "users", "account", "compte"):
            return obj
    raise RuntimeError("Modèle utilisateur introuvable (essaye Utilisateur/User).")

@cli.command("init-db")
def init_db():
    """Crée le schéma et bootstrap admin/admin si manquant (idempotent)."""
    with app.app_context():
        # Créer le schéma
        db.create_all()

        UserModel = _find_user_model()

        # Déterminer le champ username/login/email
        username_fields = ["nom_utilisateur", "username", "login", "email"]
        password_fields = ["mot_de_passe_hash", "password_hash", "password"]

        # Construire un filtre pour trouver l'utilisateur 'admin'
        username_field = None
        for f in username_fields:
            if hasattr(UserModel, f):
                username_field = f
                break
        if username_field is None:
            raise RuntimeError("Champ username/login/email introuvable sur le modèle utilisateur.")

        # Vérifier si 'admin' existe déjà
        existing = UserModel.query.filter(getattr(UserModel, username_field)=="admin").first()
        if existing:
            print("[init-db] admin existe déjà — OK")
            return

        # Créer l'utilisateur admin
        admin = UserModel()

        # Renseigner username
        setattr(admin, username_field, "admin")

        # Renseigner rôles/champs booléens si présents
        for field, value in ("role", "admin"), ("type_utilisateur", "admin"), ("is_admin", True), ("actif", True):
            if hasattr(UserModel, field):
                setattr(admin, field, value)

        # Déterminer où écrire le hash du mot de passe
        pw_field = None
        for f in password_fields:
            if hasattr(UserModel, f):
                pw_field = f
                break

        # Générer un hash court compatible VARCHAR(128)
        # -> forcer PBKDF2-SHA256 (Werkzeug), ~80-100 caractères
        pw_hash = generate_password_hash("admin", method="pbkdf2:sha256", salt_length=16)

        if pw_field:
            setattr(admin, pw_field, pw_hash)
        elif hasattr(admin, "set_password") and callable(getattr(admin, "set_password")):
            # Si set_password existe mais utilise un schéma trop long (scrypt),
            # on tente d'injecter notre hash directement via attribut connu.
            # S'il n'y a vraiment pas d'attribut, on appelle set_password en dernier recours.
            try:
                admin.set_password("admin")  # type: ignore[attr-defined]
            except Exception as e:
                raise RuntimeError(f"Aucun champ mot_de_passe_hash/password_hash et set_password a échoué: {e}")
        else:
            raise RuntimeError("Aucun champ mot_de_passe_hash/password_hash ni set_password trouvé.")

        db.session.add(admin)
        db.session.commit()
        print("[init-db] admin/admin créé avec succès")

if __name__ == "__main__":
    cli()
