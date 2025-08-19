import os
import click
import importlib

from app import create_app
try:
    from app.extensions import db
except Exception:
    from app import db  # type: ignore

try:
    from werkzeug.security import generate_password_hash
except Exception:
    generate_password_hash = None  # type: ignore

def _discover_models():
    """Import app.models and return classes that subclass db.Model."""
    try:
        mod = importlib.import_module('app.models')
    except Exception as e:
        print(f"[init-db] Warning: cannot import app.models: {e}")
        return []
    models = []
    for name, obj in vars(mod).items():
        try:
            if isinstance(obj, type) and issubclass(obj, db.Model):
                models.append(obj)
        except Exception:
            continue
    return models

def _choose_user_model(models):
    # Prefer names that look like User/Utilisateur
    preferred_names = {'user', 'users', 'utilisateur', 'utilisateurs', 'compte', 'account'}
    for cls in models:
        n = getattr(cls, '__tablename__', '').lower()
        if n in preferred_names or cls.__name__.lower() in {'user','utilisateur','account','compte'}:
            return cls
    # Fallback: any model that has a username/email-like field
    for cls in models:
        for fld in ('username','nom_utilisateur','login','email'):
            if hasattr(cls, fld):
                return cls
    return models[0] if models else None

def _first_attr(obj, names):
    for n in names:
        if hasattr(obj, n):
            return n
    return None

@click.group()
def cli():
    pass

@cli.command('init-db')
def init_db():
    """Create tables and ensure an admin/admin exists (idempotent)."""
    app = create_app(os.environ.get('FLASK_CONFIG', 'prod'))
    with app.app_context():
        # Import models so metadata is populated, then create tables
        models = _discover_models()
        db.create_all()

        user_model = _choose_user_model(models)
        if not user_model:
            print("[init-db] No user-like model found; skipping admin bootstrap.")
            return

        username_field = _first_attr(user_model, ('username','nom_utilisateur','login','email'))
        if not username_field:
            print("[init-db] No username/email field; skipping admin bootstrap.")
            return

        # Determine identifier and lookup value
        if username_field == 'email':
            admin_identifier_value = 'admin@example.com'
        else:
            admin_identifier_value = 'admin'

        existing = user_model.query.filter(getattr(user_model, username_field) == admin_identifier_value).first()
        if existing:
            print("[init-db] Admin already exists; nothing to do.")
            return

        # Create new admin
        admin = user_model()

        # Set username/email
        setattr(admin, username_field, admin_identifier_value)

        # Set password
        if hasattr(admin, 'set_password'):
            admin.set_password('admin')
        else:
            # Try common hash fields
            if generate_password_hash and hasattr(admin, 'password_hash'):
                admin.password_hash = generate_password_hash('admin')
            elif generate_password_hash and hasattr(admin, 'mot_de_passe_hash'):
                admin.mot_de_passe_hash = generate_password_hash('admin')
            elif hasattr(admin, 'password'):
                admin.password = 'admin'  # last resort

        # Admin flags
        if hasattr(admin, 'is_admin'):
            admin.is_admin = True
        if hasattr(admin, 'role'):
            try:
                setattr(admin, 'role', 'admin')
            except Exception:
                pass
        if hasattr(admin, 'actif'):
            try:
                setattr(admin, 'actif', True)
            except Exception:
                pass
        if hasattr(admin, 'type_utilisateur'):
            try:
                if getattr(admin, 'type_utilisateur') in (None, '', 'user'):
                    setattr(admin, 'type_utilisateur', 'admin')
            except Exception:
                pass

        db.session.add(admin)
        db.session.commit()
        print("[init-db] Admin user created.")

if __name__ == '__main__':
    cli()
