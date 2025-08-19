import os
import click
from werkzeug.security import generate_password_hash
from app import create_app
from app.extensions import db

app = create_app(os.environ.get("FLASK_CONFIG", "prod"))

@click.group()
def cli():
    pass

@cli.command("init-db")
def init_db():
    """Create tables and bootstrap admin/admin (idempotent)."""
    with app.app_context():
        from importlib import import_module
        # Import models module to register models with SQLAlchemy
        try:
            import_module("app.models")
        except Exception as e:
            # models.py may not exist; ignore
            print("[init-db] Warning: could not import app.models:", e)

        db.create_all()

        # Try to discover user model
        user_model = None
        # Walk through db.Model subclasses
        for cls in db.Model.__subclasses__():
            name = cls.__name__.lower()
            cols = cls.__table__.columns.keys() if hasattr(cls, "__table__") else []
            if {"username", "password_hash"} <= set(cols) or {"nom_utilisateur", "mot_de_passe_hash"} <= set(cols) or "is_admin" in cols:
                user_model = cls
                break

        if not user_model:
            print("[init-db] No user model found; skipping admin bootstrap.")
            return

        # Find username field
        username_field = "username"
        for cand in ("nom_utilisateur", "username", "login", "email"):
            if hasattr(user_model, cand):
                username_field = cand
                break

        # Query existing admin
        admin = user_model.query.filter(getattr(user_model, username_field) == "admin").first()
        if admin:
            print("[init-db] admin already exists; nothing to do.")
            return

        # Create admin with PBKDF2-SHA256 (fits VARCHAR(128))
        admin = user_model()
        setattr(admin, username_field, "admin")

        # Try set_password; else populate known hash fields
        if hasattr(admin, "set_password"):
            try:
                admin.set_password("admin")
            except Exception:
                pass

        hash_value = generate_password_hash("admin", method="pbkdf2:sha256")
        for passwd_field in ("mot_de_passe_hash", "password_hash", "mot_de_passe", "password"):
            if hasattr(admin, passwd_field):
                setattr(admin, passwd_field, hash_value)
                break

        # Default flags
        for flag_field, value in (("is_admin", True), ("actif", True), ("role", "admin"), ("type_utilisateur", "admin")):
            if hasattr(admin, flag_field):
                setattr(admin, flag_field, value)

        db.session.add(admin)
        db.session.commit()
        print("[init-db] admin/admin créé avec succès")

if __name__ == "__main__":
    cli()
