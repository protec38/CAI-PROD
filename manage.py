import os
import sys
import click

from app import create_app
try:
    # extensions may be under app.extensions
    from app.extensions import db
except Exception:
    # fallback for legacy layout
    from app import db  # type: ignore

@click.group()
def cli():
    pass

@cli.command("init-db")
def init_db():
    """Create all tables and ensure admin/admin exists (idempotent)."""
    app = create_app(os.environ.get("FLASK_CONFIG", "prod"))
    with app.app_context():
        # Create tables
        db.create_all()

        # Try to find a User model dynamically (Utilisateur/User)
        user_model = None
        for cls in db.Model._decl_class_registry.values():  # type: ignore[attr-defined]
            try:
                if hasattr(cls, "__tablename__") and cls.__tablename__ in ("utilisateur", "users", "user", "utilisateurs"):
                    user_model = cls
                    break
            except Exception:
                continue
        # fallback: find any model with a username-like field
        if user_model is None:
            for cls in db.Model._decl_class_registry.values():  # type: ignore[attr-defined]
                for cand in ("nom_utilisateur", "username", "email"):
                    if hasattr(cls, cand):
                        user_model = cls
                        break
                if user_model:
                    break

        if user_model is None:
            click.echo("No user-like model found; skipping admin bootstrap.")
            sys.exit(0)

        # Determine username field
        username_field = "nom_utilisateur" if hasattr(user_model, "nom_utilisateur") else ("username" if hasattr(user_model, "username") else "email")
        # Determine admin flag field
        admin_field = "is_admin" if hasattr(user_model, "is_admin") else ("role" if hasattr(user_model, "role") else None)

        # Does admin exist?
        exists = user_model.query.filter(getattr(user_model, username_field)=="admin").first()
        if not exists:
            user = user_model()
            setattr(user, username_field, "admin")
            # password
            raw_pass = "admin"
            if hasattr(user, "set_password"):
                try:
                    user.set_password(raw_pass)
                except Exception:
                    pass
            elif hasattr(user, "mot_de_passe_hash"):
                try:
                    from werkzeug.security import generate_password_hash
                    setattr(user, "mot_de_passe_hash", generate_password_hash(raw_pass))
                except Exception:
                    setattr(user, "mot_de_passe_hash", raw_pass)  # worst-case
            elif hasattr(user, "password_hash"):
                try:
                    from werkzeug.security import generate_password_hash
                    setattr(user, "password_hash", generate_password_hash(raw_pass))
                except Exception:
                    setattr(user, "password_hash", raw_pass)
            elif hasattr(user, "password"):
                setattr(user, "password", raw_pass)

            # admin flag if present
            if admin_field:
                try:
                    setattr(user, admin_field, True if admin_field=="is_admin" else "admin")
                except Exception:
                    pass

            # actif if present
            if hasattr(user, "actif"):
                try:
                    setattr(user, "actif", True)
                except Exception:
                    pass

            db.session.add(user)
            db.session.commit()
            click.echo("Admin user created (admin/admin).")
        else:
            click.echo("Admin already exists; nothing to do.")

if __name__ == "__main__":
    cli()
