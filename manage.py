import os
import click
from flask import Flask
from sqlalchemy import inspect, text
from werkzeug.security import generate_password_hash

from app import create_app
from app.extensions import db

app = create_app()

def _find_user_model():
    try:
        from app.models import Utilisateur as M
        return M
    except Exception:
        try:
            from app.models import User as M  # type: ignore
            return M
        except Exception:
            raise RuntimeError("Impossible de trouver le modèle Utilisateur/User")

def _set_password(user, raw_password: str):
    # Essaye set_password si dispo, sinon set hash dans attribut connu
    if hasattr(user, "set_password"):
        user.set_password(raw_password)
        return True
    pwd_hash = generate_password_hash(raw_password, method="pbkdf2:sha256")
    for field in ("mot_de_passe_hash","password_hash","mot_de_passe","password"):
        if hasattr(user, field):
            setattr(user, field, pwd_hash)
            return True
    raise RuntimeError("Aucun champ de mot de passe pris en charge (mot_de_passe_hash/password_hash/...)")

def _get_username_filter(Model, username: str):
    # essaie les champs classiques
    for field in ("nom_utilisateur","username","login","email"):
        if hasattr(Model, field):
            return getattr(Model, field) == username
    raise RuntimeError("Aucun champ d'identifiant utilisateur (nom_utilisateur/username/login/email)")

@click.group()
def cli():
    pass

@cli.command("init-db")
def init_db():
    with app.app_context():
        db.create_all()
        _ensure_evenement_archive_columns()
        _ensure_provisional_expiry_column()
        _ensure_share_link_label_column()
        Model = _find_user_model()
        # Existence de admin ?
        fil = _get_username_filter(Model, "admin")
        exists = db.session.query(db.exists().where(fil)).scalar()
        if not exists:
            # Créer l'admin
            user = Model()
            # Remplir quelques champs courants si existants
            for field, value in (
                ("nom_utilisateur","admin"),
                ("username","admin"),
                ("login","admin"),
                ("role","admin"),
                ("type_utilisateur","admin"),
                ("is_admin", True),
                ("actif", True),
            ):
                if hasattr(user, field):
                    setattr(user, field, value)
            _set_password(user, "admin")
            db.session.add(user)
            db.session.commit()
            print("[init-db] admin/admin créé avec succès")
        else:
            print("[init-db] admin existe déjà")


def _ensure_provisional_expiry_column():
    """Ensure legacy databases receive the provisional expiry column and index."""
    engine = db.engine
    inspector = inspect(engine)
    if not inspector.has_table("utilisateur"):
        return

    def _has_column(table_name: str, column_name: str) -> bool:
        return any(
            column.get("name") == column_name
            for column in inspector.get_columns(table_name)
        )

    if not _has_column("utilisateur", "provisional_expires_at"):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE utilisateur "
                    "ADD COLUMN provisional_expires_at TIMESTAMP NULL"
                )
            )
    # Refresh inspector to avoid cached metadata after ALTER TABLE
    inspector = inspect(engine)
    existing_indexes = {
        index["name"] for index in inspector.get_indexes("utilisateur")
    }
    index_name = "ix_utilisateur_provisional_expires_at"
    if index_name not in existing_indexes:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE INDEX "
                    f"{index_name} ON utilisateur (provisional_expires_at)"
                )
            )


def _ensure_evenement_archive_columns():
    """Ensure legacy databases have archived flags for events."""

    engine = db.engine
    inspector = inspect(engine)

    if not inspector.has_table("evenement"):
        return

    def _has_column(table_name: str, column_name: str) -> bool:
        return any(
            column.get("name") == column_name
            for column in inspector.get_columns(table_name)
        )

    if not _has_column("evenement", "archived"):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE evenement "
                    "ADD COLUMN archived BOOLEAN NOT NULL DEFAULT FALSE"
                )
            )

    if not _has_column("evenement", "archived_at"):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE evenement "
                    "ADD COLUMN archived_at TIMESTAMP NULL"
                )
            )

    inspector = inspect(engine)
    existing_indexes = {index["name"] for index in inspector.get_indexes("evenement")}
    index_name = "ix_evenement_archived"
    if index_name not in existing_indexes:
        with engine.begin() as connection:
            connection.execute(
                text(f"CREATE INDEX {index_name} ON evenement (archived)")
            )


def _ensure_share_link_label_column():
    """Ensure legacy databases have the share link label column."""

    engine = db.engine
    inspector = inspect(engine)

    if not inspector.has_table("share_link"):
        return

    has_label_column = any(
        column.get("name") == "label" for column in inspector.get_columns("share_link")
    )

    if not has_label_column:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE share_link "
                    "ADD COLUMN label VARCHAR(120) NULL"
                )
            )


if __name__ == "__main__":
    cli()
