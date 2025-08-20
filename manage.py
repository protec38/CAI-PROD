import click
from sqlalchemy import text
from pathlib import Path
from app import create_app
from app.extensions import db

app = create_app()

@click.group()
def cli():
    """Outils de maintenance."""
    pass

@cli.command("init-db")
def init_db():
    """Crée les tables et l'admin/admin si absent (idempotent)."""
    from app.models import Utilisateur  # noqa
    from werkzeug.security import generate_password_hash

    with app.app_context():
        db.create_all()
        admin = db.session.execute(
            db.select(Utilisateur).where(Utilisateur.nom_utilisateur == "admin")
        ).scalar_one_or_none()
        if not admin:
            admin = Utilisateur(
                nom_utilisateur="admin",
                nom="Admin",
                role="admin",
                type_utilisateur="admin",
                is_admin=True,
                actif=True,
            )
            try:
                admin.set_password("admin")  # scrypt par défaut (Werkzeug ≥ 3)
            except Exception:
                admin.mot_de_passe_hash = generate_password_hash(
                    "admin", method="pbkdf2:sha256", salt_length=16
                )
            db.session.add(admin)
            db.session.commit()
            click.echo("[init-db] admin/admin créé avec succès")
        else:
            click.echo("[init-db] admin déjà présent (OK)")

@cli.command("apply-cascade")
def apply_cascade():
    """Applique les ON DELETE CASCADE sur les FKs (idempotent)."""
    sql_path = Path(__file__).parent / "db" / "alter_cascade.sql"
    if not sql_path.exists():
        raise click.ClickException(f"Fichier SQL introuvable: {sql_path}")
    with app.app_context():
        sql = sql_path.read_text(encoding="utf-8")
        for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
            db.session.execute(text(stmt))
        db.session.commit()
        click.echo("[apply-cascade] Contraintes CASCADE appliquées.")

if __name__ == "__main__":
    cli()
