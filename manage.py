import click
from flask.cli import with_appcontext
from app import create_app
from app.extensions import db
from app.models import Utilisateur

app = create_app()

@click.command('init-db')
@with_appcontext
def init_db_command():
    """Create all tables and ensure default admin exists (idempotent)."""
    db.create_all()
    # Ensure admin/admin exists; ignore if already there
    admin = Utilisateur.query.filter_by(nom_utilisateur='admin').first()
    if not admin:
        admin = Utilisateur(
            nom_utilisateur='admin',
            role='admin',
            type_utilisateur='admin',
            is_admin=True,
            actif=True,
        )
        if hasattr(admin, 'set_password'):
            admin.set_password('admin')
        else:
            # Fallback if custom field names exist
            try:
                admin.mot_de_passe_hash = 'admin'
            except Exception:
                pass
        db.session.add(admin)
        db.session.commit()
    click.echo('Database initialized.')

app.cli.add_command(init_db_command)

if __name__ == '__main__':
    app.run()
