import os
import click
from flask.cli import with_appcontext
from app import create_app
from app.extensions import db
from app.models import User

app = create_app()

@click.command('init-db')
@with_appcontext
def init_db_command():
    """Create all tables and ensure default admin exists (idempotent)."""
    db.create_all()
    # Ensure admin/admin exists; ignore if already there
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', is_admin=True, actif=True if hasattr(User, 'actif') else True)
        # set_password if available
        if hasattr(admin, 'set_password'):
            admin.set_password('admin')
        elif hasattr(admin, 'mot_de_passe_hash'):
            admin.mot_de_passe_hash = 'admin'  # fallback; replace later by proper hash in your model
        db.session.add(admin)
        db.session.commit()
    click.echo('Database initialized.')

app.cli.add_command(init_db_command)

if __name__ == '__main__':
    app.run()
