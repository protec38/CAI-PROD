# app/__init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

bcrypt = Bcrypt()
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    # Initialiser les extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "main_bp.login"  # 🔑 Nom de la vue pour login

    from .models import Utilisateur

    @login_manager.user_loader
    def load_user(user_id):
        return Utilisateur.query.get(int(user_id))

    # Importer les routes
    from .routes import main_bp
    app.register_blueprint(main_bp)

    # Création de la base et admin par défaut
    with app.app_context():
        db.create_all()
        create_default_admin()

    return app

def create_default_admin():
    from .models import Utilisateur

    if not Utilisateur.query.filter_by(nom_utilisateur="admin").first():
        admin = Utilisateur(
            nom_utilisateur="admin",
            type_utilisateur="interne",
            niveau="encadrant",
            role="codep",
            nom="Administrateur",
            prenom="Général",
            is_admin=True
        )
        admin.set_password("admin")
        db.session.add(admin)
        db.session.commit()
