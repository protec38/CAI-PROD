from app.time_utils import utcnow
from datetime import datetime
import os

import pytest
from sqlalchemy import event

from app import create_app
from app.extensions import db
from app.models import Evenement, EventNews, FicheImplique, Utilisateur
from app.routes import _HOUSEKEEPING_STATE, ip_login_attempts


@pytest.fixture
def app():
    app = create_app("dev", {
        "TESTING": True, "SQLALCHEMY_DATABASE_URI": os.environ.get("CAI_TEST_DATABASE_URL", "sqlite:///:memory:"),
        "WTF_CSRF_ENABLED": False, "RATELIMIT_ENABLED": False,
    })
    with app.app_context():
        if db.engine.dialect.name == "sqlite":
            @event.listens_for(db.engine, "connect")
            def foreign_keys(connection, _):
                connection.execute("PRAGMA foreign_keys=ON")
            db.session.execute(db.text("PRAGMA foreign_keys=ON"))
        db.create_all()
        admin = Utilisateur(id=1, nom_utilisateur="admin", role="admin", type_utilisateur="permanent", is_admin=True, actif=True)
        member = Utilisateur(id=2, nom_utilisateur="member", role="responsable", type_utilisateur="permanent", actif=True)
        for user in (admin, member):
            user.set_password("test-password-123")
        own = Evenement(id=1, numero="0001", nom="Own", createur_id=1)
        other = Evenement(id=2, numero="0002", nom="Other", createur_id=1)
        member.evenements.append(own)
        db.session.add_all([admin, member, own, other])
        db.session.flush()
        db.session.add_all([
            FicheImplique(id=1, numero="F1", evenement_id=1, utilisateur_id=1, nom="Example"),
            FicheImplique(id=2, numero="F2", evenement_id=2, utilisateur_id=1),
            EventNews(id=1, evenement_id=2, created_by=1, message="Private"),
        ])
        db.session.commit()
        if db.engine.dialect.name == "postgresql":
            for model in (Utilisateur, Evenement, FicheImplique, EventNews):
                next_id = (db.session.scalar(db.select(db.func.max(model.id))) or 0) + 1
                db.session.execute(db.text("SELECT setval(pg_get_serial_sequence(:table, 'id'), :next_id, false)"),
                                   {"table": model.__tablename__, "next_id": next_id})
            db.session.commit()
        _HOUSEKEEPING_STATE["last_run"] = utcnow()
        ip_login_attempts.clear()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 2
        session["_user_id"] = "2"
        session["_fresh"] = True
    return client
