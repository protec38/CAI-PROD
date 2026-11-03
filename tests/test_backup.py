import json

import pytest
from sqlalchemy.exc import IntegrityError

from app.backup_utils import backup_to_bytesio, bulk_restore
from app.extensions import db
from app.models import Evenement, EventNews, FicheImplique, TimelineEntry, Utilisateur


def test_backup_empty_selection_does_not_leak_data(app):
    with app.app_context():
        for selection in ([], [999]):
            payload = json.loads(backup_to_bytesio(selection).getvalue())
            assert all(not value for key, value in payload.items() if key != "version")


def test_backup_round_trip_dates_news_timeline_and_references(app):
    with app.app_context():
        db.session.add(TimelineEntry(fiche_id=1, user_id=1, content="History", kind="comment"))
        db.session.get(FicheImplique, 2).referent_humain_id = 1
        db.session.commit()
        payload = json.loads(backup_to_bytesio().getvalue())
        bulk_restore(payload)
        assert Evenement.query.count() == 2
        assert Utilisateur.query.count() == 2
        assert EventNews.query.one().message == "Private"
        assert TimelineEntry.query.one().content == "History"
        assert db.session.get(FicheImplique, 2).referent_humain_id == 1
        assert db.session.get(Evenement, 1).date_ouverture is not None


def test_failed_restore_rolls_back_deletions(app):
    with app.app_context():
        payload = json.loads(backup_to_bytesio().getvalue())
        payload["fiches"][0]["evenement_id"] = 999
        with pytest.raises(IntegrityError):
            bulk_restore(payload)
        assert db.session.get(Evenement, 2).nom == "Other"
        assert FicheImplique.query.count() == 2
        assert EventNews.query.count() == 1
