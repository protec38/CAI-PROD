"""Queued bagage and departure actions: authorization, atomicity and receipts."""
from datetime import datetime
import json
from uuid import uuid4

import pytest

from app.extensions import db
from app.models import Bagage, FicheImplique, OfflineMutation, TimelineEntry, Utilisateur

URL = "/api/evenement/1/fiches/actions/sync"


def action(kind="bagages", **overrides):
    return {"operation_uuid": str(uuid4()), "user_id": "2", "fiche_id": "1", "kind": kind,
            "numeros": "BAG-1, BAG-2", "base_numeros": "",
            "occurred_at": "2026-10-30T13:15:00.000Z", **overrides}


@pytest.mark.parametrize("kind", ["bagages", "sortie"])
def test_action_retry_is_idempotent(app, client, kind):
    data = action(kind, destination="Domicile", moyen_transport="Bus")
    first = client.post(URL, data=data)
    assert first.status_code == 200
    assert client.post(URL, data=data).json == first.json
    with app.app_context():
        assert OfflineMutation.query.count() == 1
        assert TimelineEntry.query.filter_by(fiche_id=1).count() == 1
        fiche = db.session.get(FicheImplique, 1)
        if kind == "bagages":
            assert {bagage.numero for bagage in fiche.bagages} == {"BAG-1", "BAG-2"}
        else:
            assert fiche.statut == "sorti"
            assert fiche.destination == "Domicile"
            assert fiche.moyen_transport == "Bus"
            assert fiche.heure_sortie == datetime(2026, 10, 30, 13, 15)
    snapshot = client.get("/evenement/1/fiches_json").json
    assert data["operation_uuid"] in snapshot["applied_operations"]
    assert "bagages" in snapshot["fiches"][0]


def test_action_cannot_be_reused_for_different_content(client):
    data = action()
    assert client.post(URL, data=data).status_code == 200
    assert client.post(URL, data={**data, "numeros": "OTHER"}).status_code == 409


def test_action_access_and_account_checks(app, client):
    assert app.test_client().post(URL, data=action()).status_code == 401
    assert client.post(URL, data=action(user_id="1")).status_code == 403
    assert client.post(URL, data=action(fiche_id="2")).status_code == 409
    assert client.post(URL.replace("/1/", "/2/"), data=action(fiche_id="2")).status_code == 403
    with app.app_context():
        user = db.session.get(Utilisateur, 2)
        user.role = "logisticien"
        db.session.commit()
    assert client.post(URL, data=action()).status_code == 403
    assert client.post(URL, data=action("sortie")).status_code == 200


def test_action_rechecks_permissions_on_retry(app, client):
    data = action()
    assert client.post(URL, data=data).status_code == 200
    with app.app_context():
        user = db.session.get(Utilisateur, 2)
        user.evenements.clear()
        db.session.commit()
    assert client.post(URL, data=data).status_code == 403


@pytest.mark.parametrize("changes", [
    {"operation_uuid": "invalid"}, {"fiche_id": "invalid"}, {"kind": "unknown"},
    {"numeros": "x" * 51}, {"numeros": "x" * 301},
    {"kind": "sortie", "destination": "x" * 256},
    {"kind": "sortie", "occurred_at": "invalid"},
])
def test_invalid_actions_do_not_change_data(app, client, changes):
    assert client.post(URL, data=action(**changes)).status_code == 422
    with app.app_context():
        assert OfflineMutation.query.count() == 0
        assert Bagage.query.count() == 0
        assert db.session.get(FicheImplique, 1).statut == "présent"


def test_action_requires_csrf(app, client):
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post(URL, data=action()).status_code == 400
    token = client.get("/api/offline/session").json["csrf_token"]
    assert client.post(URL, data=action(), headers={"X-CSRFToken": token}).status_code == 200


def test_bagage_conflict_is_atomic_and_can_be_corrected(app, client):
    with app.app_context():
        other = FicheImplique(numero="001-0010", utilisateur_id=1, evenement_id=1)
        db.session.add(other)
        db.session.flush()
        db.session.add_all([Bagage(numero="TAKEN", fiche_id=other.id, evenement_id=1),
                            Bagage(numero="KEEP", fiche_id=1, evenement_id=1)])
        db.session.commit()
    data = action(numeros="TAKEN, NEW", base_numeros="KEEP")
    assert client.post(URL, data=data).status_code == 422
    with app.app_context():
        assert {bagage.numero for bagage in Bagage.query.filter_by(fiche_id=1)} == {"KEEP"}
        assert OfflineMutation.query.count() == 0
    assert client.post(URL, data={**data, "numeros": "NEW"}).status_code == 200


def test_bagage_merge_preserves_additions_from_other_operator(app, client):
    with app.app_context():
        db.session.add_all([Bagage(numero="OLD", fiche_id=1, evenement_id=1),
                            Bagage(numero="OTHER-OPERATOR", fiche_id=1, evenement_id=1)])
        db.session.commit()
    assert client.post(URL, data=action(numeros="NEW", base_numeros="OLD")).status_code == 200
    with app.app_context():
        assert {bagage.numero for bagage in Bagage.query.filter_by(fiche_id=1)} == {"NEW", "OTHER-OPERATOR"}


def test_local_target_waits_for_creation(client):
    data = {"client_uuid": str(uuid4()), "user_id": "2", "type_fiche": "humain",
            "nom": "Test", "prenom": "Local", "date_naissance": "1990-01-31"}
    pending = action(fiche_id="", fiche_uuid=data["client_uuid"])
    assert client.post(URL, data=pending).status_code == 409
    assert client.post("/api/evenement/1/fiches/sync", data=data).status_code == 200
    assert client.post(URL, data=pending).status_code == 200


def test_receipts_survive_backup_and_restore(app, client):
    from app.backup_utils import backup_to_bytesio, bulk_restore
    data = action("sortie")
    assert client.post(URL, data=data).status_code == 200
    with app.app_context():
        bulk_restore(json.loads(backup_to_bytesio().getvalue()))
    assert client.post(URL, data=data).status_code == 200
    with app.app_context():
        assert TimelineEntry.query.filter_by(kind="exit").count() == 1


def test_existing_form_routes_share_validation(app, client):
    assert client.post("/fiche/1/bagages/ajouter", data={"numeros": "FORM-1"}).status_code == 302
    assert client.post("/fiche/1/sortie", data={"destination": "Domicile", "moyen_transport": "Bus"}).status_code == 302
    with app.app_context():
        assert Bagage.query.filter_by(fiche_id=1).one().numero == "FORM-1"
        assert db.session.get(FicheImplique, 1).statut == "sorti"


def test_receipts_are_removed_when_fiche_is_deleted(app, client):
    assert client.post(URL, data=action()).status_code == 200
    assert client.post("/fiche/delete/1").status_code == 302
    with app.app_context():
        assert OfflineMutation.query.count() == 0


def test_concurrent_action_retries(app):
    from concurrent.futures import ThreadPoolExecutor
    with app.app_context():
        if db.engine.dialect.name != "postgresql":
            pytest.skip("Concurrency validation uses PostgreSQL in CI.")
    data = action("sortie", destination="Domicile")

    def send(_):
        client = app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = 2
        response = client.post(URL, data=data)
        assert response.status_code == 200
        return response.json

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(send, range(4)))
    assert all(result == results[0] for result in results)
    with app.app_context():
        assert OfflineMutation.query.count() == 1
        assert TimelineEntry.query.filter_by(fiche_id=1, kind="exit").count() == 1
