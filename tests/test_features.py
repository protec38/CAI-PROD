"""Feature invariants: merge, recycle identities, settings, permissions and locking."""
import json
import time
from datetime import date
from uuid import uuid4

import pytest

from app.extensions import db
from app.models import (
    Bagage,
    EventSettings,
    FicheChange,
    FicheImplique,
    FicheMetadata,
    FicheTrash,
    UserPreference,
)


def edit(client, changes, base, **kwargs):
    return client.post('/api/evenement/1/fiches/actions/sync', data={
        'operation_uuid': kwargs.pop('operation_uuid', str(uuid4())), 'kind': 'edit', 'user_id': '2', 'fiche_id': '1',
        'changes': json.dumps(changes), 'base': json.dumps(base), **kwargs})


def test_different_fields_merge_and_same_field_conflicts(app, client):
    assert edit(client, {'telephone': '0612345678'}, {'telephone': ''}).status_code == 200
    response = edit(client, {'adresse': 'Rue A'}, {'adresse': ''})
    assert response.status_code == 200
    op = str(uuid4())
    response = edit(client, {'telephone': '0699999999', 'adresse': 'Rue B'}, {'telephone': '', 'adresse': 'Rue A'}, operation_uuid=op)
    assert response.status_code == 409
    assert response.json['conflicts'] == [{'field': 'telephone', 'base': '', 'server': '0612345678', 'mine': '0699999999'}]
    with app.app_context():
        assert db.session.get(FicheImplique, 1).adresse == 'Rue A'  # all or nothing
    response = edit(client, {'telephone': '0699999999', 'adresse': 'Rue B'}, {'telephone': '0612345678', 'adresse': 'Rue A'}, operation_uuid=op)
    assert response.status_code == 200
    assert edit(client, {'telephone': '0699999999', 'adresse': 'Rue B'}, {'telephone': '0612345678', 'adresse': 'Rue A'}, operation_uuid=op).status_code == 200
    with app.app_context():
        history = FicheChange.query.filter_by(fiche_id=1, kind='edit').all()
        assert len(history) == 3
        assert history[-1].changes['telephone'] == {'old': '0612345678', 'new': '0699999999'}
        assert history[-1].user_id == 2


def test_custom_field_merge_is_per_field(app, client):
    assert edit(client, {'custom_values': {'a': 'one'}}, {'custom_values': {}}).status_code == 200
    assert edit(client, {'custom_values': {'b': 'two'}}, {'custom_values': {}}).status_code == 200
    with app.app_context():
        assert db.session.get(FicheMetadata, 1).custom_values == {'a': 'one', 'b': 'two'}
    response = edit(client, {'custom_values': {'a': 'different'}}, {'custom_values': {'a': ''}})
    assert response.status_code == 409
    assert response.json['conflicts'][0]['field'] == 'custom_values.a'


@pytest.mark.parametrize(('changes', 'base'), [({'telephone': 'a'*21}, {'telephone': ''}),
    ({'date_naissance': '2999-01-01'}, {'date_naissance': ''}), ({'nom': []}, {'nom': 'Example'}),
    ({'utilisateur_id': '2'}, {'utilisateur_id': '1'}), ({'nom': 'X'}, {}),
    ({'referent_humain_id': '2'}, {'referent_humain_id': ''})])
def test_invalid_edits_are_atomic(app, client, changes, base):
    assert edit(client, changes, base).status_code == 422
    with app.app_context():
        assert db.session.get(FicheImplique, 1).nom == 'Example'
        assert FicheChange.query.count() == 0


def test_legacy_metadata_and_snapshot_are_stable(app, client):
    first = client.get('/evenement/1/fiches_json?details=1').json['fiches'][0]
    second = client.get('/evenement/1/fiches_json?details=1').json['fiches'][0]
    assert first['qr_url'] == second['qr_url']
    assert first['identity_token'] == second['identity_token']
    assert first['qr_data'].startswith('data:image/svg+xml;base64,')
    assert 'edit_state' in first
    with app.app_context():
        assert FicheMetadata.query.count() == 1


def test_duplicate_detection_normalizes_identity_and_is_event_scoped(app, client):
    with app.app_context():
        fiche = db.session.get(FicheImplique, 1)
        fiche.nom, fiche.prenom, fiche.date_naissance = 'ÉXAMPLE', 'Alice', date(1990, 1, 31)
        db.session.commit()
    response = client.get('/api/evenement/1/doublons?nom=example&prenom=ALICE&date_naissance=1990-01-31')
    assert [f['id'] for f in response.json['duplicates']] == [1]
    assert client.get('/api/evenement/1/doublons?nom=example&prenom=ALICE&date_naissance=1990-01-31&exclude=1').json['duplicates'] == []
    assert client.get('/api/evenement/2/doublons').status_code == 403


def test_recycle_restores_data_renumbers_and_changes_identity(app, client):
    before = client.get('/evenement/1/fiches_json?details=1').json['fiches'][0]
    assert edit(client, {'telephone': '0612345678', 'family_key': 'Famille A'}, {'telephone': '', 'family_key': ''}).status_code == 200
    client.post('/fiche/1/bagages/ajouter', data={'numeros': 'BAG1'})
    assert client.post('/fiche/delete/1').status_code == 302
    with app.app_context():
        assert db.session.get(FicheImplique, 1) is None
        item = FicheTrash.query.one()
        item_id = item.id
        assert item.payload['changes']
        db.session.add(FicheImplique(numero='F1', evenement_id=1, utilisateur_id=1))
        db.session.commit()
    response = client.post(f'/evenement/1/corbeille/{item_id}/restaurer')
    assert response.status_code == 302
    with app.app_context():
        item = db.session.get(FicheTrash, item_id)
        restored = db.session.get(FicheImplique, item.restored_id)
        assert restored.telephone == '0612345678'
        assert restored.numero != 'F1'
        restored_id = restored.id
        assert db.session.get(FicheMetadata, restored.id).family_key == 'Famille A'
    fiches = client.get('/evenement/1/fiches_json?details=1').json['fiches']
    restored = next(f for f in fiches if f['id'] == restored_id)
    assert restored['identity_token'] != before['identity_token']
    assert restored['qr_url'] == before['qr_url']
    response = client.post('/api/evenement/1/fiches/actions/sync', data={'kind':'delete','operation_uuid':str(uuid4()),
        'user_id':'2','fiche_id':str(restored_id),'identity_token':before['identity_token']})
    assert response.status_code == 409
    assert client.post(f'/evenement/1/corbeille/{item_id}/restaurer').status_code == 302


def test_restore_bagage_collision_keeps_trash_atomic(app, client):
    with app.app_context():
        db.session.add(Bagage(numero='B1',fiche_id=1,evenement_id=1))
        db.session.commit()
    client.post('/fiche/delete/1')
    with app.app_context():
        item_id=FicheTrash.query.one().id
        fiche=FicheImplique(numero='X',evenement_id=1,utilisateur_id=2)
        db.session.add(fiche)
        db.session.flush()
        db.session.add(Bagage(numero='B1',fiche_id=fiche.id,evenement_id=1))
        db.session.commit()
    response=client.post(f'/evenement/1/corbeille/{item_id}/restaurer',follow_redirects=True)
    assert 'déjà attribué' in response.text
    with app.app_context():
        assert FicheTrash.query.one().restored_at is None
        assert FicheImplique.query.filter_by(evenement_id=1).count()==1


def event_settings():
    return {'capacity': 100,'warning_percent':80,'choice_lists':{'zones':['A','B'],'transports':['Bus']},
            'custom_fields':[{'key':'besoin','label':'Besoin','type':'choice','choices':['Oui','Non'],'scope':'humain','required':True}]}


def test_event_settings_custom_validation_and_creation(app, client):
    response=client.post('/evenement/1/outils',data={'settings':json.dumps(event_settings())})
    assert response.status_code==302
    payload={'client_uuid':str(uuid4()),'user_id':'2','nom':'Test','prenom':'Alice','date_naissance':'1990-01-01'}
    assert client.post('/api/evenement/1/fiches/sync',data=payload).status_code==422
    payload.update(custom_values=json.dumps({'besoin':'Oui'}),family_key='Famille A')
    response=client.post('/api/evenement/1/fiches/sync',data=payload)
    assert response.status_code==200
    snapshot=client.get('/evenement/1/fiches_json?details=1').json
    assert snapshot['evenement']['settings']['capacity']==100
    fiche=next(f for f in snapshot['fiches'] if f['id']==response.json['id'])
    assert fiche['custom_values']=={'besoin':'Oui'}
    assert fiche['family_key']=='Famille A'
    assert client.get('/evenement/1/outils').status_code==200


@pytest.mark.parametrize('bad', [{'capacity':-1},{'warning_percent':101},{'custom_fields':[{'key':'unsafe key'}]},
                                  {'choice_lists':{'zones':['x'*81]}},{'custom_fields':[None]}])
def test_settings_reject_invalid_values(app, client, bad):
    data=event_settings() | bad
    client.post('/evenement/1/outils',data={'settings':json.dumps(data)})
    with app.app_context():
        assert db.session.get(EventSettings,1) is None


def test_pdf_and_qr_authorization(client):
    snapshot=client.get('/evenement/1/fiches_json?details=1').json['fiches'][0]
    from urllib.parse import urlsplit
    assert client.get(urlsplit(snapshot['qr_url']).path).status_code==302
    assert client.get('/api/fiche/2/complement').status_code==403
    assert client.post('/evenement/1/etiquettes.pdf',data={'fiche_ids':'2'}).status_code==403
    assert client.get('/evenement/2/bilan.pdf').status_code==403
    for response in [client.post('/evenement/1/etiquettes.pdf',data={'fiche_ids':'1'}),client.get('/evenement/1/bilan.pdf')]:
        assert response.status_code==200
        assert response.data.startswith(b'%PDF-')
        assert response.headers['Cache-Control']=='no-store'


def test_preferences_and_inactivity_lock(app, client):
    response=client.post('/mes-preferences',data={'lock_minutes':'1','compact':'on','show_counters':'on','next':'//evil.test'})
    assert response.status_code==302 and 'evil.test' not in response.location
    with app.app_context():
        assert db.session.get(UserPreference,2).dashboard['compact'] is True
    with client.session_transaction() as session:
        session['last_activity']=time.time()-61
    assert client.get('/evenement/1/fiches_json').status_code==423
    assert client.get('/api/offline/session').status_code==423
    assert client.get('/fiche/1').location.startswith('/session/deverrouiller')
    assert client.post('/api/session/activite').status_code==423
    assert client.post('/session/deverrouiller',data={'password':'wrong','json':'1'}).status_code==403
    assert client.get('/evenement/1/fiches_json').status_code==423
    assert client.post('/session/deverrouiller',data={'password':'test-password-123','json':'1'}).json['unlocked']
    assert client.get('/evenement/1/fiches_json').status_code==200


def test_backup_roundtrip_includes_metadata_and_recycle(app, client):
    from app.backup_utils import backup_to_bytesio, bulk_restore
    client.post('/evenement/1/outils',data={'settings':json.dumps(event_settings())})
    edit(client,{'family_key':'Family'},{'family_key':''})
    client.post('/fiche/delete/1')
    with app.app_context():
        backup=json.loads(backup_to_bytesio().getvalue())
        bulk_restore(backup)
        assert FicheTrash.query.count()==1
        assert db.session.get(EventSettings,1).capacity==100


def test_restricted_role_cannot_change_event_settings_status_or_pec(app, client):
    from app.models import Utilisateur
    with app.app_context():
        db.session.get(Utilisateur, 2).role = 'logisticien'
        db.session.commit()
    assert client.get('/evenement/1/outils').status_code == 200
    assert client.post('/evenement/1/outils', data={'settings': json.dumps(event_settings())}).status_code == 403
    assert edit(client, {'numero_pec': 'PEC-1'}, {'numero_pec': ''}).status_code == 422
    assert edit(client, {'statut': 'sorti'}, {'statut': 'présent'}).status_code == 422


def test_restored_uuid_rejects_legacy_actions_without_lifecycle_proof(app, client):
    uuid = str(uuid4())
    with app.app_context():
        db.session.get(FicheImplique, 1).client_uuid = uuid
        db.session.commit()
    client.post('/fiche/delete/1')
    with app.app_context():
        item_id = FicheTrash.query.one().id
    client.post(f'/evenement/1/corbeille/{item_id}/restaurer')
    response = client.post('/api/evenement/1/fiches/actions/sync', data={
        'kind': 'delete', 'operation_uuid': str(uuid4()), 'user_id': '2', 'fiche_uuid': uuid})
    assert response.status_code == 409
    with app.app_context():
        assert FicheImplique.query.filter_by(client_uuid=uuid).one()


def test_receipts_from_previous_version_still_acknowledge_retries(app, client):
    import hashlib

    from app.models import OfflineMutation
    operation = str(uuid4())
    content = {'kind': 'bagages', 'numeros': 'B-OLD', 'base_numeros': '', 'destination': '',
               'moyen_transport': '', 'occurred_at': '2026-01-01T10:00:00Z'}
    digest = hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    with app.app_context():
        db.session.add(OfflineMutation(id=operation, evenement_id=1, fiche_id=1,
            utilisateur_id=2, kind='bagages', payload_hash=digest))
        db.session.add(Bagage(numero='B-OLD', fiche_id=1, evenement_id=1))
        db.session.commit()
    response = client.post('/api/evenement/1/fiches/actions/sync', data={**content,
        'operation_uuid': operation, 'fiche_id': '1', 'user_id': '2'})
    assert response.status_code == 200
    with app.app_context():
        assert Bagage.query.filter_by(fiche_id=1).count() == 1
