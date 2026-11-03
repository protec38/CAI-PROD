"""Person searches, automatic families, private appearance and broadcast permissions."""
import json
from uuid import uuid4

import pytest

from app.extensions import db
from app.models import (
    BroadcastNotification,
    FicheImplique,
    FicheMetadata,
    PersonSearch,
    UserPreference,
    Utilisateur,
)


def search_fields(**kwargs):
    return {'seeker_nom': 'Martin', 'seeker_prenom': 'Luc', 'target_nom': 'DUPONT', 'target_prenom': 'Élise', **kwargs}


def test_search_matches_creation_and_stays_in_its_event(app, client):
    assert client.post('/evenement/1/recherches', data=search_fields()).status_code == 302
    result = client.get('/api/evenement/1/recherches/correspondances?nom=dupont&prenom=elise').json
    assert result['matches'][0]['seeker_nom'] == 'Martin'
    assert client.get('/api/evenement/2/recherches/correspondances?nom=dupont&prenom=elise').status_code == 403
    assert client.get('/evenement/2/recherches').status_code == 403
    response = client.post('/api/evenement/1/fiches/sync', data={'client_uuid':str(uuid4()), 'user_id':'2',
        'nom':'Dupont', 'prenom':'Elise', 'date_naissance':'1990-01-01'})
    assert response.status_code == 200
    assert response.json['wanted_matches'][0]['seeker_prenom'] == 'Luc'
    snapshot = client.get('/evenement/1/fiches_json?details=1').json
    assert len(snapshot['person_searches']) == 1
    response = client.post('/fiche/new', data={'evenement_id':'1','nom':'Dupont','prenom':'Elise','date_naissance':'1990-01-01'}, follow_redirects=True)
    assert 'recherchée par : Martin Luc' in response.text


def test_search_resolution_requires_author_or_manager_and_backup_preserves_it(app, client):
    from app.backup_utils import backup_to_bytesio, bulk_restore
    with app.app_context():
        row = PersonSearch(evenement_id=1, created_by_id=1, **search_fields())
        db.session.add(row)
        db.session.get(Utilisateur, 2).role = 'technicien'
        db.session.commit()
        search_id = row.id
    assert client.post('/evenement/1/recherches', data={'action':'resolve','search_id':search_id}).status_code == 403
    with app.app_context():
        db.session.get(Utilisateur, 2).role = 'responsable'
        db.session.commit()
    client.post('/evenement/1/recherches', data={'action':'resolve','search_id':search_id})
    assert client.get('/api/evenement/1/recherches/correspondances?nom=dupont&prenom=elise').json['matches'] == []
    client.post('/evenement/1/recherches', data={'action':'reopen','search_id':search_id})
    with app.app_context():
        payload = json.loads(backup_to_bytesio().getvalue())
        assert len(payload['person_searches']) == 1
        bulk_restore(payload)
        assert PersonSearch.query.one().target_prenom == 'Élise'


@pytest.mark.parametrize('values', [search_fields(target_nom=''), search_fields(seeker_nom='x'*101), {'action':'unknown'}, {'action':'resolve'}])
def test_search_validation_has_no_partial_writes(app, client, values):
    client.post('/evenement/1/recherches', data=values)
    with app.app_context():
        assert PersonSearch.query.count() == 0


def test_automatic_family_and_manual_group_are_independent(app, client):
    with app.app_context():
        fiche = db.session.get(FicheImplique, 1)
        fiche.nom, fiche.prenom = 'DUPONT', 'Alice'
        db.session.add_all([FicheImplique(numero='F3', nom='Dupont', prenom='Luc', evenement_id=1, utilisateur_id=2),
                            FicheImplique(numero='F4', nom='Martin', prenom='Marc', evenement_id=1, utilisateur_id=2)])
        db.session.commit()
        other_id = FicheImplique.query.filter_by(numero='F4').one().id
    page = client.get('/evenement/1/outils')
    assert 'Famille DUPONT · 2 fiche(s)' in page.text
    client.post('/evenement/1/groupes', data={'group_name':'Voyageurs','fiche_ids':['1',str(other_id)]})
    with app.app_context():
        assert db.session.get(FicheMetadata, 1).family_key == 'Voyageurs'
        assert db.session.get(FicheMetadata, other_id).family_key == 'Voyageurs'
    assert client.post('/evenement/1/groupes', data={'group_name':'Interdit','fiche_ids':['1','2']}).status_code == 403
    with app.app_context():
        assert db.session.get(FicheMetadata, 1).family_key == 'Voyageurs'
        db.session.get(FicheImplique, 1).nom = 'Martin'
        db.session.commit()
    page = client.get('/evenement/1/outils')
    assert 'Famille Martin · 2 fiche(s)' in page.text
    assert 'Voyageurs · 2 fiche(s)' in page.text


def test_appearance_is_saved_only_for_current_user_and_validated(app, client):
    response = client.post('/mes-preferences', data={'user_id':'1','theme':'dark','accent':'violet',
        'font_size':'extra','layout_width':'wide','corners':'square','stripe_rows':'on','reduce_motion':'on'})
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(UserPreference,1) is None
        prefs = db.session.get(UserPreference,2).dashboard
        assert prefs['theme']=='dark' and prefs['font_size']=='extra' and prefs['reduce_motion']
    client.post('/mes-preferences', data={'theme':'invalid','lock_minutes':'30'})
    with app.app_context():
        assert db.session.get(UserPreference,2).dashboard['theme']=='dark'
        assert db.session.get(UserPreference,2).lock_minutes==0


@pytest.mark.parametrize(('role','allowed'), [('admin',True),('responsable',True),('technicien',False),('logisticien',False),('codep',False)])
def test_broadcast_access_is_enforced_on_server(app, client, monkeypatch, role, allowed):
    monkeypatch.setattr('app.routes.schedule_broadcast_expiration', lambda *args, **kwargs: None)
    with app.app_context():
        db.session.get(Utilisateur,2).role=role
        db.session.commit()
    response=client.get('/notifications/broadcast')
    assert response.status_code == (200 if allowed else 403)
    response=client.post('/notifications/broadcast',data={'message':'Test uniquement dans la base de tests','level':'info'})
    assert response.status_code == (302 if allowed else 403)
    with app.app_context():
        assert BroadcastNotification.query.count() == int(allowed)
    assert client.get('/api/offline/session').json['permissions']['canBroadcast'] == allowed


def test_removed_fields_and_navigation(client):
    for path in ['/fiche/new?evenement_id=1','/fiche/edit/1']:
        page=client.get(path)
        for field in ['numero_pec','nationalite','effets_perso','numero_recherche']:
            assert f'name="{field}"' not in page.text
    page=client.get('/evenement/1/dashboard')
    assert 'Retour au menu principal' in page.text
    assert 'Gestion des évènements' not in page.text and 'Vue synthétique' not in page.text
    assert page.text.index('btn-main-menu') < page.text.index('action="/logout"')
    assert client.get('/evenement/1/panorama').location.endswith('/evenement/1/dashboard')
    assert 'Other' not in client.get('/recherches').text
