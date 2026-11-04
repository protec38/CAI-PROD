"""Event family totals, linked seekers and shared found-person notifications."""
import json
from datetime import timedelta

import pytest

from app import _ensure_database_schema, create_app
from app.backup_utils import backup_to_bytesio, bulk_restore
from app.extensions import db
from app.models import FicheImplique, PersonSearch
from app.time_utils import utcnow


def fields(**values):
    return dict(seeker_nom='Martin', seeker_prenom='Luc', target_nom='Dupont', target_prenom='Emma', **values)


def test_present_families_ignore_case_accents_animals_and_departures(app, client):
    with app.app_context():
        db.session.get(FicheImplique, 1).nom = '  MÉNARD  '
        db.session.add_all([
            FicheImplique(numero='F3', evenement_id=1, utilisateur_id=2, nom='menard', statut='présent'),
            FicheImplique(numero='F4', evenement_id=1, utilisateur_id=2, nom='Martin', statut='présent'),
            FicheImplique(numero='F5', evenement_id=1, utilisateur_id=2, nom='Sortie', statut='sorti'),
            FicheImplique(numero='F6', evenement_id=1, utilisateur_id=2, nom='Effacé', statut='supprimé'),
            FicheImplique(numero='F7', evenement_id=1, utilisateur_id=2, nom='Animal', est_animal=True),
            FicheImplique(numero='F8', evenement_id=1, utilisateur_id=2, nom='   '),
        ])
        db.session.commit()
    assert client.get('/evenement/1/fiches_json').json['nb_familles'] == 2
    assert 'id="nb_familles">2</strong>' in client.get('/evenement/1/dashboard').text
    with app.app_context():
        FicheImplique.query.filter_by(evenement_id=1, nom='Martin').one().statut = 'sorti'
        db.session.commit()
    assert client.get('/evenement/1/fiches_json').json['nb_familles'] == 1


def test_seeker_links_to_selected_fiche_and_can_also_have_no_fiche(app, client):
    with app.app_context():
        fiche = db.session.get(FicheImplique, 1)
        fiche.nom, fiche.prenom = 'Martin', 'Luc'
        db.session.commit()
    assert client.post('/evenement/1/recherches', data={**fields(), 'seeker_fiche_id': '1'}).status_code == 302
    assert client.post('/evenement/1/recherches', data=fields()).status_code == 302
    with app.app_context():
        assert [row.seeker_fiche_id for row in PersonSearch.query.order_by(PersonSearch.id)] == [1, None]
        # Links persist independently of subsequent corrections to the fiche name.
        db.session.get(FicheImplique, 1).nom = 'Martin corrigé'
        db.session.commit()
    assert 'Fiche au nom du demandeur : F1 — Martin corrigé Luc' in client.get('/evenement/1/recherches').text
    with app.app_context():
        bulk_restore(json.loads(backup_to_bytesio().getvalue()))
        assert PersonSearch.query.order_by(PersonSearch.id).first().seeker_fiche_id == 1
        db.session.execute(db.delete(FicheImplique).where(FicheImplique.id == 1))
        db.session.commit()
        assert PersonSearch.query.order_by(PersonSearch.id).first().seeker_fiche_id is None


@pytest.mark.parametrize('kind', ['foreign', 'animal', 'deleted', 'mismatch', 'invalid'])
def test_linked_seeker_is_validated_in_its_event(app, client, kind):
    with app.app_context():
        fiche = db.session.get(FicheImplique, 1)
        fiche.nom, fiche.prenom = 'Martin', 'Luc'
        if kind == 'animal':
            fiche.est_animal = True
        if kind == 'deleted':
            fiche.statut = 'supprimé'
        if kind == 'mismatch':
            fiche.prenom = 'Autre'
        db.session.commit()
    seeker_id = '2' if kind == 'foreign' else 'invalid' if kind == 'invalid' else '1'
    response = client.post('/evenement/1/recherches', data={**fields(), 'seeker_fiche_id': seeker_id})
    assert response.status_code == (403 if kind == 'foreign' else 302)
    with app.app_context():
        assert PersonSearch.query.count() == 0


def test_found_notifications_are_event_scoped_and_resolve_is_idempotent(app, client):
    since = (utcnow() - timedelta(seconds=1)).isoformat() + 'Z'
    client.post('/evenement/1/recherches', data=fields())
    with app.app_context():
        search_id = PersonSearch.query.one().id
    action = {'action': 'resolve', 'search_id': search_id}
    client.post('/evenement/1/recherches', data=action)
    result = client.get('/api/evenement/1/recherches/etat', query_string={'since': since}).json
    assert result['notifications'][0]['id'] == search_id
    assert result['searches'][0]['resolved_at']
    assert 'search-found' in client.get('/evenement/1/recherches').text
    assert client.get('/evenement/1/fiches_json').json['person_searches'][0]['resolved_at']
    client.post('/evenement/1/recherches', data=action)
    later = client.get('/api/evenement/1/recherches/etat', query_string={'since': result['server_time']}).json
    assert later['notifications'] == []
    assert later['searches'][0]['resolved_at'] == result['searches'][0]['resolved_at']
    assert client.get('/api/evenement/2/recherches/etat', query_string={'since': since}).status_code == 403
    assert client.get('/api/evenement/1/recherches/etat?since=incorrect').status_code == 400
    assert client.get('/api/evenement/1/recherches/correspondances?nom=Dupont&prenom=Emma').json['matches'] == []
    client.post('/evenement/1/recherches', data={'action': 'reopen', 'search_id': search_id})
    assert 'search-missing' in client.get('/evenement/1/recherches').text
    assert client.get('/api/evenement/1/recherches/etat', query_string={'since': since}).json['notifications'] == []


def test_legacy_search_schema_adds_optional_seeker_link():
    legacy = create_app('dev', {'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'})
    with legacy.app_context():
        db.session.execute(db.text('CREATE TABLE person_search (id INTEGER PRIMARY KEY)'))
        db.session.commit()
        _ensure_database_schema(legacy)
        _ensure_database_schema(legacy)
        assert 'seeker_fiche_id' in {column['name'] for column in db.inspect(db.engine).get_columns('person_search')}


def test_existing_fiche_resolves_new_search_immediately(app, client):
    with app.app_context():
        fiche = db.session.get(FicheImplique, 1)
        fiche.nom, fiche.prenom = ' DUPONT ', 'Émma'
        db.session.commit()
    since = utcnow().isoformat() + 'Z'
    client.post('/evenement/1/recherches', data=fields())
    with app.app_context():
        assert PersonSearch.query.one().resolved_at is not None
    response = client.get('/api/evenement/1/recherches/etat', query_string={'since': since}).json
    assert len(response['notifications']) == 1
    assert 'search-found' in client.get('/evenement/1/recherches').text
    again = client.get('/api/evenement/1/recherches/etat', query_string={'since': response['server_time']}).json
    assert again['notifications'] == []
    assert again['searches'][0]['resolved_at'] == response['searches'][0]['resolved_at']


def test_existing_search_resolves_when_fiche_is_corrected(app, client):
    client.post('/evenement/1/recherches', data=fields())
    since = utcnow().isoformat() + 'Z'
    with app.app_context():
        fiche = db.session.get(FicheImplique, 1)
        fiche.nom, fiche.prenom = 'Dupont', 'Emma'
        db.session.commit()
    result = client.get('/api/evenement/1/recherches/etat', query_string={'since': since}).json
    assert len(result['notifications']) == 1
    assert result['searches'][0]['resolved_at']
    assert 'search-found' in client.get('/evenement/1/recherches').text


@pytest.mark.parametrize('kind', ['foreign', 'animal', 'deleted', 'different_first_name', 'different_name'])
def test_automatic_resolution_requires_a_matching_person_in_same_event(app, client, kind):
    with app.app_context():
        fiche = db.session.get(FicheImplique, 2 if kind == 'foreign' else 1)
        fiche.nom, fiche.prenom = 'Dupont', 'Emma'
        if kind == 'animal':
            fiche.est_animal = True
        elif kind == 'deleted':
            fiche.statut = 'supprimé'
        elif kind == 'different_first_name':
            fiche.prenom = 'Anne'
        elif kind == 'different_name':
            fiche.nom = 'Martin'
        db.session.commit()
    since = utcnow().isoformat() + 'Z'
    client.post('/evenement/1/recherches', data=fields())
    result = client.get('/api/evenement/1/recherches/etat', query_string={'since': since}).json
    assert result['notifications'] == []
    assert result['searches'][0]['resolved_at'] is None
    assert 'search-missing' in client.get('/evenement/1/recherches').text


@pytest.mark.parametrize('resolved', [False, True])
def test_delete_search_removes_it_from_event_lists_and_preserves_fiches(app, client, resolved):
    with app.app_context():
        search = PersonSearch(evenement_id=1, created_by_id=2, seeker_fiche_id=1,
                              resolved_at=utcnow() if resolved else None, **fields())
        db.session.add(search)
        db.session.commit()
        search_id = search.id
    page = client.get('/evenement/1/recherches').text
    assert 'value="delete"' in page and '>Supprimer</button>' in page
    response = client.post('/evenement/1/recherches', data={'action': 'delete', 'search_id': search_id},
                           follow_redirects=True)
    assert response.status_code == 200
    assert 'La recherche a été supprimée.' in response.text
    assert f'data-search-id="{search_id}"' not in response.text
    assert client.get('/evenement/1/fiches_json').json['person_searches'] == []
    since = (utcnow() - timedelta(seconds=10)).isoformat() + 'Z'
    status = client.get('/api/evenement/1/recherches/etat', query_string={'since': since}).json
    assert status['searches'] == status['notifications'] == []
    with app.app_context():
        assert db.session.get(PersonSearch, search_id) is None
        assert FicheImplique.query.count() == 2


@pytest.mark.parametrize(('role', 'author', 'allowed'), [
    ('technicien', 2, True), ('technicien', 1, False), ('responsable', 1, True), ('admin', 1, True),
])
def test_delete_search_requires_author_or_manager(app, client, role, author, allowed):
    from app.models import Utilisateur

    with app.app_context():
        db.session.get(Utilisateur, 2).role = role
        db.session.get(Utilisateur, 2).is_admin = role == 'admin'
        search = PersonSearch(evenement_id=1, created_by_id=author, **fields())
        db.session.add(search)
        db.session.commit()
        search_id = search.id
    page = client.get('/evenement/1/recherches').text
    assert ('>Supprimer</button>' in page) == allowed
    response = client.post('/evenement/1/recherches', data={'action': 'delete', 'search_id': search_id})
    assert response.status_code == (302 if allowed else 403)
    with app.app_context():
        assert (db.session.get(PersonSearch, search_id) is None) == allowed


def test_delete_search_cannot_target_another_event(app, client):
    with app.app_context():
        search = PersonSearch(evenement_id=2, created_by_id=2, **fields())
        db.session.add(search)
        db.session.commit()
        search_id = search.id
    assert client.post('/evenement/1/recherches', data={'action': 'delete', 'search_id': search_id}).status_code == 403
    with app.app_context():
        assert db.session.get(PersonSearch, search_id) is not None
