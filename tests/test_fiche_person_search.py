"""Searches declared on fiches share their creation transaction and offline UUID."""
from uuid import uuid4

import pytest

from app.extensions import db
from app.models import FicheImplique, FicheMetadata, PersonSearch, TimelineEntry


def fiche_fields(**values):
    return {'evenement_id': '1', 'nom': 'Martin', 'prenom': 'Luc',
            'date_naissance': '1990-01-01', 'recherche_nom': ' Dupont  ',
            'recherche_prenom': '  Élise  Anne ', **values}


def test_creation_registers_search_and_matches_a_later_fiche(app, client):
    response = client.post('/fiche/new', data=fiche_fields())
    assert response.status_code == 302
    with app.app_context():
        row = PersonSearch.query.one()
        assert (row.evenement_id, row.created_by_id) == (1, 2)
        assert (row.seeker_nom, row.seeker_prenom) == ('Martin', 'Luc')
        assert (row.target_nom, row.target_prenom) == ('Dupont', 'Élise Anne')
        fiche = FicheImplique.query.filter_by(nom='Martin').one()
        assert fiche.recherche_personne == 'Dupont Élise Anne'
        seeker_id = fiche.id
    snapshot = client.get('/evenement/1/fiches_json?details=1').json
    assert snapshot['person_searches'][0]['target_prenom'] == 'Élise Anne'
    page = client.get('/evenement/1/recherches').text
    assert f'href="/fiche/{seeker_id}"' in page
    assert 'Fiche au nom du demandeur' in page
    assert 'Dupont Élise Anne' in page

    response = client.post('/fiche/new', data=fiche_fields(nom='DUPONT', prenom='elise anne',
        recherche_nom='', recherche_prenom=''), follow_redirects=True)
    assert 'Cette personne est recherchée par : Martin Luc.' in response.text


def test_offline_retry_creates_only_one_search(app, client):
    values = fiche_fields(client_uuid=str(uuid4()), user_id='2')
    first = client.post('/api/evenement/1/fiches/sync', data=values)
    second = client.post('/api/evenement/1/fiches/sync', data=values)
    assert first.status_code == second.status_code == 200
    assert first.json['id'] == second.json['id']
    with app.app_context():
        assert PersonSearch.query.count() == 1
        assert FicheImplique.query.filter_by(client_uuid=values['client_uuid']).count() == 1
        assert TimelineEntry.query.filter_by(fiche_id=first.json['id'], kind='create').count() == 1


@pytest.mark.parametrize('overrides', [
    {'recherche_nom': ''}, {'recherche_prenom': ''}, {'recherche_nom': 'x' * 101},
    {'recherche_prenom': 'x' * 101}, {'nom': ''}, {'prenom': ''},
    {'custom_values': 'invalid JSON'},
])
def test_invalid_search_or_fiche_rolls_back_everything(app, client, overrides):
    response = client.post('/api/evenement/1/fiches/sync', data=fiche_fields(
        client_uuid=str(uuid4()), user_id='2', **overrides))
    assert response.status_code == 422
    with app.app_context():
        assert FicheImplique.query.count() == 2
        assert PersonSearch.query.count() == 0
        assert FicheMetadata.query.count() == 0
        assert TimelineEntry.query.count() == 0


def test_legacy_search_text_stays_readable_without_guessing_the_identity(app, client):
    response = client.post('/fiche/new', data=fiche_fields(recherche_nom='', recherche_prenom='',
        recherche_personne='Mon voisin Jean, nom inconnu'))
    assert response.status_code == 302
    with app.app_context():
        assert FicheImplique.query.filter_by(nom='Martin').one().recherche_personne == 'Mon voisin Jean, nom inconnu'
        assert PersonSearch.query.count() == 0


def test_stale_human_search_fields_do_not_create_a_search_for_an_animal(app, client):
    response = client.post('/api/evenement/1/fiches/sync', data=fiche_fields(
        type_fiche='animal', animal_nom='Milo', client_uuid=str(uuid4()), user_id='2'))
    assert response.status_code == 200
    with app.app_context():
        assert db.session.get(FicheImplique, response.json['id']).recherche_personne is None
        assert PersonSearch.query.count() == 0


def test_creation_form_and_offline_edit_keep_their_respective_search_fields(client):
    for path in ('/fiche/new?evenement_id=1', '/hors-ligne/fiche'):
        page = client.get(path).text
        assert 'name="recherche_nom"' in page and 'name="recherche_prenom"' in page
        assert 'name="recherche_personne"' not in page
    page = client.get('/hors-ligne/fiche/edit').text
    assert 'name="recherche_personne"' in page
    assert 'name="recherche_nom"' not in page
    page = client.get('/evenement/1/recherches').text
    assert 'id="local-search-list"' in page
    assert 'Créer la fiche du demandeur' in page
