"""Live notification delivery and seeker suggestions on phone and desktop."""
import os
from threading import Thread

import pytest
from werkzeug.serving import make_server

from app.extensions import db
from app.models import FicheImplique


@pytest.mark.skipif(os.environ.get('CAI_BROWSER_TEST') != '1', reason='Optional browser integration test')
def test_found_person_popup_and_seeker_suggestions(app, tmp_path):
    from playwright.sync_api import expect, sync_playwright

    with app.app_context():
        fiche = db.session.get(FicheImplique, 1)
        fiche.nom, fiche.prenom = 'Martin', 'Luc'
        db.session.add(FicheImplique(numero='F3', evenement_id=1, utilisateur_id=2, nom='MARTIN', prenom='Anne'))
        db.session.commit()
    server = make_server('127.0.0.1', 0, app)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, channel=os.environ.get('CAI_BROWSER_CHANNEL') or None)
            context = browser.new_context(viewport={'width': 390, 'height': 900})
            page = context.new_page()
            errors = []
            context.on('page', lambda p: p.on('pageerror', lambda error: errors.append(str(error))))
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(base)
            page.get_by_label("Nom d'utilisateur").fill('admin')
            page.get_by_label('Mot de passe', exact=True).fill('test-password-123')
            page.get_by_role('button', name='Se connecter').click()
            page.goto(base + '/evenement/1/dashboard')
            expect(page.locator('#nb_familles')).to_have_text('1')
            watcher = context.new_page()
            watcher.set_viewport_size({'width': 1280, 'height': 900})
            watcher.goto(base + '/evenement/1/dashboard')
            unrelated = context.new_page()
            unrelated.goto(base + '/evenement/2/dashboard')
            tools = context.new_page()
            tools.goto(base + '/evenement/1/outils')
            page.goto(base + '/evenement/1/recherches')
            name = page.get_by_label('Nom de la personne qui recherche', exact=True)
            first = page.get_by_label('Prénom de la personne qui recherche', exact=True)
            name.fill('mar')
            expect(page.locator('#seeker-suggestions button')).to_have_count(2)
            page.get_by_role('button', name='Martin Luc — F1', exact=True).click()
            expect(first).to_have_value('Luc')
            expect(page.locator('[name=seeker_fiche_id]')).to_have_value('1')
            page.get_by_label('Nom de la personne recherchée', exact=True).fill('Durand')
            page.get_by_label('Prénom de la personne recherchée', exact=True).fill('Emma')
            page.get_by_role('button', name='Enregistrer la recherche', exact=True).click()
            row = page.locator('[data-search-id]').filter(has_text='Durand Emma')
            expect(row).to_have_class('search-entry search-missing')
            expect(row.locator('[data-search-status]')).to_contain_text('Personne non retrouvée')
            expect(watcher.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur')
            # Both screens have an initialized event watch before resolution.
            page.wait_for_function("sessionStorage.getItem('search-watch:1:1') !== null")
            row.get_by_role('button', name='Marquer comme retrouvée', exact=True).click()
            row = page.locator('[data-search-id]').filter(has_text='Durand Emma')
            expect(row).to_have_class('search-entry search-found')
            expect(watcher.locator('.search-toast')).to_contain_text('Durand Emma', timeout=12000)
            expect(page.locator('.search-toast')).to_contain_text('Durand Emma', timeout=12000)
            expect(tools.locator('.search-toast')).to_contain_text('Durand Emma', timeout=12000)
            expect(unrelated.locator('.search-toast')).to_have_count(0)
            watcher.screenshot(path=str(tmp_path / 'found-notification-desktop.png'))
            page.screenshot(path=str(tmp_path / 'search-found-phone.png'), full_page=True)
            expect(watcher.locator('.search-toast')).to_have_count(0, timeout=6500)
            expect(page.locator('.search-toast')).to_have_count(0, timeout=6500)
            # A subsequent poll must not replay the same notification.
            watcher.wait_for_timeout(3200)
            expect(watcher.locator('.search-toast')).to_have_count(0)
            row.get_by_role('button', name='Relancer la recherche', exact=True).click()
            expect(page.locator('[data-search-id]')).to_have_class('search-entry search-missing')
            # Editing the selected identity returns to free entry.
            name.fill('Martin')
            page.get_by_role('button', name='Martin Luc — F1', exact=True).click()
            first.fill('Libre')
            expect(page.locator('[name=seeker_fiche_id]')).to_have_value('')
            name.fill('Sans fiche')
            first.fill('Libre')
            page.get_by_label('Nom de la personne recherchée', exact=True).fill('Autre')
            page.get_by_label('Prénom de la personne recherchée', exact=True).fill('Personne')
            page.get_by_role('button', name='Enregistrer la recherche', exact=True).click()
            expect(page.locator('[data-search-id]').filter(has_text='Sans fiche Libre')).to_have_count(1)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
