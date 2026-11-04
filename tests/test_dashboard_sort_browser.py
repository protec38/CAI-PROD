"""Column sorting remains usable with keyboard, cards and offline refreshes."""
import os
from datetime import datetime
from threading import Thread

import pytest
from werkzeug.serving import make_server

from app.extensions import db
from app.models import FicheImplique


@pytest.mark.skipif(os.environ.get('CAI_BROWSER_TEST') != '1', reason='Optional browser integration test')
@pytest.mark.parametrize('width', [390, 1280])
def test_dashboard_sorting_online_and_offline(app, width):
    from playwright.sync_api import expect, sync_playwright

    with app.app_context():
        first = db.session.get(FicheImplique, 1)
        first.numero, first.nom, first.prenom = 'SORT10', 'Émile', 'Zoé'
        first.heure_arrivee = datetime(2026, 1, 31, 23)
        db.session.add_all([
            FicheImplique(id=3, numero='SORT2', nom='alpha', prenom='Camille', evenement_id=1,
                          utilisateur_id=2, heure_arrivee=datetime(2025, 12, 31, 23)),
            FicheImplique(id=4, numero='SORT3', nom='Zola', prenom='Alice', evenement_id=1,
                          utilisateur_id=2, heure_arrivee=datetime(2026, 1, 31, 22)),
        ])
        db.session.commit()
    server = make_server('127.0.0.1', 0, app)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, channel=os.environ.get('CAI_BROWSER_CHANNEL') or None)
            context = browser.new_context(viewport={'width': width, 'height': 900})
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(base)
            page.get_by_label("Nom d'utilisateur").fill('member')
            page.get_by_label('Mot de passe', exact=True).fill('test-password-123')
            page.get_by_role('button', name='Se connecter').click()
            page.goto(base + '/evenement/1/dashboard')
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur')
            rows = page.locator('#fiches-table-body tr')
            names = page.locator('#fiches-table-body [data-col="nom"] [data-value]')
            select = page.get_by_label('Trier par', exact=True)
            if width > 1100:
                header = page.locator('th[data-col="nom"]')
                button = header.get_by_role('button')
                button.click()
                expect(header).to_have_attribute('aria-sort', 'ascending')
                expect(names).to_have_text(['alpha', 'Émile', 'Zola'])
                button.press('Enter')
                expect(header).to_have_attribute('aria-sort', 'descending')
                expect(names).to_have_text(['Zola', 'Émile', 'alpha'])
                button.press('Space')
            else:
                select.select_option('nom')
                expect(names).to_have_text(['alpha', 'Émile', 'Zola'])
                page.get_by_role('button', name='Passer au tri décroissant', exact=True).click()
                expect(names).to_have_text(['Zola', 'Émile', 'alpha'])
            select.select_option('numero')
            expect(rows.locator('.fiche-number')).to_have_text(['SORT2', 'SORT3', 'SORT10'])
            select.select_option('heure_arrivee')
            expect(rows.locator('.fiche-number')).to_have_text(['SORT2', 'SORT3', 'SORT10'])
            page.locator('#search-bar').fill('emile')
            select.select_option('prenom')
            visible_rows = page.locator('#fiches-table-body tr:not([hidden])')
            expect(visible_rows).to_have_count(1)
            expect(visible_rows).to_contain_text('Émile')
            page.locator('#search-bar').fill('')
            select.select_option('nom')
            with app.app_context():
                db.session.get(FicheImplique, 4).nom = 'Aaron'
                db.session.commit()
            page.evaluate('refreshFiches()')
            expect(names).to_have_text(['Aaron', 'alpha', 'Émile'])
            context.set_offline(True)
            page.evaluate("window.dispatchEvent(new Event('cai:local'))")
            expect(names).to_have_text(['Aaron', 'alpha', 'Émile'])
            page.get_by_role('button', name='Passer au tri décroissant', exact=True).click()
            expect(names).to_have_text(['Émile', 'alpha', 'Aaron'])
            page.evaluate('refreshFiches()')
            expect(names).to_have_text(['Émile', 'alpha', 'Aaron'])
            expect(page.locator('th[data-col="nom"]')).to_have_attribute('aria-sort', 'descending')
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
