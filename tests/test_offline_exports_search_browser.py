"""Searches created from fiches and downloadable exports with the network disabled."""
import os
from threading import Thread

import pytest
from openpyxl import load_workbook
from werkzeug.serving import make_server

from app.extensions import db
from app.models import FicheImplique, PersonSearch


@pytest.mark.skipif(os.environ.get('CAI_BROWSER_TEST') != '1', reason='Optional browser integration test')
@pytest.mark.parametrize('width', [390, 1280])
def test_fiche_search_and_exports_work_without_network(app, tmp_path, width):
    from playwright.sync_api import expect, sync_playwright

    server = make_server('127.0.0.1', 0, app)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, channel=os.environ.get('CAI_BROWSER_CHANNEL') or None)
            context = browser.new_context(viewport={'width': width, 'height': 900}, accept_downloads=True)
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(base)
            page.get_by_label("Nom d'utilisateur").fill('member')
            page.get_by_label('Mot de passe', exact=True).fill('test-password-123')
            page.get_by_role('button', name='Se connecter').click()
            page.goto(base + '/evenement/1/dashboard')
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur')
            page.evaluate('navigator.serviceWorker.ready')
            page.wait_for_function('navigator.serviceWorker.controller !== null')
            context.set_offline(True)

            page.get_by_role('link', name='Créer une fiche impliquée', exact=True).click()
            form = page.locator('form[data-initial-type]')
            expect(form).to_have_attribute('data-features-ready', 'true')
            form.locator('[name=nom]').fill('Martin')
            form.locator('[name=prenom]').fill('Marc')
            form.locator('#date_naissance_display').fill('01/01/1990')
            form.locator('[name=recherche_nom]').fill('Durand')
            form.locator('[name=recherche_prenom]').fill('Émilie')
            form.locator('[type=submit]').click()
            expect(page.locator('#fiches-table-body')).to_contain_text('Martin')
            page.locator('.dashboard-menu > summary').click()
            page.get_by_role('link', name='Recherche de personnes', exact=True).click()
            expect(page.locator('#offline-search-list')).to_contain_text('Durand Émilie')
            expect(page.locator('#offline-search-list')).to_contain_text('Martin Marc')
            expect(page.locator('#offline-search-list')).to_contain_text('En attente du serveur')
            page.reload()
            expect(page.locator('#offline-search-list .search-entry')).to_have_count(1)

            page.get_by_role('link', name='Créer une fiche et déclarer une recherche', exact=True).click()
            form = page.locator('form[data-initial-type]')
            expect(form).to_have_attribute('data-features-ready', 'true')
            form.locator('[name=nom]').fill('DURAND')
            form.locator('[name=prenom]').fill('Emilie')
            form.locator('#date_naissance_display').fill('02/02/2000')
            expect(page.locator('#wanted-warning')).to_contain_text('Martin Marc')
            form.locator('[type=submit]').click()
            expect(page.locator('#wanted-person-notice')).to_contain_text('Martin Marc')
            row = page.locator('#fiches-table-body tr').filter(has_text='DURAND')
            row.get_by_role('button', name='Bagages', exact=True).click()
            page.locator('#numeros').fill('OFF-123')
            page.locator('#form-bagage button[type=submit]').click()
            expect(row).to_contain_text('OFF-123')
            row.get_by_role('button', name='Sortie', exact=True).click()
            page.locator('#sortie-destination').fill('Hôpital')
            page.locator('#sortie-moyen').fill('Bus')
            page.locator('#form-sortie button[type=submit]').click()
            expect(row.locator('.badge.sorti')).to_be_visible()
            page.reload()
            expect(page.locator('#fiches-table-body')).to_contain_text('OFF-123')

            page.locator('.dashboard-menu > summary').click()
            with page.expect_download() as excel_download:
                page.get_by_role('link', name='Export Excel', exact=True).click()
            excel = excel_download.value
            assert excel.suggested_filename.endswith('.xlsx')
            assert excel.url.startswith('blob:')
            filename = tmp_path / 'offline.xlsx'
            excel.save_as(filename)
            workbook = load_workbook(filename)
            rows = list(workbook['Fiches Impliqués'].values)
            values = [dict(zip(rows[0], record)) for record in rows[1:]]
            assert len(values) == 3
            target = next(record for record in values if record['Nom'] == 'DURAND')
            assert target['Statut'] == 'sorti'
            assert target['Destination'] == 'Hôpital'
            assert target['Bagages'] == 'OFF-123'
            assert target['Synchronisation'] == 'En attente de synchronisation'
            assert next(record for record in values if record['Nom'] == 'Martin')['Recherche personne'] == 'Durand Émilie'
            page.locator('.dashboard-menu > summary').click()
            with page.expect_download() as pdf_download:
                page.get_by_role('link', name='Export PDF', exact=True).click()
            pdf = tmp_path / 'offline.pdf'
            pdf_download.value.save_as(pdf)
            assert pdf_download.value.url.startswith('blob:')
            assert pdf.read_bytes().startswith(b'%PDF-1.4')
            row = page.locator('#fiches-table-body tr').filter(has_text='DURAND')
            row.get_by_role('link', name='Voir', exact=True).click()
            expect(page.locator('#cai-detail-content')).to_contain_text('OFF-123')
            with page.expect_download() as fiche_download:
                page.get_by_role('button', name='Exporter PDF', exact=True).click()
            fiche_pdf = tmp_path / 'fiche.pdf'
            fiche_download.value.save_as(fiche_pdf)
            assert fiche_pdf.read_bytes().startswith(b'%PDF-1.4')
            assert not errors, errors

            # Open the online searches page while creation is still queued,
            # then check that its entry remains visible after the server receipt.
            sync_url = '**/api/evenement/1/fiches/sync'
            page.route(sync_url, lambda route: route.abort())
            context.set_offline(False)
            page.goto(base + '/evenement/1/recherches')
            expect(page.locator('#local-search-list')).to_contain_text('Durand Émilie')
            page.unroute(sync_url)
            page.evaluate('CAIOffline.sync()')
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur', timeout=20000)
            expect(page.locator('#local-search-list')).to_contain_text('Durand Émilie')
            expect(page.locator('.search-entry')).to_have_count(1)
            with app.app_context():
                search = PersonSearch.query.one()
                assert (search.target_nom, search.target_prenom) == ('Durand', 'Émilie')
                assert (search.seeker_nom, search.seeker_prenom) == ('Martin', 'Marc')
                target = FicheImplique.query.filter_by(nom='DURAND').one()
                assert target.statut == 'sorti'
                assert [bagage.numero for bagage in target.bagages] == ['OFF-123']
            page.goto(base + '/evenement/1/recherches')
            expect(page.locator('.search-entry')).to_have_count(1)
            expect(page.locator('.search-entry')).to_contain_text('Fiche correspondante')
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
