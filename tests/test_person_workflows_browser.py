"""Phone/tablet searches, offline matching, family groups and account appearance."""
import os
import re
from pathlib import Path
from threading import Thread

import pytest
from werkzeug.serving import make_server

from app.extensions import db
from app.models import FicheImplique


@pytest.mark.skipif(os.environ.get('CAI_BROWSER_TEST') != '1', reason='Optional browser integration test')
@pytest.mark.parametrize('width', [390, 768])
def test_search_families_and_private_appearance(app, width, tmp_path):
    from playwright.sync_api import expect, sync_playwright

    with app.app_context():
        first = db.session.get(FicheImplique, 1)
        first.nom, first.prenom = 'Dupont', 'Alice'
        db.session.add_all([FicheImplique(numero='F3', nom='DUPONT', prenom='Luc', evenement_id=1, utilisateur_id=2),
                            FicheImplique(numero='F4', nom='Martin', prenom='Marc', evenement_id=1, utilisateur_id=2)])
        db.session.commit()
    server = make_server('127.0.0.1', 0, app)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, channel=os.environ.get('CAI_BROWSER_CHANNEL') or None)
            context = browser.new_context(viewport={'width':width,'height':900}, has_touch=True)
            page = context.new_page()
            errors=[]
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(base)
            page.get_by_label("Nom d'utilisateur").fill('member')
            page.get_by_label('Mot de passe',exact=True).fill('test-password-123')
            page.get_by_role('button',name='Se connecter').click()
            page.goto(base+'/evenement/1/dashboard')
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur')
            expect(page.locator('#fiche-row-1 .family-hint')).to_contain_text('2 fiches')
            menu=page.locator('.dashboard-menu')
            menu.locator('summary').click()
            expect(menu.get_by_role('link',name='Envoyer une alerte ou un message')).to_be_visible()
            back=menu.get_by_role('link',name='Retour au menu principal')
            expect(back).to_have_css('background-color','rgb(255, 211, 77)')
            assert back.evaluate("a=>a.nextElementSibling.matches('form[action=\"/logout\"]')")
            menu.get_by_role('link',name='Recherche de personnes',exact=True).click()
            page.get_by_label('Nom de la personne qui recherche',exact=True).fill('Martin')
            page.get_by_label('Prénom de la personne qui recherche',exact=True).fill('Marc')
            page.get_by_label('Nom de la personne recherchée',exact=True).fill('Dupont')
            page.get_by_label('Prénom de la personne recherchée',exact=True).fill('Emma')
            page.get_by_role('button',name='Enregistrer la recherche',exact=True).click()
            expect(page.get_by_text('La recherche de personne a été enregistrée.',exact=True)).to_be_visible()
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur')
            page.get_by_role('link',name='← Tableau de bord',exact=True).click()
            page.get_by_role('link',name='Créer une fiche impliquée',exact=True).click()
            form=page.locator('form[data-initial-type]')
            expect(form).to_have_attribute('data-features-ready','true')
            form.locator('[name=nom]').fill('Dupont')
            form.locator('[name=prenom]').fill('Emma')
            form.locator('#date_naissance_display').fill('01/01/2000')
            expect(page.locator('#wanted-warning')).to_contain_text('recherchée par : Martin Marc')
            expect(page.locator('#automatic-family')).to_contain_text('Famille automatique : Dupont')
            for name in ['nationalite','effets_perso','numero_recherche','numero_pec']:
                expect(form.locator(f'[name={name}]')).to_have_count(0)
            notes=form.locator('[name=autres_informations]')
            notes.fill('Informations complémentaires visibles dans un champ de saisie assez grand.')
            assert notes.bounding_box()['height']>=160
            assert notes.bounding_box()['width']>=form.locator('[name=nom]').bounding_box()['width']
            context.set_offline(True)
            form.locator('[type=submit]').click()
            expect(page.locator('#wanted-person-notice')).to_contain_text('Martin Marc')
            row=page.locator('#fiches-table-body tr').filter(has_text='Emma')
            expect(row.locator('.cai-sync-pending')).to_be_visible()
            expect(row.locator('.family-hint')).to_contain_text('3 fiches')
            page.locator('.dashboard-menu > summary').click()
            page.get_by_role('link',name='Recherche de personnes',exact=True).click()
            expect(page.locator('#offline-search-list')).to_contain_text('Dupont Emma')
            expect(page.locator('#offline-search-list')).to_contain_text('Martin Marc')
            page.get_by_role('link',name='← Tableau de bord',exact=True).click()
            context.set_offline(False)
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur',timeout=20000)
            page.goto(base+'/evenement/1/outils')
            expect(page.locator('#groupes')).to_contain_text('Famille Dupont · 3 fiche(s)')
            group=page.locator('form[action="/evenement/1/groupes"]')
            group.get_by_label('Nom du groupe manuel').fill('Équipe terrain')
            group.get_by_role('checkbox',name=re.compile('Martin Marc')).check()
            group.get_by_role('checkbox',name=re.compile('Dupont Emma')).check()
            group.get_by_role('button',name='Créer le groupe / relier les profils').click()
            expect(page.locator('#groupes')).to_contain_text('Équipe terrain · 2 fiche(s)')
            page.goto(base+'/mes-preferences?next=/evenement/1/dashboard')
            page.get_by_label('Thème',exact=True).select_option('dark')
            page.get_by_label('Couleur principale',exact=True).select_option('violet')
            page.get_by_label('Taille du texte',exact=True).select_option('large')
            page.get_by_label('Largeur de l’affichage',exact=True).select_option('wide')
            page.get_by_label('Forme des éléments',exact=True).select_option('square')
            page.get_by_label('Alterner la couleur des lignes').check()
            page.get_by_label('Réduire les animations').check()
            expect(page.locator('body')).to_have_attribute('data-theme','dark')
            page.get_by_role('button',name='Enregistrer mes préférences',exact=True).click()
            expect(page.locator('body')).to_have_attribute('data-theme','dark')
            expect(page.locator('body')).to_have_attribute('data-font-size','large')
            expect(page.locator('#fiche-row-1 .badge.present')).to_have_css('color','rgb(176, 241, 206)')
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur')
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            preview=Path(os.environ.get('CAI_UI_PREVIEW_DIR',str(tmp_path)))
            preview.mkdir(parents=True,exist_ok=True)
            page.screenshot(path=str(preview/f'personal-dashboard-{width}.png'),full_page=True)
            page.goto(base+'/fiche/new?evenement_id=1')
            expect(page.locator('form[data-initial-type]')).to_have_attribute('data-features-ready','true')
            expect(page.locator('body')).to_have_attribute('data-theme','dark')
            page.screenshot(path=str(preview/f'personal-form-{width}.png'),full_page=True)
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            other=browser.new_context()
            admin=other.new_page()
            admin.goto(base)
            admin.get_by_label("Nom d'utilisateur").fill('admin')
            admin.get_by_label('Mot de passe',exact=True).fill('test-password-123')
            admin.get_by_role('button',name='Se connecter').click()
            admin.goto(base+'/evenement/1/dashboard')
            expect(admin.locator('body')).to_have_attribute('data-theme','light')
            assert not errors,errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
