"""Real phone/tablet workflows for the additional event tools."""
import os
from datetime import date
from pathlib import Path
from threading import Thread

import pytest
from werkzeug.serving import make_server

from app.extensions import db
from app.models import EventSettings, FicheImplique


@pytest.mark.skipif(os.environ.get('CAI_BROWSER_TEST') != '1', reason='Optional browser integration test')
@pytest.mark.parametrize('width', [390, 768])
def test_edit_conflict_drafts_and_tools(app, width, tmp_path):
    from playwright.sync_api import expect, sync_playwright

    from app.fiche_updates import apply_edit
    from app.models import Utilisateur

    with app.app_context():
        fiche = db.session.get(FicheImplique, 1)
        fiche.nom, fiche.prenom, fiche.date_naissance = 'Exemple', 'Alice', date(1990, 1, 31)
        db.session.add(EventSettings(id=1, capacity=2, warning_percent=50,
            choice_lists={'destinations':['Domicile'], 'transports':['Bus'], 'zones':['Nord','Sud'], 'competences':['Interprète']},
            custom_fields=[{'key':'besoin','label':'Besoin particulier','type':'text','scope':'all','required':False,'choices':[]}]))
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
            page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto(base)
            page.get_by_label("Nom d'utilisateur").fill('member')
            page.get_by_label('Mot de passe',exact=True).fill('test-password-123')
            page.get_by_role('button',name='Se connecter').click()
            page.goto(base+'/evenement/1/dashboard')
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur')
            expect(page.locator('#capacity-alert')).to_contain_text('Seuil d’alerte atteint')
            page.get_by_role('button',name='Disponibilité hors ligne').click()
            prep=page.get_by_role('dialog',name='Disponibilité hors ligne')
            expect(prep).to_contain_text('1 fiche(s) disponibles')
            prep.get_by_role('button',name='Fermer',exact=True).click()

            # A protected QR also opens an already prepared fiche without a network.
            qr=page.evaluate("async()=> (await CAIOffline.cached()).fiches.find(f=>f.id===1).qr_url")
            context.set_offline(True)
            page.goto(qr)
            expect(page.locator('#cai-detail-content')).to_contain_text('Exemple')
            page.goto(base+'/evenement/1/dashboard')
            expect(page.locator('#fiche-row-1')).to_be_visible()
            # The usual Edit action works offline and shows the saved values.
            page.locator('#fiche-row-1').get_by_role('link',name='Modifier',exact=True).click()
            form=page.locator('form[data-initial-type]')
            expect(form).to_have_attribute('data-features-ready','true')
            expect(form.locator('[name=nom]')).to_have_value('Exemple')
            form.locator('[name=telephone]').fill('0612345678')
            form.get_by_label('Famille / groupe',exact=True).fill('Famille Martin')
            form.get_by_label('Besoin particulier',exact=True).fill('Interprète')
            form.get_by_label('Zone d’accueil',exact=True).select_option('Nord')
            form.locator('button[type=submit]').click()
            expect(page.locator('#fiche-row-1 .cai-sync-pending')).to_be_visible()
            with app.app_context():
                apply_edit(db.session.get(FicheImplique,1),db.session.get(Utilisateur,1),{'adresse':'Rue du serveur'},{'adresse':''})
                db.session.commit()
            context.set_offline(False)
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur',timeout=20000)
            with app.app_context():
                fiche=db.session.get(FicheImplique,1)
                assert fiche.telephone=='0612345678' and fiche.adresse=='Rue du serveur'
            page.locator('#search-bar').fill('0612345678')
            expect(page.locator('#fiche-row-1')).to_be_visible()
            page.locator('#search-bar').fill('Famille Martin')
            expect(page.locator('#fiche-row-1')).to_be_visible()
            page.locator('#search-bar').fill('')

            # A same-field edit must be resolved explicitly.
            context.set_offline(True)
            page.locator('#fiche-row-1').get_by_role('link',name='Modifier',exact=True).click()
            expect(form).to_have_attribute('data-features-ready','true')
            form.locator('[name=telephone]').fill('0699999999')
            form.locator('button[type=submit]').click()
            page.wait_for_url('**/evenement/1/dashboard')
            with app.app_context():
                apply_edit(db.session.get(FicheImplique,1),db.session.get(Utilisateur,1),{'telephone':'0600000000'},{'telephone':'0612345678'})
                db.session.commit()
            context.set_offline(False)
            conflict=page.get_by_role('dialog',name='Choisir les valeurs à conserver')
            expect(conflict).to_be_visible(timeout=20000)
            conflict.get_by_role('radio',name='Ma valeur : 0699999999').check()
            conflict.get_by_role('button',name='Appliquer mes choix et synchroniser').click()
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur',timeout=20000)
            with app.app_context():
                assert db.session.get(FicheImplique,1).telephone=='0699999999'

            # Autosave survives a reload; duplicate warning is separate from saving.
            context.set_offline(True)
            page.get_by_role('link',name='Créer une fiche impliquée',exact=True).click()
            expect(form).to_have_attribute('data-features-ready','true')
            form.locator('[name=nom]').fill('Exemple')
            form.locator('[name=prenom]').fill('Alice')
            form.locator('#date_naissance_display').fill('31/01/1990')
            form.locator('#date_naissance_display').dispatch_event('blur')
            expect(form.locator('.feature-draft')).to_contain_text('Brouillon enregistré sur cet appareil.')
            page.reload()
            expect(form).to_have_attribute('data-features-ready','true')
            expect(page.get_by_role('button',name='Reprendre le brouillon')).to_be_visible()
            page.get_by_role('button',name='Reprendre le brouillon').click()
            expect(form.locator('[name=nom]')).to_have_value('Exemple')
            expect(form.locator('#date_naissance_display')).to_have_value('31/01/1990')
            form.locator('[name=nom]').dispatch_event('input')
            expect(page.locator('#duplicate-warning')).to_contain_text('Doublon possible')
            form.locator('[name=nom]').fill('Nouvelle fiche')
            form.locator('button[type=submit]').click()
            expect(page.locator('#fiches-table-body')).to_contain_text('Nouvelle fiche')
            local=page.locator('#fiches-table-body tr').filter(has_text='Nouvelle fiche')
            page.once('dialog',lambda dialog:dialog.accept())
            local.get_by_role('button',name='Supprimer',exact=True).click()
            expect(local).to_have_count(0)
            page.get_by_role('button',name='Disponibilité hors ligne').click()
            prep=page.get_by_role('dialog',name='Disponibilité hors ligne')
            expect(prep).to_contain_text('Corbeille de cet appareil')
            prep.get_by_role('button',name='Restaurer cette fiche locale',exact=True).click()
            prep.get_by_role('button',name='Fermer',exact=True).click()
            expect(local).to_be_visible()
            context.set_offline(False)
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur',timeout=20000)

            # Saved groups, QR and full history are visible in the normal detail view.
            page.locator('#fiche-row-1').get_by_role('link',name='Voir',exact=True).click()
            expect(page.locator('#feature-detail')).to_contain_text('Famille Martin')
            expect(page.get_by_role('img',name='QR d’accès à la fiche F1')).to_be_visible()
            page.get_by_text('Historique détaillé des modifications',exact=True).click()
            expect(page.locator('#feature-detail')).to_contain_text('0699999999')
            page.goto(base+'/evenement/1/outils')
            expect(page.get_by_role('heading',name='Familles et groupes',exact=True)).to_be_visible()
            expect(page.locator('#groupes')).to_contain_text('Famille Martin')
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            preview=Path(os.environ.get('CAI_UI_PREVIEW_DIR',str(tmp_path)))
            preview.mkdir(parents=True,exist_ok=True)
            page.screenshot(path=str(preview/f'outils-{width}.png'),full_page=True)
            page.get_by_role('button',name='+ Ajouter un champ',exact=True).click()
            page.get_by_label('Libellé du champ',exact=True).last.fill('Langue')
            page.get_by_role('button',name='Enregistrer les réglages',exact=True).click()
            expect(page.get_by_text('Les réglages de l’évènement ont été enregistrés.',exact=True)).to_be_visible()

            # Recycle a server fiche, restore it, customize the dashboard, then lock it.
            page.goto(base+'/evenement/1/dashboard')
            expect(page.locator('#cai-connection-label')).to_have_text('Synchronisé au serveur')
            page.once('dialog',lambda dialog:dialog.accept())
            page.locator('#fiche-row-1').get_by_role('button',name='Supprimer',exact=True).click()
            expect(page.locator('#fiche-row-1')).to_have_count(0,timeout=20000)
            page.goto(base+'/evenement/1/outils#corbeille')
            page.get_by_role('button',name='Restaurer la fiche',exact=True).click()
            expect(page.locator('#corbeille')).to_contain_text('La corbeille est vide')
            page.goto(base+'/mes-preferences?next=/evenement/1/dashboard')
            page.locator('[name=lock_minutes]').select_option('1')
            page.get_by_label('Affichage compact',exact=True).check()
            page.get_by_label('Afficher les bagages',exact=True).uncheck()
            page.get_by_role('button',name='Enregistrer mes préférences').click()
            expect(page.locator('body')).to_have_class(__import__('re').compile(r'\bcai-compact\b'))
            expect(page.locator('#fiche-row-1 .bagages-cell')).not_to_be_visible()
            page.get_by_role('button',name='Verrouiller',exact=True).click()
            lock=page.get_by_role('dialog',name='Appareil verrouillé')
            expect(lock).to_be_visible()
            page.keyboard.press('Escape')
            expect(lock).to_be_visible()
            lock.get_by_label('Mot de passe du compte',exact=True).fill('test-password-123')
            lock.get_by_role('button',name='Déverrouiller',exact=True).click()
            expect(lock).to_have_count(0)
            # The inactivity clock survives an offline reload.
            context.set_offline(True)
            page.evaluate("async()=> CAIOfflineStore.put({key:'activity:2',at:Date.now()-61000})")
            page.reload()
            lock=page.get_by_role('dialog',name='Appareil verrouillé')
            expect(lock).to_be_visible()
            lock.get_by_label('Mot de passe du compte',exact=True).fill('test-password-123')
            lock.get_by_role('button',name='Déverrouiller',exact=True).click()
            expect(lock).to_contain_text('Reconnectez cet appareil pour déverrouiller.')
            context.set_offline(False)
            lock.get_by_role('button',name='Déverrouiller',exact=True).click()
            expect(lock).to_have_count(0)
            assert not errors,errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
