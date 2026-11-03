"""Touch layout and keyboard regressions at phone, tablet and desktop widths."""
import os
from pathlib import Path
from threading import Thread

import pytest
from werkzeug.serving import make_server

from app.extensions import db
from app.models import FicheImplique


def assert_fits(page):
    overflow = page.evaluate("""() => [...document.querySelectorAll('body *')].filter(node => {
      const box=node.getBoundingClientRect(); return box.width && box.right>innerWidth+1 && getComputedStyle(node).position!=='fixed';
    }).slice(0,8).map(node => ({tag:node.tagName,cls:node.className,id:node.id,w:node.getBoundingClientRect().width}))""")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (page.url, overflow)


def assert_named_fields(page):
    missing = page.evaluate("""() => [...document.querySelectorAll('input,select,textarea')]
      .filter(input => input.type !== 'hidden' && input.getClientRects().length &&
        !input.labels?.length && !input.getAttribute('aria-label') && !input.getAttribute('aria-labelledby'))
      .map(input => input.id || input.name)""")
    assert not missing, missing


@pytest.mark.skipif(os.environ.get("CAI_BROWSER_TEST") != "1", reason="Optional browser integration test")
@pytest.mark.parametrize("width,height", [(320, 740), (390, 844), (768, 1024), (1024, 768), (1280, 800), (1440, 900)])
def test_responsive_layout_and_keyboard(app, width, height, tmp_path):
    from playwright.sync_api import sync_playwright, expect

    with app.app_context():
        fiche = db.session.get(FicheImplique, 1)
        fiche.nom, fiche.prenom = "Marie-Claire de la Tour", "Jean-Baptiste"
        fiche.difficultes = "Accompagnement nécessaire pour les déplacements."
        fiche.competences = "Médecin"
        db.session.add(FicheImplique(numero="001-0001", evenement_id=1, utilisateur_id=1,
                                    nom="DUPONT", prenom="Aline", statut="sorti"))
        db.session.commit()
    server = make_server("127.0.0.1", 0, app)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, channel=os.environ.get("CAI_BROWSER_CHANNEL") or None)
            context = browser.new_context(viewport={"width": width, "height": height},
                                          has_touch=width <= 1280, is_mobile=width <= 700,
                                          reduced_motion="reduce")
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(base)
            assert_fits(page)
            page.get_by_label("Nom d'utilisateur").fill("member")
            page.get_by_label("Mot de passe").fill("test-password-123")
            page.get_by_role("button", name="Se connecter").click()
            page.wait_for_url("**/evenement/new")
            assert_fits(page)
            page.goto(base + "/evenement/1/dashboard")
            expect(page.locator("#cai-connection-label")).to_have_text("Synchronisé au serveur", timeout=20000)
            expect(page.locator("#fiche-results-count")).to_have_text("2 fiches affichées sur 2")
            assert_fits(page)
            expect(page.get_by_role("table", name="Fiches des impliqués")).to_be_visible()
            if width <= 1280:
                columns = page.locator("#fiches-table-body").evaluate("node => getComputedStyle(node).gridTemplateColumns.split(' ').length")
                assert columns == (1 if width <= 700 else 2)
                expect(page.locator(".cell-label").first).to_be_visible()
                sizes = page.locator("#fiche-row-1 .actions :is(a,button)").evaluate_all(
                    "nodes => nodes.map(node => ({w:node.getBoundingClientRect().width,h:node.getBoundingClientRect().height}))")
                assert all(size["w"] >= 44 and size["h"] >= 44 for size in sizes), sizes
            else:
                expect(page.locator(".cell-label").first).not_to_be_visible()

            # Visible search and checkbox filters work without a modifier key.
            search = page.get_by_role("searchbox", name="Rechercher par nom, téléphone, code Sinus, bagage, numéro de fiche ou groupe")
            expect(search).to_be_visible()
            search.fill("DUPONT")
            expect(page.locator("#fiches-table-body tr:visible")).to_have_count(1)
            search.fill("")
            page.locator("#toggle-filters").click()
            page.get_by_role("checkbox", name="Sorti", exact=True).check()
            expect(page.locator("#fiches-table-body tr:visible")).to_have_count(1)
            page.get_by_role("checkbox", name="Médecin", exact=True).check()
            expect(page.locator("#fiche-empty-state")).to_be_visible()
            page.get_by_role("button", name="Réinitialiser").click()
            expect(page.locator("#fiches-table-body tr:visible")).to_have_count(2)
            assert_named_fields(page)
            page.locator("#toggle-filters").click()

            menu = page.locator(".dashboard-menu")
            menu.locator("summary").click()
            expect(menu.get_by_role("link", name="Gestion des évènements")).to_be_visible()
            page.keyboard.press("Escape")
            expect(menu).not_to_have_attribute("open", "")

            # Dialog traps focus, Escape returns to its trigger, and short screens fit.
            trigger = page.locator("#fiche-row-1").get_by_role("button", name="Bagages", exact=True)
            trigger.focus()
            trigger.press("Enter")
            dialog = page.get_by_role("dialog", name="Rattacher des bagages")
            expect(dialog).to_be_visible()
            expect(page.get_by_label("Numéro(s) de bagage")).to_be_focused()
            assert_named_fields(page)
            dialog.get_by_role("button", name="Annuler").focus()
            page.keyboard.press("Tab")
            expect(dialog.get_by_role("button", name="Fermer")).to_be_focused()
            page.keyboard.press("Escape")
            expect(dialog).not_to_be_visible()
            expect(trigger).to_be_focused()
            if width <= 1280:
                page.set_viewport_size({"width": width, "height": 480})
                page.locator("#fiche-row-1").get_by_role("button", name="Sortie", exact=True).click()
                dialog = page.get_by_role("dialog", name="Déclarer la sortie")
                expect(dialog).to_be_visible()
                box = dialog.locator(".modal-content").bounding_box()
                assert box["y"] >= 0 and box["y"] + box["height"] <= 481, box
                dialog.get_by_role("button", name="Annuler").click()
                page.set_viewport_size({"width": width, "height": height})

            preview = Path(os.environ.get("CAI_UI_PREVIEW_DIR", str(tmp_path)))
            preview.mkdir(parents=True, exist_ok=True)
            page.evaluate("scrollTo(0,0)")
            page.screenshot(path=str(preview / f"dashboard-{width}.png"), full_page=True)
            for path in ["/fiche/new?evenement_id=1", "/fiche/1", "/fiche/edit/1", "/evenement/1/panorama"]:
                page.goto(base + path)
                assert_fits(page)
                assert_named_fields(page)
                if width <= 1280:
                    sizes = page.locator('input:not([type="hidden"]),select,textarea').evaluate_all(
                        "nodes => nodes.filter(node => node.getClientRects().length).map(node => parseFloat(getComputedStyle(node).fontSize))")
                    assert all(size >= 16 for size in sizes), (path, sizes)
            if width in (390, 768):
                page.goto(base + "/fiche/new?evenement_id=1")
                expect(page.locator("#cai-connection-label")).to_have_text("Synchronisé au serveur")
                page.evaluate("scrollTo(0,0)")
                page.screenshot(path=str(preview / f"form-{width}.png"), full_page=True)
            if width in (320, 768):
                page.goto(base + "/fiche/new?evenement_id=1")
                expect(page.locator("#cai-connection-label")).to_have_text("Synchronisé au serveur")
                context.set_offline(True)
                page.locator('[name="nom"]').fill("Fiche locale sur petit écran")
                page.locator('[name="prenom"]').fill("Test")
                page.locator('#date_naissance_display').fill("31011990")
                page.locator('form[data-initial-type] button[type="submit"]').click()
                local = page.locator("#fiches-table-body tr").filter(has_text="Fiche locale sur petit écran")
                expect(local).to_be_visible()
                assert_fits(page)
                local.get_by_role("button", name="Bagages", exact=True).click()
                expect(page.get_by_role("dialog", name="Rattacher des bagages")).to_be_visible()
                page.keyboard.press("Escape")
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
