"""Optional real-browser regression: pip install playwright && playwright install chromium.

Run with CAI_BROWSER_TEST=1. CAI_BROWSER_CHANNEL=msedge uses installed Edge.
The test uses the isolated test database, never the application's real data.
"""
import os
from threading import Thread

import pytest
from werkzeug.serving import make_server

from app.extensions import db
from app.models import Bagage, FicheImplique, OfflineMutation, TimelineEntry


@pytest.mark.skipif(os.environ.get("CAI_BROWSER_TEST") != "1", reason="Optional browser integration test")
def test_offline_reload_and_automatic_recovery(app):
    from playwright.sync_api import sync_playwright, expect

    server = make_server("127.0.0.1", 0, app)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, channel=os.environ.get("CAI_BROWSER_CHANNEL") or None)
            context = browser.new_context(viewport={"width": 390, "height": 844})
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(base)
            page.locator('[name="username"]').fill("member")
            page.locator('[name="password"]').fill("test-password-123")
            page.locator('button[type="submit"]').click()
            page.goto(base + "/evenement/1/dashboard")
            expect(page.get_by_role("status")).to_have_text("Synchronisé au serveur", timeout=20000)
            expect(page.locator(".cai-connection-indicator")).to_have_attribute("data-state", "synced")
            expect(page.locator(".cai-connection-indicator .cai-sync-dot")).to_have_css("background-color", "rgb(23, 128, 61)")
            expect(page.get_by_text("Saisie et fiches hors ligne", exact=True)).to_have_count(0)
            context.set_offline(True)
            expect(page.get_by_role("status")).to_have_text("Mode hors ligne")
            expect(page.locator(".cai-connection-indicator .cai-sync-dot")).to_have_css("background-color", "rgb(237, 136, 0)")
            page.get_by_role("link", name="Créer une fiche impliquée", exact=True).click()
            expect(page.locator("body")).to_have_class("cai-offline-form-page")
            form = page.locator("form[data-initial-type]")
            form.locator('[name="nom"]').fill("Hors Ligne")
            form.locator('[name="prenom"]').fill("Alice")
            form.locator("#date_naissance_display").fill("31/01/1990")
            form.locator('button[type="submit"]').click()
            expect(page.locator("#fiches-table-body")).to_contain_text("Hors Ligne")
            expect(page.locator("#fiches-table-body .cai-sync-pending")).to_have_count(1)
            page.wait_for_url("**/evenement/1/dashboard")
            expect(page.locator("body")).to_have_class("cai-offline-dashboard")
            row = page.locator("#fiches-table-body tr").filter(has_text="Hors Ligne")
            row.get_by_role("button", name="Bagages", exact=True).click()
            page.locator("#numeros").fill("BAG-OFF-1, BAG-OFF-2")
            page.locator('#form-bagage button[type="submit"]').click()
            expect(row).to_contain_text("BAG-OFF-1")
            row.get_by_role("button", name="Sortie", exact=True).click()
            page.locator("#sortie-destination").fill("Domicile")
            page.locator("#sortie-moyen").fill("Bus")
            page.locator('#form-sortie button[type="submit"]').click()
            expect(row.locator('[data-col="statut"]')).to_contain_text("Sorti")
            expect(row).to_have_class("cai-row-pending")
            pending = page.evaluate("CAIOfflineStore.pending(2, 1)")
            assert len(pending) == 3
            uuid = next(record["uuid"] for record in pending if record["kind"] == "fiche")
            page.reload()
            expect(page.locator("#fiches-table-body")).to_contain_text("Hors Ligne")
            expect(page.locator("#fiches-table-body")).to_contain_text("BAG-OFF-2")
            expect(page.locator("#fiches-table-body tr").filter(has_text="Hors Ligne").locator('[data-col="statut"]')).to_contain_text("Sorti")
            page.goto(base)
            expect(page.locator(".table-wrap")).to_be_visible()
            expect(page.locator("#fiches-table-body")).to_contain_text("Hors Ligne")

            # A second operator takes the next number while this device is offline.
            with app.app_context():
                db.session.add(FicheImplique(numero="001-0001", evenement_id=1, utilisateur_id=1))
                db.session.commit()
            context.set_offline(False)
            expect(page.locator("#fiches-table-body")).to_contain_text("001-0002", timeout=20000)
            expect(page.locator("#fiches-table-body .cai-sync-pending")).to_have_count(0)
            expect(page.get_by_role("status")).to_have_text("Synchronisé au serveur")
            with app.app_context():
                fiche = FicheImplique.query.filter_by(client_uuid=uuid).one()
                assert fiche.numero == "001-0002"
                assert fiche.statut == "sorti"
                assert fiche.destination == "Domicile"
                assert {bagage.numero for bagage in fiche.bagages} == {"BAG-OFF-1", "BAG-OFF-2"}
            page.goto(base + "/hors-ligne?event=1")
            expect(page.locator("#fiches-table-body")).to_contain_text("001-0002")
            assert page.evaluate("CAIOfflineStore.pending(2, 1)") == []

            # Test the existing form as well as its offline navigation fallback.
            page.goto(base + "/fiche/new?evenement_id=1")
            form = page.locator("form[data-initial-type]")
            form.locator('[name="nom"]').fill("Formulaire")
            form.locator('[name="prenom"]').fill("Connecté")
            form.locator("#date_naissance_display").fill("31/01/1990")
            form.locator('button[type="submit"]').click()
            page.wait_for_url("**/evenement/1/dashboard")
            expect(page.locator("#fiches-table-body")).to_contain_text("001-0003")
            context.set_offline(True)
            page.reload()
            expect(page.locator(".table-wrap")).to_be_visible()
            expect(page.locator("#fiches-table-body")).to_contain_text("Formulaire")

            # Drop a response after the server has committed: the retry must
            # retrieve its receipt, preserving exactly one server fiche.
            page.get_by_role("link", name="Créer une fiche impliquée", exact=True).click()
            form = page.locator("form[data-initial-type]")
            form.locator('[name="nom"]').fill("Réponse perdue")
            form.locator('[name="prenom"]').fill("Bob")
            form.locator("#date_naissance_display").fill("12/04/1985")
            form.locator('button[type="submit"]').click()
            expect(page.locator("#fiches-table-body")).to_contain_text("Réponse perdue")
            def lose_response(route):
                route.fetch()
                route.abort("failed")
            page.route("**/api/evenement/1/fiches/sync", lose_response)
            context.set_offline(False)
            expect(page.locator(".cai-connection-indicator")).to_have_attribute("data-state", "offline", timeout=20000)
            assert len(page.evaluate("CAIOfflineStore.pending(2, 1)")) == 1
            with app.app_context():
                assert FicheImplique.query.filter_by(nom="Réponse perdue").count() == 1
            page.unroute("**/api/evenement/1/fiches/sync", lose_response)
            page.locator(".cai-connection-indicator").click()
            page.get_by_role("button", name="Synchroniser", exact=True).click()
            expect(page.locator("#fiches-table-body")).to_contain_text("001-0004", timeout=20000)
            assert page.evaluate("CAIOfflineStore.pending(2, 1)") == []
            with app.app_context():
                assert FicheImplique.query.filter_by(nom="Réponse perdue").count() == 1
            expect(page.get_by_role("status")).to_have_text("Synchronisé au serveur")
            page.locator(".cai-connection-indicator").click()

            # Existing server fiche: both modals work offline in the same table.
            context.set_offline(True)
            existing = page.locator("#fiche-row-1")
            existing.get_by_role("button", name="Bagages", exact=True).click()
            page.locator("#numeros").fill("SRV-OFF-1")
            page.locator('#form-bagage button[type="submit"]').click()
            expect(existing).to_contain_text("SRV-OFF-1")
            existing.get_by_role("button", name="Sortie", exact=True).click()
            page.locator("#sortie-destination").fill("Hôpital")
            page.locator("#sortie-moyen").fill("Ambulance")
            page.locator('#form-sortie button[type="submit"]').click()
            expect(existing).to_have_class("cai-row-pending")
            page.reload()
            expect(existing).to_contain_text("SRV-OFF-1")
            expect(existing.locator('[data-col="statut"]')).to_contain_text("Sorti")
            assert len(page.evaluate("CAIOfflineStore.pending(2, 1)")) == 2

            # A lost action acknowledgement must not repeat a bagage or timeline.
            page.route("**/api/evenement/1/fiches/actions/sync", lose_response)
            context.set_offline(False)
            expect(page.locator(".cai-connection-indicator")).to_have_attribute("data-state", "offline", timeout=20000)
            page.unroute("**/api/evenement/1/fiches/actions/sync", lose_response)
            page.locator(".cai-connection-indicator").click()
            page.get_by_role("button", name="Synchroniser", exact=True).click()
            expect(existing).not_to_have_class("cai-row-pending", timeout=20000)
            expect(page.get_by_role("status")).to_have_text("Synchronisé au serveur")
            with app.app_context():
                fiche = db.session.get(FicheImplique, 1)
                assert fiche.statut == "sorti" and fiche.destination == "Hôpital"
                assert fiche.moyen_transport == "Ambulance"
                assert Bagage.query.filter_by(fiche_id=1, numero="SRV-OFF-1").count() == 1
                assert OfflineMutation.query.filter_by(fiche_id=1).count() == 2
                assert TimelineEntry.query.filter_by(fiche_id=1, kind="exit").count() == 1
            page.locator(".cai-connection-indicator").click()

            # A conflicting bagage remains orange and can be corrected in place.
            with app.app_context():
                other_id = FicheImplique.query.filter_by(numero="001-0001").one().id
                db.session.add(Bagage(numero="TAKEN", fiche_id=other_id, evenement_id=1))
                db.session.commit()
            context.set_offline(True)
            existing.get_by_role("button", name="Bagages", exact=True).click()
            page.locator("#numeros").fill("SRV-OFF-1, TAKEN")
            page.locator('#form-bagage button[type="submit"]').click()
            expect(existing).to_have_class("cai-row-pending")
            context.set_offline(False)
            page.wait_for_function("async () => (await CAIOfflineStore.pending(2, 1)).some(record => record.error?.includes('TAKEN'))")
            expect(page.locator(".cai-connection-indicator")).to_have_attribute("data-state", "pending")
            existing.get_by_role("button", name="Bagages", exact=True).click()
            page.locator("#numeros").fill("SRV-OFF-1, CORRECTED")
            page.locator('#form-bagage button[type="submit"]').click()
            expect(existing).not_to_have_class("cai-row-pending", timeout=20000)
            expect(existing).to_contain_text("CORRECTED")
            with app.app_context():
                assert {bagage.numero for bagage in Bagage.query.filter_by(fiche_id=1)} == {"SRV-OFF-1", "CORRECTED"}
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
