"""Offline shell (no personal data) and authenticated synchronization API."""
from uuid import UUID

from flask import Blueprint, request, send_from_directory, current_app, render_template
from flask_wtf.csrf import generate_csrf

from .extensions import db
from .fiche_service import save_fiche
from .models import Evenement
from .routes import get_current_user, user_can_access_event, json_nocache, COMPETENCES_CAI

offline_bp = Blueprint("offline", __name__)


@offline_bp.get("/service-worker.js")
def service_worker():
    response = send_from_directory(current_app.static_folder, "service-worker.js")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Service-Worker-Allowed"] = "/"
    return response


@offline_bp.get("/hors-ligne")
def shell():
    # Public, static shell: user-specific data lives in IndexedDB, never here.
    return send_from_directory(current_app.static_folder, "offline.html")


@offline_bp.get("/hors-ligne/fiche")
def fiche_shell():
    # The same form as online, without account data or a session/CSRF token.
    return render_template("fiche_new.html", offline_mode=True, fiche_type="humain",
                           numero_prevu="Attribué à la synchronisation",
                           competences_list=COMPETENCES_CAI, referent_lookup_url="")


@offline_bp.get("/api/offline/session")
def offline_session():
    user = get_current_user()
    if not user or not user.is_active:
        return json_nocache({"error": "Reconnectez-vous pour synchroniser les fiches."}, 401)
    return json_nocache({"user_id": user.id, "csrf_token": generate_csrf()})


@offline_bp.post("/api/evenement/<int:event_id>/fiches/sync")
def sync_fiche(event_id):
    user = get_current_user()
    if not user or not user.is_active:
        return json_nocache({"error": "Reconnectez-vous pour synchroniser les fiches."}, 401)
    event = db.session.get(Evenement, event_id)
    if not user_can_access_event(user, event):
        return json_nocache({"error": "Vous n’avez plus accès à cet évènement."}, 403)
    try:
        client_uuid = str(UUID(request.form.get("client_uuid", "")))
        # Bind the saved queue to its author, even if a different account logs in.
        if request.form.get("user_id") != str(user.id):
            return json_nocache({"error": "Reconnectez-vous avec le compte ayant créé cette fiche."}, 403)
        fiche = save_fiche(request.form, event, user, client_uuid)
    except ValueError as exc:
        db.session.rollback()
        return json_nocache({"error": str(exc)}, 422)
    return json_nocache({"id": fiche.id, "numero": fiche.numero,
                         "client_uuid": fiche.client_uuid, "synced": True})
