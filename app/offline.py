"""Offline shell (no personal data) and authenticated synchronization API."""
from uuid import UUID
from types import SimpleNamespace
from datetime import datetime
import hashlib
import json

from flask import Blueprint, request, send_from_directory, current_app, render_template
from flask_wtf.csrf import generate_csrf

from .extensions import db
from .fiche_service import save_fiche
from .models import Evenement, FicheImplique, OfflineMutation
from .routes import get_current_user, user_can_access_event, json_nocache, COMPETENCES_CAI, COMPETENCE_COLORS
from .fiche_actions import apply_bagages, apply_sortie

offline_bp = Blueprint("offline", __name__)


@offline_bp.get("/service-worker.js")
def service_worker():
    response = send_from_directory(current_app.static_folder, "service-worker.js")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Service-Worker-Allowed"] = "/"
    return response


@offline_bp.get("/hors-ligne")
def shell():
    # The classic dashboard, rendered without any account/event data.
    return render_template("dashboard.html", offline_mode=True,
        user=SimpleNamespace(is_admin=False, role=""),
        evenement=SimpleNamespace(id=0, nom="", adresse="", statut="", utilisateurs=[],
                                  date_ouverture_locale=datetime(2000, 1, 1)),
        peut_modifier_statut=False, nb_present=0, nb_total=0, nb_present_animaux=0, nb_total_animaux=0,
        competence_colors=COMPETENCE_COLORS)


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
    return json_nocache({"user_id": user.id, "csrf_token": generate_csrf(), "permissions": {
        "canDelete": user.is_admin or user.role.lower() in {"codep", "responsable"},
        "canBagages": user.is_admin or user.role.lower() in {"codep", "responsable", "technicien"},
    }})


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


@offline_bp.post("/api/evenement/<int:event_id>/fiches/actions/sync")
def sync_action(event_id):
    user = get_current_user()
    if not user or not user.is_active:
        return json_nocache({"error": "Reconnectez-vous pour synchroniser."}, 401)
    event = db.session.get(Evenement, event_id)
    if not user_can_access_event(user, event) or request.form.get("user_id") != str(user.id):
        return json_nocache({"error": "Vous n’avez pas accès à cet envoi."}, 403)
    kind = request.form.get("kind")
    if kind == "bagages" and not (user.is_admin or user.role.lower() in {"codep", "responsable", "technicien"}):
        return json_nocache({"error": "Vous n’êtes pas autorisé à modifier les bagages."}, 403)
    if kind not in {"bagages", "sortie"}:
        return json_nocache({"error": "Action invalide."}, 422)
    try:
        operation_id = str(UUID(request.form.get("operation_uuid", "")))
        db.session.execute(db.select(Evenement.id).where(Evenement.id == event_id).with_for_update())
        query = FicheImplique.query.filter_by(evenement_id=event_id)
        if request.form.get("fiche_uuid"):
            fiche = query.filter_by(client_uuid=str(UUID(request.form["fiche_uuid"]))).first()
        else:
            fiche = query.filter_by(id=int(request.form.get("fiche_id", ""))).first()
        if not fiche:
            return json_nocache({"error": "Fiche absente du serveur. Sa création doit être synchronisée avant cette action."}, 409)
        content = {key: request.form.get(key, "") for key in
                   ("kind", "numeros", "base_numeros", "destination", "moyen_transport", "occurred_at")}
        digest = hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        receipt = db.session.get(OfflineMutation, operation_id)
        if receipt:
            if (receipt.utilisateur_id != user.id or receipt.fiche_id != fiche.id or receipt.payload_hash != digest):
                return json_nocache({"error": "L’identifiant de cet envoi correspond à une autre action."}, 409)
        else:
            if kind == "bagages":
                apply_bagages(fiche, user.id, content["numeros"], content["base_numeros"])
            else:
                apply_sortie(fiche, user.id, content["destination"].strip(), content["moyen_transport"].strip(), content["occurred_at"])
            db.session.add(OfflineMutation(id=operation_id, evenement_id=event_id,
                fiche_id=fiche.id, utilisateur_id=user.id, kind=kind, payload_hash=digest))
            db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        return json_nocache({"error": str(exc)}, 422)
    return json_nocache({"operation_uuid": operation_id, "id": fiche.id, "numero": fiche.numero, "synced": True})
