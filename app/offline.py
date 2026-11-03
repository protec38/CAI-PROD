"""Offline shell (no personal data) and authenticated synchronization API."""
from uuid import UUID
from types import SimpleNamespace
from datetime import datetime
import hashlib
import json

from flask import Blueprint, request, send_from_directory, current_app, render_template
from flask_wtf.csrf import generate_csrf

from .extensions import db
from .fiche_service import save_fiche, FicheDeletedError
from .models import Evenement, FicheImplique, OfflineMutation, OfflineDeletion
from .routes import get_current_user, user_can_access_event, json_nocache, COMPETENCES_CAI, COMPETENCE_COLORS
from .fiche_actions import apply_bagages, apply_sortie
from .fiche_deletion import delete_fiche, identity_token

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


@offline_bp.get('/hors-ligne/fiche/edit')
def fiche_edit_shell():
    return render_template('fiche_new.html', offline_mode=True, edit_mode=True, fiche_type='humain',
                           numero_prevu='', competences_list=COMPETENCES_CAI, referent_lookup_url='')


@offline_bp.get("/hors-ligne/fiche/detail")
def fiche_detail_shell():
    return render_template("fiche_detail.html", offline_mode=True)


@offline_bp.get('/hors-ligne/recherches')
def search_shell():
    return render_template('person_search.html', offline_mode=True)


@offline_bp.get("/api/offline/session")
def offline_session():
    user = get_current_user()
    if not user or not user.is_active:
        return json_nocache({"error": "Reconnectez-vous pour synchroniser les fiches."}, 401)
    from .features import preferences
    return json_nocache({"preferences": preferences(user.id), "user_id": user.id, "csrf_token": generate_csrf(), "permissions": {
        "canBroadcast": user.is_admin or user.role.lower() in {"admin", "responsable"},
        "canEditPec": user.is_admin or user.role.lower() not in {"technicien", "logisticien"},
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
    except FicheDeletedError as exc:
        receipt = exc.receipt
        return json_nocache({"id": receipt.fiche_id, "numero": receipt.numero,
                             "client_uuid": client_uuid, "synced": True, "deleted": True})
    except (ValueError, TypeError) as exc:
        db.session.rollback()
        return json_nocache({"error": str(exc)}, 422)
    from .person_search import wanted_matches
    return json_nocache({"id": fiche.id, "numero": fiche.numero,
        "client_uuid": fiche.client_uuid, "synced": True,
        "wanted_matches": wanted_matches(event_id, fiche.nom, fiche.prenom) if not fiche.est_animal else []})


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
    if kind == "delete" and not (user.is_admin or user.role.lower() in {"codep", "responsable"}):
        return json_nocache({"error": "Vous n’êtes pas autorisé à supprimer les fiches."}, 403)
    if kind not in {"bagages", "sortie", "delete", "edit"}:
        return json_nocache({"error": "Action invalide."}, 422)
    try:
        operation_id = str(UUID(request.form.get("operation_uuid", "")))
        db.session.execute(db.select(Evenement.id).where(Evenement.id == event_id).with_for_update())
        if kind == "delete":
            return sync_deletion(event_id, user, operation_id)
        query = FicheImplique.query.filter_by(evenement_id=event_id)
        if request.form.get("fiche_uuid"):
            fiche = query.filter_by(client_uuid=str(UUID(request.form["fiche_uuid"]))).first()
        else:
            fiche = query.filter_by(id=int(request.form.get("fiche_id", ""))).first()
        if not fiche:
            return json_nocache({"error": "Fiche absente du serveur. Sa création doit être synchronisée avant cette action."}, 409)
        from .fiche_updates import metadata
        if (request.form.get('identity_token') or metadata(fiche).generation > 1) and request.form.get('identity_token') != identity_token(fiche):
            return json_nocache({"error": "L’identité de cette fiche a changé. Ouvrez la fiche restaurée avant de modifier.", "stale_identity": True}, 409)
        content = {key: request.form.get(key, "") for key in
                   ("kind", "numeros", "base_numeros", "destination", "moyen_transport", "occurred_at")}
        if kind == 'edit':
            content.update(changes=request.form.get('changes', ''), base=request.form.get('base', ''))
        digest = hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        receipt = db.session.get(OfflineMutation, operation_id)
        if receipt:
            if (receipt.utilisateur_id != user.id or receipt.fiche_id != fiche.id or receipt.payload_hash != digest):
                return json_nocache({"error": "L’identifiant de cet envoi correspond à une autre action."}, 409)
        else:
            if kind == "bagages":
                apply_bagages(fiche, user.id, content["numeros"], content["base_numeros"])
            elif kind == 'edit':
                from .fiche_updates import apply_edit, FieldConflict
                try:
                    apply_edit(fiche, user, json.loads(content['changes']), json.loads(content['base']))
                except FieldConflict as exc:
                    db.session.rollback()
                    return json_nocache({'error': str(exc), 'conflicts': exc.conflicts, 'current': exc.current}, 409)
            else:
                apply_sortie(fiche, user.id, content["destination"].strip(), content["moyen_transport"].strip(), content["occurred_at"])
            db.session.add(OfflineMutation(id=operation_id, evenement_id=event_id,
                fiche_id=fiche.id, utilisateur_id=user.id, kind=kind, payload_hash=digest))
            db.session.commit()
    except (ValueError, TypeError) as exc:
        db.session.rollback()
        return json_nocache({"error": str(exc)}, 422)
    return json_nocache({"operation_uuid": operation_id, "id": fiche.id, "numero": fiche.numero, "synced": True})


def sync_deletion(event_id, user, operation_id):
    """The event lock is held. Receipts remain valid after the fiche is gone."""
    fiche_uuid = str(UUID(request.form["fiche_uuid"])) if request.form.get("fiche_uuid") else None
    fiche_id = int(request.form.get("fiche_id", "")) if not fiche_uuid else None
    target = f"uuid:{fiche_uuid}" if fiche_uuid else f"id:{fiche_id}"
    digest = hashlib.sha256(json.dumps({"target": target, "identity_token": request.form.get("identity_token", "")},
                                      sort_keys=True).encode()).hexdigest()
    receipt = db.session.get(OfflineDeletion, operation_id)
    if receipt:
        if (receipt.evenement_id != event_id or receipt.utilisateur_id != user.id or
                receipt.target_key != target or receipt.payload_hash != digest):
            return json_nocache({"error": "Cet identifiant correspond à une autre suppression."}, 409)
    else:
        if db.session.get(OfflineMutation, operation_id):
            return json_nocache({"error": "Cet identifiant correspond à une autre action."}, 409)
        query = FicheImplique.query.filter_by(evenement_id=event_id)
        fiche = query.filter_by(client_uuid=fiche_uuid).first() if fiche_uuid else query.filter_by(id=fiche_id).first()
        if fiche:
            from .fiche_updates import metadata
            if (not fiche_uuid or request.form.get('identity_token') or metadata(fiche).generation > 1) and request.form.get('identity_token') != identity_token(fiche):
                return json_nocache({"error": "L’identité de cette fiche a changé. Ouvrez la fiche restaurée avant de supprimer.", "stale_identity": True}, 409)
            receipt = delete_fiche(fiche, user.id, operation_id, target, digest)
        else:
            # Never remove a fiche from another event or one reusing an old id.
            anywhere = FicheImplique.query.filter_by(client_uuid=fiche_uuid).first() if fiche_uuid else db.session.get(FicheImplique, fiche_id)
            if anywhere:
                return json_nocache({"error": "Cette fiche appartient à un autre évènement."}, 403)
            receipt = OfflineDeletion(id=operation_id, evenement_id=event_id, utilisateur_id=user.id,
                fiche_id=fiche_id, fiche_uuid=fiche_uuid, numero=request.form.get("numero", "")[:100],
                target_key=target, payload_hash=digest)
            db.session.add(receipt)
        db.session.commit()
    return json_nocache({"operation_uuid": operation_id, "id": receipt.fiche_id or receipt.fiche_uuid,
                         "numero": receipt.numero or "Fiche supprimée", "synced": True, "deleted": True})
