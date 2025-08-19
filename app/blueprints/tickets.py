from flask import render_template, request, redirect, url_for, session, flash, abort, jsonify, make_response
from datetime import datetime, timedelta
from flask_login import current_user
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
import io
from ..models import Utilisateur, Evenement, FicheImplique, Bagage, ShareLink, Ticket, Animal, utilisateur_evenement
from .. import db
from ..backup_utils import is_db_empty, backup_to_bytesio, wipe_db, bulk_restore
from app.blueprints.decorators import login_required, role_required, event_member_required


def register(bp):
    @bp.route("/tickets/create", methods=["POST"])
    @login_required
    def ticket_create():
        user = get_current_user()
        if not has_ticket_rights(user):
            flash("⛔ Vous n'êtes pas autorisé à créer des tickets.", "danger")
            return redirect(url_for("main_bp.evenement_new"))

        evenement_id = int(request.form.get("evenement_id"))
        evt = Evenement.query.get_or_404(evenement_id)
        if evt not in user.evenements:
            flash("⛔ Accès refusé.", "danger")
            return redirect(url_for("main_bp.evenement_new"))

        title = (request.form.get("title") or "").strip()
        if not title:
            flash("Le titre est obligatoire.", "danger")
            return redirect(url_for("main_bp.tickets_board", evenement_id=evenement_id))

        t = Ticket(
            evenement_id=evenement_id,
            created_by_id=user.id,
            title=title,
            description=(request.form.get("description") or "").strip(),
            status=(request.form.get("status") or "Ouvert"),
            priority=(request.form.get("priority") or "Normal"),
            category=(request.form.get("category") or "Logistique"),
            assigned_to_id=(int(request.form.get("assigned_to_id")) if request.form.get("assigned_to_id") else None),
        )
        db.session.add(t)
        db.session.commit()
        flash("🎫 Ticket créé.", "success")
        return redirect(url_for("main_bp.tickets_board", evenement_id=evenement_id))


    @bp.route("/tickets/<int:ticket_id>/update", methods=["POST"])
    @login_required
    def ticket_update(ticket_id):
        user = get_current_user()
        t = Ticket.query.get_or_404(ticket_id)
        evt = Evenement.query.get_or_404(t.evenement_id)
        if evt not in user.evenements:
            return jsonify({"error": "unauthorized"}), 403
        if not has_ticket_rights(user):
            return jsonify({"error": "forbidden"}), 403

        # champs autorisés à modifier
        t.status = request.form.get("status", t.status)
        t.priority = request.form.get("priority", t.priority)
        t.category = request.form.get("category", t.category)
        t.description = request.form.get("description", t.description)
        if "assigned_to_id" in request.form:
            val = request.form.get("assigned_to_id")
            t.assigned_to_id = int(val) if val else None

        db.session.commit()
        return jsonify({"ok": True})


    @bp.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
    @login_required
    def ticket_delete(ticket_id):
        user = get_current_user()
        t = Ticket.query.get_or_404(ticket_id)
        evt = Evenement.query.get_or_404(t.evenement_id)

        if evt not in user.evenements or not has_ticket_rights(user):
            flash("⛔ Suppression non autorisée.", "danger")
            return redirect(url_for("main_bp.evenement_new"))

        db.session.delete(t)
        db.session.commit()
        flash("🗑️ Ticket supprimé.", "info")
        return redirect(url_for("main_bp.tickets_board", evenement_id=evt.id))


    # === Sauvegarde (téléchargement direct) ===

