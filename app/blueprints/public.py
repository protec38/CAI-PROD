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
    @bp.route("/share/<token>/revoke", methods=["POST"])
    @login_required
    def revoke_share_link(token):
        user = get_current_user()
        link = ShareLink.query.filter_by(token=token).first_or_404()
        if not can_manage_sharing(user):
            abort(403)
        link.revoked = True
        db.session.commit()
        flash("❌ Lien révoqué.", "info")
        return redirect(url_for("main_bp.autorite_dashboard_manage", evenement_id=link.evenement_id))

    # Endpoint public (sans login) — lecture seule

    @bp.route("/autorite/share/<token>")
    def autorite_share_public(token):
        link = ShareLink.query.filter_by(token=token).first()
        if not link or not link.is_active():
            return render_template("autorite_share_invalid.html"), 410  # expiré/révoqué

        evt = Evenement.query.get_or_404(link.evenement_id)
        return render_template("autorite_dashboard.html", user=None, evenement=evt, links=None, manage=False, public_token=token)

    # JSON pour la “Vue Autorité” (stats + infos clefs)

