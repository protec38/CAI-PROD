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


def register(bp):
    @bp.route("/", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            nom_utilisateur = request.form["username"]
            mot_de_passe = request.form["password"]
            user = Utilisateur.query.filter_by(nom_utilisateur=nom_utilisateur).first()

            if user and user.check_password(mot_de_passe):
                session["user_id"] = user.id
                return redirect(url_for("main_bp.evenement_new"))
            else:
                flash("Nom d'utilisateur ou mot de passe invalide.", "danger")

        return render_template("login.html")

    # 🔓 Déconnexion

    @bp.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("main_bp.login"))

    # 📋 Création + sélection d’un événement

