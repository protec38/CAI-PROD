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
    @bp.route("/admin/utilisateurs")
    @login_required
    def admin_utilisateurs():
        user = get_current_user()

        if not user.is_admin and user.role != "codep":
            flash("⛔ Accès refusé : vous n’avez pas les droits pour gérer les utilisateurs.", "danger")
            return redirect(url_for("main_bp.evenement_new"))

        utilisateurs = Utilisateur.query.all()
        return render_template("admin_utilisateurs.html", utilisateurs=utilisateurs, user=user)





    ################################################################


    @bp.route("/admin/utilisateur/create", methods=["GET", "POST"])
    @login_required
    def utilisateur_create():
        user = get_current_user()
        if not (user.is_admin or user.role == "codep"):
            flash("Accès refusé", "danger")
            return redirect(url_for("main_bp.dashboard"))

        from app.models import Evenement
        all_evenements = Evenement.query.all()

        if request.method == "POST":
            nom = request.form["nom"]
            nom_utilisateur = request.form["nom_utilisateur"]
            role = request.form["role"]
            type_utilisateur = request.form["type_utilisateur"]
            password = request.form["password"]
            evenement_ids = request.form.getlist("evenements")

            existing = Utilisateur.query.filter_by(nom_utilisateur=nom_utilisateur).first()
            if existing:
                flash("Nom d'utilisateur déjà utilisé.", "danger")
                return redirect(url_for("main_bp.utilisateur_create"))

            new_user = Utilisateur(
                nom=nom,
                nom_utilisateur=nom_utilisateur,
                role=role,
                type_utilisateur=type_utilisateur,
            )
            new_user.set_password(password)

            for evt_id in evenement_ids:
                evt = Evenement.query.get(int(evt_id))
                if evt:
                    new_user.evenements.append(evt)

            db.session.add(new_user)
            db.session.commit()
            flash("Utilisateur créé avec succès", "success")
            return redirect(url_for("main_bp.admin_utilisateurs"))

        return render_template("utilisateur_form.html", utilisateur=None, all_evenements=all_evenements, mode="create")


    ###########################################



    @bp.route("/admin/utilisateur/edit/<int:id>", methods=["GET", "POST"])
    @login_required
    def utilisateur_edit(id):
        user = get_current_user()
        if not (user.is_admin or user.role == "codep"):
            flash("Accès refusé", "danger")
            return redirect(url_for("main_bp.dashboard"))

        utilisateur = Utilisateur.query.get_or_404(id)
        from app.models import Evenement
        all_evenements = Evenement.query.all()

        if request.method == "POST":
            utilisateur.nom = request.form["nom"]
            utilisateur.nom_utilisateur = request.form["nom_utilisateur"]
            utilisateur.role = request.form["role"]
            utilisateur.type_utilisateur = request.form["type_utilisateur"]
            password = request.form["password"]

            if password:
                utilisateur.set_password(password)

            utilisateur.evenements = []
            for evt_id in request.form.getlist("evenements"):
                evt = Evenement.query.get(int(evt_id))
                if evt:
                    utilisateur.evenements.append(evt)

            db.session.commit()
            flash("Utilisateur mis à jour.", "success")
            return redirect(url_for("main_bp.admin_utilisateurs"))

        return render_template("utilisateur_form.html", utilisateur=utilisateur, all_evenements=all_evenements, mode="edit")




    @bp.route("/admin/utilisateur/delete/<int:id>")
    @login_required
    def utilisateur_delete(id):
        user = get_current_user()
        if not (user.is_admin or user.role in ["responsable", "codep"]):
            flash("Accès refusé.", "danger")
            return redirect(url_for("main_bp.dashboard"))

        utilisateur = Utilisateur.query.get_or_404(id)
        db.session.delete(utilisateur)
        db.session.commit()
        flash("Utilisateur supprimé.", "info")
        return redirect(url_for("main_bp.admin_utilisateurs"))

    # 🔍 Détail d’une fiche impliqué

    @bp.route("/admin/evenements")
    @login_required
    def admin_evenements():
        user = get_current_user()

        if not user.is_admin and user.role != "codep":
            flash("⛔ Accès interdit.", "danger")
            return redirect(url_for("main_bp.evenement_new"))

        evenements = Evenement.query.order_by(Evenement.id.desc()).all()
        return render_template("admin_evenements.html", evenements=evenements, user=user)


    ####################################

    @bp.route("/admin/backup", methods=["GET"])
    @login_required
    def admin_backup():
        user = get_current_user()
        if not user.is_admin:
            abort(403)
        buf = backup_to_bytesio()
        return send_file(
            buf,
            as_attachment=True,
            download_name="backup.json",
            mimetype="application/json"
        )

    # === Page de gestion (boutons + formulaire restauration) ===

    @bp.route("/admin/backup-restore", methods=["GET"])
    @login_required
    def admin_backup_restore_page():
        user = get_current_user()
        if not user.is_admin:
            abort(403)
        return render_template("admin_backup_restore.html", user=user)

    # === Restauration ===

    @bp.route("/admin/restore", methods=["POST"])
    @login_required
    def admin_restore():

        user = get_current_user()
        if not (user and user.is_admin):
            abort(403)

        # --- Récupération du fichier + option "forcer" ---
        file = request.files.get("backup_file")
        force = request.form.get("force") == "on"

        if not file or file.filename.strip() == "":
            flash("Aucun fichier fourni.", "danger")
            return redirect(url_for("main_bp.admin_backup_restore_page"))

        # --- Lecture JSON ---
        try:
            raw = file.read()
            payload = json.loads(raw.decode("utf-8"))
        except Exception as e:
            flash(f"Fichier invalide (JSON) : {e}", "danger")
            return redirect(url_for("main_bp.admin_backup_restore_page"))

        # --- Réglages SQLite pour limiter les verrous pendant l'opération ---
        try:
            with db.engine.connect() as con:
                con.exec_driver_sql("PRAGMA busy_timeout=10000")
                con.exec_driver_sql("PRAGMA journal_mode=WAL")
        except Exception:
            # Non bloquant si l’on n’est pas sur SQLite
            pass

        # --- Sécurité : refuser si la base n'est pas vide (sauf option 'forcer') ---
        try:
            if not force and not is_db_empty():
                flash("Restauration refusée : la base n’est pas vide (sécurité). Coche « Forcer » pour écraser.", "warning")
                return redirect(url_for("main_bp.admin_backup_restore_page"))
        except Exception as e:
            flash(f"Vérification de base vide impossible : {e}", "danger")
            return redirect(url_for("main_bp.admin_backup_restore_page"))

        # --- Si 'forcer', on efface proprement avant de restaurer ---
        if force:
            try:
                # Ferme toute session en cours (évite 'database is locked')
                db.session.remove()
                wipe_db()
            except Exception as e:
                flash(f"Impossible d’effacer la base : {e}", "danger")
                return redirect(url_for("main_bp.admin_backup_restore_page"))

        # --- Injection en base ---
        try:
            bulk_restore(payload)
        except Exception as e:
            # On tente un rollback propre pour laisser l'app dans un état stable
            try:
                db.session.rollback()
            except Exception:
                pass
            flash(f"Erreur pendant la restauration : {e}", "danger")
            return redirect(url_for("main_bp.admin_backup_restore_page"))

        flash("✅ Restauration terminée avec succès.", "success")
        return redirect(url_for("main_bp.admin_backup_restore_page"))

