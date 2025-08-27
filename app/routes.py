from flask import Blueprint, render_template, request, redirect, url_for, session, flash, abort
from .models import Utilisateur, Evenement, FicheImplique, Bagage, ShareLink, Ticket, Animal, AuditLog, TimelineEntry, utilisateur_evenement
from .extensions import db, limiter
from werkzeug.security import check_password_hash
from functools import wraps
from .audit import log_action
from datetime import datetime, timedelta
from flask import jsonify
from flask_login import current_user
from flask import make_response
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
import io
from .backup_utils import is_db_empty, backup_to_bytesio, wipe_db, bulk_restore
from flask import send_file
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.units import cm, mm
import os
from io import BytesIO
import re
import json
main_bp = Blueprint("main_bp", __name__)

def json_nocache(payload: dict, status: int = 200):
    """Réponse JSON avec no-store pour empêcher tout cache navigateur/proxy."""
    resp = make_response(jsonify(payload), status)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

# 🔒 Décorateur pour vérifier l’authentification
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("main_bp.login"))
        return f(*args, **kwargs)
    return decorated_function

# 🔧 Fonction utilitaire
def get_current_user():
    return Utilisateur.query.get(session["user_id"])


# 🔐 Page de connexion
@main_bp.route("/", methods=["GET", "POST"])
@limiter.limit("5 per 3 minutes")
def login():
    if request.method == "POST":
        nom_utilisateur = request.form.get("username", "")
        mot_de_passe = request.form.get("password", "")
        user = Utilisateur.query.filter_by(nom_utilisateur=nom_utilisateur).first()
        if user and user.check_password(mot_de_passe):
            session["user_id"] = user.id
            log_action("login_success", "utilisateur", user.id)
            return redirect(url_for("main_bp.evenement_new"))
        else:
            flash("Nom d'utilisateur ou mot de passe invalide.", "danger")
    return render_template("login.html")
# 🔓 Déconnexion
@main_bp.route("/logout")
def logout():
    log_action("logout")
    session.clear()
    return redirect(url_for("main_bp.login"))

# 📋 Création + sélection d’un événement
@main_bp.route("/evenement/new", methods=["GET", "POST"])
@login_required
def evenement_new():
    user = get_current_user()

    # 🔒 Restriction stricte à admin ou codep
    if not user.is_admin and user.role != "codep":
        flash("⛔ Vous n’avez pas l’autorisation de créer un évènement.", "danger")
        evenements = user.evenements  # on peut quand même lui afficher ceux qu’il voit
        return render_template("evenement_new.html", user=user, evenements=evenements)

    if request.method == "POST":
        nom_evt = request.form["nom_evt"]
        type_evt = request.form["type_evt"]
        adresse = request.form["adresse"]
        statut = request.form["statut"]

        # Génération du numéro d'évènement
        last_evt = Evenement.query.order_by(Evenement.id.desc()).first()
        next_id = last_evt.id + 1 if last_evt else 1
        numero_evt = str(next_id).zfill(8)

        # Création de l'évènement
        nouvel_evt = Evenement(
            numero=numero_evt,
            nom=nom_evt,
            type_evt=type_evt,
            adresse=adresse,
            statut=statut,
            createur_id=user.id,
            date_ouverture=datetime.utcnow()
        )

        db.session.add(nouvel_evt)
        db.session.commit()

        # Association du créateur à l'évènement
        if nouvel_evt not in user.evenements:
            user.evenements.append(nouvel_evt)
            db.session.commit()

        flash("✅ Évènement créé avec succès.", "success")
        return redirect(url_for("main_bp.dashboard", evenement_id=nouvel_evt.id))

    # 🔁 Méthode GET
    evenements = Evenement.query.all() if user.is_admin or user.role == "codep" else user.evenements
    return render_template("evenement_new.html", user=user, evenements=evenements)




@main_bp.route("/evenement/<int:evenement_id>/dashboard")
@login_required
def dashboard(evenement_id):
    session["evenement_id"] = evenement_id
    user = get_current_user()

    evenement = Evenement.query.get(evenement_id)
    if not evenement or evenement not in user.evenements:
        flash("⛔ Vous n’avez pas accès à cet évènement.", "danger")
        return redirect(url_for("main_bp.evenement_new"))

    fiches = FicheImplique.query.filter_by(evenement_id=evenement.id).all()
    nb_present = FicheImplique.query.filter_by(evenement_id=evenement.id, statut="présent").count()
    nb_total = len(fiches)

    peut_modifier_statut = (
        user.is_admin or
        user.role == "codep" or
        evenement.createur_id == user.id or
        (user.role == "responsable" and user in evenement.utilisateurs)
    )

    return render_template(
        "dashboard.html",
        user=user,
        evenement=evenement,
        fiches=fiches,
        nb_present=nb_present,
        nb_total=nb_total,
        peut_modifier_statut=peut_modifier_statut,
        competence_colors=COMPETENCE_COLORS
    )








# 🔁 Sélection d’un événement existant
@main_bp.route("/evenement/select", methods=["POST"])
@login_required
def select_evenement():
    user = get_current_user()
    evt_id = request.form.get("evenement_id")

    if evt_id:
        session["evenement_id"] = int(evt_id)  # 🧠 on stocke dans la session
        return redirect(url_for("main_bp.dashboard", evenement_id=int(evt_id)))
    else:
        flash("Veuillez sélectionner un événement.", "warning")
        return redirect(url_for("main_bp.evenement_new"))





# ➕ Création fiche impliqué (NOUVELLE VERSION)
@main_bp.route("/fiche/new", methods=["GET", "POST"])
@login_required
def fiche_new():
    user = get_current_user()
    evenement_id = session.get("evenement_id")

    if not evenement_id:
        flash("⛔ Aucun évènement actif. Veuillez d'abord accéder à un évènement.", "danger")
        return redirect(url_for("main_bp.evenement_new"))

    evenement = Evenement.query.get(evenement_id)
    if not evenement or evenement not in user.evenements:
        flash("⛔ Vous n’avez pas accès à cet évènement.", "danger")
        return redirect(url_for("main_bp.evenement_new"))

    # ✅ Liste fixe des compétences (avec 'Autre')
    COMPETENCES_CAI = [
        "Médecin", "Infirmier", "Sapeur-pompier", "SST", "Psychologue",
        "Bénévole", "Artisan", "Interprète", "Logisticien", "Conducteur",
        "Agent sécurité", "Autre"
    ]

    if request.method == "POST":
        # --- Heure d'arrivée envoyée par le front: "YYYY-MM-DD HH:MM:SS"
        heure_js_str = (request.form.get("heure_arrivee_js") or "").strip()
        try:
            heure_arrivee = datetime.strptime(heure_js_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            # fallback si vide ou format inattendu
            heure_arrivee = datetime.utcnow()

        # --- Date de naissance
        date_naissance = None
        date_naissance_str = request.form.get("date_naissance")
        if date_naissance_str:
            try:
                date_naissance = datetime.strptime(date_naissance_str, "%Y-%m-%d").date()
            except ValueError:
                date_naissance = None

        # --- Champs de base
        nom = (request.form.get("nom") or "").strip()
        prenom = (request.form.get("prenom") or "").strip()
        adresse = (request.form.get("adresse") or "").strip()
        telephone = (request.form.get("telephone") or "").strip()
        personne_a_prevenir = (request.form.get("personne_a_prevenir") or "").strip()
        tel_personne_a_prevenir = (request.form.get("tel_personne_a_prevenir") or "").strip()
        recherche_personne = (request.form.get("recherche_personne") or "").strip()
        difficulte = (request.form.get("difficulte") or "").strip()
        humain = request.form.get("humain") == "True"
        numero_recherche = (request.form.get("numero_recherche") or "").strip()  # si tu l'utilises plus tard

        # --- Nouveau champ Code Sinus (30 max)
        code_sinus = (request.form.get("code_sinus") or "").strip()
        if len(code_sinus) > 30:
            flash("Le Code Sinus ne doit pas dépasser 30 caractères.", "danger")
            return redirect(request.url)

        # --- Compétences (max 4) + gestion 'Autre'
        selected_comps = request.form.getlist("competences")
        if "Autre" in selected_comps:
            autre_txt = (request.form.get("competence_autre") or "").strip()
            if not autre_txt:
                flash("Merci de préciser l’autre compétence (20 caractères max).", "danger")
                return redirect(request.url)
            if len(autre_txt) > 20:
                flash("La compétence 'Autre' ne doit pas dépasser 20 caractères.", "danger")
                return redirect(request.url)
            # retire 'Autre' et ajoute le texte saisi s'il n'est pas déjà présent
            selected_comps = [c for c in selected_comps if c != "Autre"]
            if autre_txt not in selected_comps:
                selected_comps.append(autre_txt)
        # sécurité côté serveur
        if len(selected_comps) > 4:
            flash("⛔ Vous ne pouvez sélectionner que 4 compétences maximum.", "danger")
            return redirect(request.url)
        competences = ",".join(selected_comps)

        # --- Autres informations (max 200)
        autres_infos = (request.form.get("autres_informations") or "").strip()
        if len(autres_infos) > 200:
            flash("Le champ « Autres informations » ne peut pas dépasser 200 caractères.", "danger")
            return redirect(request.url)

        # --- Numérotation automatique locale à l’évènement
        last_fiche_evt = (
            FicheImplique.query
            .filter_by(evenement_id=evenement.id)
            .order_by(FicheImplique.id.desc())
            .first()
        )
        next_local = 1
        if last_fiche_evt and last_fiche_evt.numero:
            try:
                last_parts = last_fiche_evt.numero.split("-")
                if len(last_parts) == 2:
                    next_local = int(last_parts[1]) + 1
            except ValueError:
                pass
        numero = f"{str(evenement.id).zfill(3)}-{str(next_local).zfill(4)}"

        # --- Création (nationalite & effets_perso SUPPRIMÉS)
        fiche = FicheImplique(
            numero=numero,
            nom=nom,
            prenom=prenom,
            adresse=adresse,
            telephone=telephone,
            personne_a_prevenir=personne_a_prevenir,
            tel_personne_a_prevenir=tel_personne_a_prevenir,
            recherche_personne=recherche_personne,
            difficultes=difficulte,
            competences=competences,
            est_animal=False,               # pas dans le form de création → False par défaut
            numero_recherche=numero_recherche,
            statut="présent",
            heure_arrivee=heure_arrivee,
            date_naissance=date_naissance,
            utilisateur_id=user.id,
            evenement_id=evenement.id,
            autres_informations=autres_infos,
            # nouveau champ en base (si ajouté au modèle)
            code_sinus=code_sinus if hasattr(FicheImplique, "code_sinus") else None,
        )

        db.session.add(fiche)
        db.session.commit()

        flash(f"✅ Fiche n°{numero} créée pour l’évènement en cours.", "success")
        return redirect(url_for("main_bp.dashboard", evenement_id=evenement.id))

    # --- GET : prévisualisation du prochain numéro
    last_fiche_evt = (
        FicheImplique.query
        .filter_by(evenement_id=evenement.id)
        .order_by(FicheImplique.id.desc())
        .first()
    )
    next_local = 1
    if last_fiche_evt and last_fiche_evt.numero:
        try:
            last_parts = last_fiche_evt.numero.split("-")
            if len(last_parts) == 2:
                next_local = int(last_parts[1]) + 1
        except ValueError:
            pass

    numero_prevu = f"{str(evenement.id).zfill(3)}-{str(next_local).zfill(4)}"

    return render_template(
        "fiche_new.html",
        user=user,
        numero_prevu=numero_prevu,
        competences_list=COMPETENCES_CAI
        # plus de 'countries' car nationalité retirée du formulaire
    )



    




########################################################

@main_bp.route("/admin/utilisateurs")
@login_required
def admin_utilisateurs():
    user = get_current_user()

    if not user.is_admin and user.role != "codep":
        flash("⛔ Accès refusé : vous n’avez pas les droits pour gérer les utilisateurs.", "danger")
        return redirect(url_for("main_bp.evenement_new"))

    utilisateurs = Utilisateur.query.all()
    return render_template("admin_utilisateurs.html", utilisateurs=utilisateurs, user=user)





################################################################


@main_bp.route("/admin/utilisateur/create", methods=["GET", "POST"])
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

    
@main_bp.route("/admin/utilisateur/edit/<int:id>", methods=["GET", "POST"])
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




@main_bp.route("/admin/utilisateur/delete/<int:id>")
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
@main_bp.route("/fiche/<int:id>")
@login_required
def fiche_detail(id):
    user = get_current_user()
    fiche = FicheImplique.query.get_or_404(id)

    if fiche.evenement not in user.evenements and not getattr(user, "is_admin", False) and getattr(user, "role", None) != "codep":
        flash("⛔ Vous n'avez pas accès à cette fiche.", "danger")
        return redirect(url_for("main_bp.evenement_new"))

    entries = fiche.timeline_entries.order_by(TimelineEntry.created_at.desc()).all()
    return render_template("fiche_detail.html", fiche=fiche, user=user, entries=entries)

# ✏️ Modification d’une fiche impliqué
from datetime import datetime

# ✏️ Modification d’une fiche impliqué (MÀJ)
@main_bp.route("/fiche/edit/<int:id>", methods=["GET", "POST"])
@login_required
def fiche_edit(id):
    user = get_current_user()
    fiche = FicheImplique.query.get_or_404(id)

    # Vérification d'accès à l'évènement
    if fiche.evenement not in user.evenements:
        flash("⛔ Vous n’avez pas accès à cet évènement.", "danger")
        return redirect(url_for("main_bp.evenement_new"))

    # Liste des compétences
    COMPETENCES_CAI = [
        "Médecin", "Infirmier", "Sapeur-pompier", "SST", "Psychologue",
        "Bénévole", "Artisan", "Interprète", "Logisticien", "Conducteur",
        "Agent sécurité", "Autre"
    ]

    if request.method == "POST":
        # Champs de base
        fiche.nom = request.form.get("nom")
        fiche.prenom = request.form.get("prenom")
        fiche.statut = request.form.get("statut")
        fiche.difficultes = request.form.get("difficulte")
        fiche.telephone = request.form.get("telephone")
        fiche.adresse = request.form.get("adresse")
        fiche.recherche_personne = request.form.get("recherche_personne")
        fiche.destination = request.form.get("destination")
        fiche.moyen_transport = request.form.get("moyen_transport")
        fiche.personne_a_prevenir = request.form.get("personne_a_prevenir")
        fiche.numero_pec = request.form.get("numero_pec")
        fiche.tel_personne_a_prevenir = request.form.get("tel_personne_a_prevenir")

        # 🚫 nationalité / effets personnels supprimés (on ne lit plus, on ne modifie plus)
        # fiche.nationalite = ...
        # fiche.effets_perso = ...

        # 🆕 Code Sinus (30 max)
        code_sinus = (request.form.get("code_sinus") or "").strip()
        if len(code_sinus) > 30:
            flash("Le Code Sinus ne doit pas dépasser 30 caractères.", "danger")
            return redirect(request.url)
        if hasattr(fiche, "code_sinus"):
            fiche.code_sinus = code_sinus

        # ✅ Compétences + 'Autre' (20 max) + limite 4
        selected_comps = request.form.getlist("competences")
        if "Autre" in selected_comps:
            autre_txt = (request.form.get("competence_autre") or "").strip()
            if not autre_txt:
                flash("Merci de préciser l’autre compétence (20 caractères max).", "danger")
                return redirect(request.url)
            if len(autre_txt) > 20:
                flash("La compétence 'Autre' ne doit pas dépasser 20 caractères.", "danger")
                return redirect(request.url)
            # remplace 'Autre' par le texte saisi (si non présent)
            selected_comps = [c for c in selected_comps if c != "Autre"]
            if autre_txt not in selected_comps:
                selected_comps.append(autre_txt)
        if len(selected_comps) > 4:
            flash("⛔ Vous ne pouvez sélectionner que 4 compétences maximum.", "danger")
            return redirect(request.url)
        fiche.competences = ",".join(selected_comps)

        # ✅ Autres informations (trim + limite 200)
        autres_infos = (request.form.get("autres_informations") or "").strip()
        if len(autres_infos) > 200:
            flash("Le champ « Autres informations » ne peut pas dépasser 200 caractères.", "danger")
            return redirect(request.url)
        fiche.autres_informations = autres_infos

        # ✅ Conversion de la date au bon format
        date_str = request.form.get("date_naissance")
        if date_str:
            try:
                fiche.date_naissance = datetime.strptime(date_str, "%Y-%m-%d").date()
            except ValueError:
                flash("⚠️ Format de date invalide.", "danger")
                return redirect(request.url)
        else:
            fiche.date_naissance = None

        db.session.commit()
        flash("✅ Fiche mise à jour avec succès.", "success")
        return redirect(url_for("main_bp.dashboard", evenement_id=fiche.evenement.id))

    return render_template(
        "fiche_edit.html",
        fiche=fiche,
        user=user,
        competences_list=COMPETENCES_CAI
    )





########################################################################

@main_bp.route("/fiche/delete/<int:id>", methods=["POST"])
@login_required
def fiche_delete(id):
    user = get_current_user()
    fiche = FicheImplique.query.get_or_404(id)

    # Doit avoir les droits de rôle
    roles_autorises = {"responsable", "codep"}
    if not (user.is_admin or (user.role or "").lower() in roles_autorises):
        flash("⛔ Suppression réservée à un administrateur, un codep ou un responsable.", "danger")
        return redirect(url_for("main_bp.dashboard", evenement_id=fiche.evenement.id))

    # Doit avoir accès à l'évènement
    if fiche.evenement not in user.evenements and not user.is_admin and (user.role or "").lower() != "codep":
        flash("⛔ Vous n’avez pas accès à cet évènement.", "danger")
        return redirect(url_for("main_bp.evenement_new"))

    db.session.delete(fiche)
    db.session.commit()
    flash("🗑️ Fiche supprimée avec succès.", "info")
    return redirect(url_for("main_bp.dashboard", evenement_id=fiche.evenement.id))




################################################################################



@main_bp.route("/fiche/<int:id>/sortie", methods=["POST"])
@login_required
def fiche_sortie(id):
    fiche = FicheImplique.query.get_or_404(id)
    user = get_current_user()

    if fiche.evenement not in user.evenements:
        flash("⛔ Vous n’avez pas accès à cette fiche.", "danger")
        return redirect(url_for("main_bp.dashboard", evenement_id=fiche.evenement_id))

    # Récupère les champs envoyés par la popup
    destination = (request.form.get("destination") or "").strip()
    moyen_transport = (request.form.get("moyen_transport") or "").strip()

    # Met à jour + sortie
    if destination:
        fiche.destination = destination
    if moyen_transport:
        fiche.moyen_transport = moyen_transport

    fiche.statut = "sorti"
    fiche.heure_sortie = datetime.utcnow()

    db.session.commit()

    flash(f"🚪 {fiche.nom} {fiche.prenom} est marqué comme 'sorti'.", "info")
    return redirect(url_for("main_bp.dashboard", evenement_id=fiche.evenement_id))




###############################################################



@main_bp.route("/evenement/<int:evenement_id>/update_statut", methods=["POST"])
@login_required
def update_evenement_statut(evenement_id):
    user = get_current_user()
    evenement = Evenement.query.get_or_404(evenement_id)

    if evenement not in user.evenements and not user.is_admin:
        flash("⛔ Accès refusé.", "danger")
        return redirect(url_for("main_bp.evenement_new"))

    new_statut = request.form.get("statut_evt")
    if new_statut:
        evenement.statut = new_statut
        db.session.commit()
        flash("✅ Statut de l’évènement mis à jour.", "success")

    return redirect(url_for("main_bp.dashboard", evenement_id=evenement.id))

#############################################

@main_bp.route("/evenement/<int:evenement_id>/fiches_json", methods=["GET"])
@login_required
def fiches_json(evenement_id):
    user = get_current_user()
    evt = Evenement.query.get_or_404(evenement_id)

    # 🔐 Accès lecture : rattaché à l’évènement OU admin/codep
    if (evt not in user.evenements) and (not getattr(user, "is_admin", False)) and (getattr(user, "role", "") != "codep"):
        return json_nocache({"error": "unauthorized"}, 403)

    # Tri stable par id (asc) pour éviter les sauts d’ordre au refresh
    fiches = (
        FicheImplique.query
        .filter_by(evenement_id=evenement_id)
        .order_by(FicheImplique.id.asc())
        .all()
    )

    def fmt(dt):
        try:
            return dt.strftime("%d/%m/%Y %H:%M") if dt else "-"
        except Exception:
            return "-"

    fiches_data = []
    for f in fiches:
        h_arr = getattr(f, "heure_arrivee_locale", None)
        h_out = getattr(f, "heure_sortie_locale", None)
        fiches_data.append({
            "id": f.id,
            "numero": f.numero or "",
            "nom": f.nom or "",
            "prenom": f.prenom or "",
            "statut": f.statut or "",
            "heure_arrivee": fmt(h_arr),
            "heure_sortie": fmt(h_out),
            "destination": f.destination or "",
            "difficultes": f.difficultes or "",
            "competences": f.competences or "",
        })

    # Métadonnées évènement pour mise à jour du bandeau
    date_ouv_loc = getattr(evt, "date_ouverture_locale", None)
    evt_payload = {
        "id": evt.id,
        "nom": evt.nom or "",
        "adresse": evt.adresse or "",
        "statut": evt.statut or "",
        "date_ouverture": fmt(date_ouv_loc),
    }

    # Compteurs live
    nb_present = sum(1 for f in fiches if (f.statut or "").lower() == "présent")
    nb_total   = len(fiches)

    return json_nocache({
        "fiches": fiches_data,
        "nb_present": nb_present,
        "nb_total": nb_total,
        "evenement": evt_payload,
    })



#####################################################################

COMPETENCE_COLORS = {
    "Médecin": "#e74c3c",
    "Infirmier": "#3498db",
    "Sapeur-pompier": "#e67e22",
    "SST": "#1abc9c",
    "Psychologue": "#9b59b6",
    "Bénévole": "#34495e",
    "Artisan": "#f39c12",
    "Interprète": "#2ecc71",
    "Logisticien": "#16a085",
    "Conducteur": "#d35400",
    "Agent sécurité": "#2c3e50",
    "Autre": "#7f8c8d"
}



#############################################"

def _styled_table(data):
    table = Table(data, colWidths=[60*mm, 100*mm])
    table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 11),
        ('BACKGROUND', (0,0), (-1,-1), colors.whitesmoke),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.whitesmoke, colors.lightgrey]),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.black),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('INNERGRID', (0,0), (-1,-1), 0.3, colors.grey),
        ('BOX', (0,0), (-1,-1), 0.5, colors.grey),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    return table


@main_bp.route("/fiche/<int:id>/pdf")
@login_required
def export_pdf_fiche(id):
    fiche = FicheImplique.query.get_or_404(id)

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=60, bottomMargin=40)

    story = []

    # === STYLES ===
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Titre', fontSize=22, alignment=1, textColor=colors.HexColor("#002f6c"), spaceAfter=20))
    styles.add(ParagraphStyle(name='SectionTitle', fontSize=14, textColor=colors.HexColor("#f58220"), spaceBefore=15, spaceAfter=8, underlineWidth=1))
    styles.add(ParagraphStyle(name='NormalBold', parent=styles['Normal'], fontName='Helvetica-Bold'))

    # === LOGO + TITRE ===
    logo_path = os.path.join("static", "img", "logo-protection-civile.jpg")
    if os.path.exists(logo_path):
        img = Image(logo_path, width=70, height=70)
        img.hAlign = 'CENTER'
        story.append(img)

    story.append(Paragraph("Fiche Impliqué", styles['Titre']))

    # === INFOS PERSO ===
    story.append(Paragraph("Informations personnelles", styles['SectionTitle']))
    data_perso = [
        ["Numéro", fiche.numero],
        ["Nom", fiche.nom],
        ["Prénom", fiche.prenom],
        ["Date de naissance", fiche.date_naissance.strftime('%d/%m/%Y') if fiche.date_naissance else "Non renseignée"],
        ["Nationalité", fiche.nationalite or "Non renseignée"],
        ["Adresse", fiche.adresse or "Non renseignée"],
        ["Téléphone", fiche.telephone or "Non renseigné"],
    ]
    story.append(_styled_table(data_perso))

    # === INFOS HORAIRES ===
    story.append(Paragraph("Heures", styles['SectionTitle']))
    data_horaires = [
        ["Heure d’arrivée", fiche.heure_arrivee_locale.strftime('%d/%m/%Y %H:%M') if fiche.heure_arrivee_locale else "Non renseignée"],
        ["Heure de sortie", fiche.heure_sortie_locale.strftime('%d/%m/%Y %H:%M') if fiche.heure_sortie_locale else "Non sortie"]
    ]
    story.append(_styled_table(data_horaires))

    # === INFOS SUP ===
    story.append(Paragraph("Informations supplémentaires", styles['SectionTitle']))
    data_supp = [
        ["Statut", fiche.statut],
        ["Difficultés", fiche.difficultes or "Non renseignée"],
        ["Compétences", fiche.competences or "Non renseignée"],
        ["Est un animal", "Oui" if fiche.est_animal else "Non"],
        ["Recherche une personne", fiche.recherche_personne or "Non"],
        ["N° recherche", fiche.numero_recherche or "Non renseigné"],
        ["Évènement", fiche.evenement.nom]
    ]
    story.append(_styled_table(data_supp))

    # === BAGAGES ===
    story.append(Paragraph("Bagages", styles['SectionTitle']))
    try:
        bag_list = sorted(
            [b.numero for b in (fiche.bagages or []) if b and b.numero],
            key=lambda x: x
        )
    except Exception:
        bag_list = []

    bagages_str = ", ".join(bag_list) if bag_list else "Aucun"
    story.append(_styled_table([["Bagages rattachés", bagages_str]]))

    doc.build(story)

    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="fiche_protection_civile.pdf", mimetype='application/pdf')



################################################

@main_bp.route("/admin/evenements")
@login_required
def admin_evenements():
    user = get_current_user()

    if not user.is_admin and user.role != "codep":
        flash("⛔ Accès interdit.", "danger")
        return redirect(url_for("main_bp.evenement_new"))

    evenements = Evenement.query.order_by(Evenement.id.desc()).all()
    return render_template("admin_evenements.html", evenements=evenements, user=user)


####################################

@main_bp.route('/evenement/<int:evenement_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_evenement(evenement_id):
    user = get_current_user()
    evenement = Evenement.query.get_or_404(evenement_id)

    if not user.is_admin and user.role != "codep" and evenement.createur_id != user.id:
        flash("⛔ Accès interdit.", "danger")
        return redirect(url_for("main_bp.admin_evenements"))

    if request.method == "POST":
        evenement.nom = request.form["nom"]
        evenement.adresse = request.form["adresse"]
        evenement.type_evt = request.form["type"]
        evenement.statut = request.form["statut"]
        db.session.commit()
        flash("✅ Évènement mis à jour.", "success")
        return redirect(url_for("main_bp.admin_evenements"))

    return render_template("edit_evenement.html", evenement=evenement, user=user)

#########################################


@main_bp.route("/evenements/<int:evenement_id>/supprimer", methods=["POST"])
@login_required
def delete_evenement(evenement_id):
    user = get_current_user()  # ✅ au lieu de current_user
    evt = Evenement.query.get_or_404(evenement_id)

    # 🔐 Vérifie si l'utilisateur est admin OU le créateur (codep)
    if not (user.is_admin or user.role == "codep" or evt.createur_id == user.id):
        abort(403)

    # 🧹 Supprime les fiches impliquées
    FicheImplique.query.filter_by(evenement_id=evt.id).delete()

    # 🧹 Supprime les tickets (si tu en as)
    from .models import Ticket
    Ticket.query.filter_by(evenement_id=evt.id).delete()

    # 🗑 Supprime l'évènement
    db.session.delete(evt)
    db.session.commit()

    flash("✅ L’évènement et ses fiches ont été supprimés.", "success")
    return redirect(url_for("main_bp.evenement_new"))



###################################################



@main_bp.route("/evenement/<int:evenement_id>/export/pdf")
@login_required
def export_evenement_fiches_pdf(evenement_id):
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    import io
    import pytz

    evenement = Evenement.query.get_or_404(evenement_id)
    fiches = FicheImplique.query.filter_by(evenement_id=evenement_id).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)
    elements = []

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CenterTitle', alignment=1, fontSize=18, spaceAfter=20))
    styles.add(ParagraphStyle(name='SubHeader', textColor=colors.orange, fontSize=14, spaceAfter=10))

    elements.append(Paragraph("Fiches Impliqués – Évènement", styles['CenterTitle']))
    elements.append(Paragraph("Informations sur l’évènement", styles['SubHeader']))

    # Date locale
    def convertir_heure_locale(dt_utc):
        if not dt_utc:
            return "Non renseignée"
        paris = pytz.timezone("Europe/Paris")
        return dt_utc.astimezone(paris).strftime("%d/%m/%Y %H:%M")

    infos_evt = [
        ["Nom", evenement.nom],
        ["Numéro", evenement.numero],
        ["Adresse", evenement.adresse],
        ["Statut", evenement.statut],
        ["Type", evenement.type_evt],
        ["Date d'ouverture", convertir_heure_locale(evenement.date_ouverture)]
    ]
    table_evt = Table(infos_evt, hAlign='LEFT', colWidths=[4*cm, 12*cm])
    table_evt.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
    ]))
    elements.append(table_evt)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Liste des fiches impliquées", styles['SubHeader']))

    header = [
        "Nom", "Prénom", "Naissance", "Nationalité", "Statut",
        "Téléphone", "Adresse", "Compétences", "Destination", "Effets perso"
    ]
    data = [header]

    for f in fiches:
        row = [
            f.nom or "-",
            f.prenom or "-",
            f.date_naissance.strftime("%d/%m/%Y") if f.date_naissance else "-",
            f.nationalite or "-",
            f.statut or "-",
            f.telephone or "-",
            f.adresse or "-",
            f.competences or "-",
            f.destination or "-",
            f.effets_perso or "-",
        ]
        data.append(row)

    table_fiches = Table(data, repeatRows=1, hAlign='LEFT')
    table_fiches.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey)
    ]))
    elements.append(table_fiches)

    doc.build(elements)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name=f"evenement_{evenement.numero}_fiches.pdf", mimetype='application/pdf')



###########################################



@main_bp.route("/fiche/<int:fiche_id>/bagages/ajouter", methods=["POST"])
@login_required
def fiche_bagages_ajouter(fiche_id):
    user = get_current_user()
    fiche = FicheImplique.query.get_or_404(fiche_id)

    if fiche.evenement not in user.evenements and not user.is_admin and user.role != "codep":
        flash("⛔ Vous n’avez pas accès à cet évènement.", "danger")
        return redirect(url_for("main_bp.evenement_new"))

    role = (user.role or "").lower()
    if not (user.is_admin or role in {"technicien", "responsable", "codep"}):
        flash("⛔ Vous n’êtes pas autorisé à modifier les bagages.", "danger")
        return redirect(url_for("main_bp.dashboard", evenement_id=fiche.evenement_id))

    raw = (request.form.get("numeros") or "").strip()
    # Découpe par virgules, espaces, points-virgules et retours à la ligne
    nouveaux = [t.strip() for t in re.split(r"[\s,;]+", raw) if t.strip()]
    # Dédoublonner en conservant l’ordre
    uniques, vus = [], set()
    for t in nouveaux:
        if t not in vus:
            uniques.append(t)
            vus.add(t)
    nouveaux_set = set(uniques)

    # État actuel
    existants = Bagage.query.filter_by(fiche_id=fiche.id).all()
    existants_map = {b.numero: b for b in existants}
    existants_set = set(existants_map.keys())

    # Diff
    a_supprimer = existants_set - nouveaux_set
    a_ajouter = nouveaux_set - existants_set

    deja_autre_fiche = []
    ajoutes = []
    supprimes = []

    # Unicité au niveau évènement : un numéro ne peut pas être utilisé par une autre fiche du même centre
    if a_ajouter:
        doublons_centre = {
            b.numero: b
            for b in Bagage.query.filter(
                Bagage.evenement_id == fiche.evenement_id,
                Bagage.numero.in_(list(a_ajouter))
            ).all()
        }
    else:
        doublons_centre = {}

    # Ajouter
    for num in a_ajouter:
        autre = doublons_centre.get(num)
        if autre and autre.fiche_id != fiche.id:
            deja_autre_fiche.append(num)
            continue
        db.session.add(Bagage(numero=num, fiche_id=fiche.id, evenement_id=fiche.evenement_id))
        ajoutes.append(num)

    # Supprimer
    for num in a_supprimer:
        db.session.delete(existants_map[num])
        supprimes.append(num)

    db.session.commit()

    # Feedback
    parts = []
    if ajoutes: parts.append(f"Ajouté: {', '.join(sorted(ajoutes))}")
    if supprimes: parts.append(f"Supprimé: {', '.join(sorted(supprimes))}")
    if deja_autre_fiche: parts.append(f"En conflit (déjà utilisés par une autre fiche): {', '.join(sorted(deja_autre_fiche))}")
    flash(" | ".join(parts) if parts else "Aucune modification.", "success" if (ajoutes or supprimes) else "info")

    return redirect(url_for("main_bp.dashboard", evenement_id=fiche.evenement_id))


##################################

@main_bp.route("/fiche/<int:fiche_id>/bagages_json", methods=["GET"])
@login_required
def fiche_bagages_json(fiche_id):
    user = get_current_user()
    fiche = FicheImplique.query.get_or_404(fiche_id)

    # 🔐 Accès lecture : rattaché à l’évènement OU admin/codep
    if (fiche.evenement not in user.evenements) and (not getattr(user, "is_admin", False)) and (getattr(user, "role", "") != "codep"):
        return json_nocache({"error": "unauthorized"}, 403)

    numeros = [
        b.numero for b in Bagage.query
        .filter_by(fiche_id=fiche.id)
        .order_by(Bagage.id.asc())
        .all()
        if b.numero
    ]
    return json_nocache({"fiche_id": fiche.id, "numero_fiche": fiche.numero, "numeros": numeros})


###########################################################

@main_bp.route("/evenement/<int:evenement_id>/export/csv")
@login_required
def export_evenement_fiches_csv(evenement_id):
    # -> Désormais export XLSX stylé
    import io
    from datetime import datetime
    import pytz
    from flask import send_file, redirect, url_for, flash
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    user = get_current_user()
    evenement = Evenement.query.get_or_404(evenement_id)

    # Permissions : admin, codep, responsable rattaché
    if not (
        user.is_admin
        or user.role == "codep"
        or (user.role == "responsable" and user in evenement.utilisateurs)
    ):
        flash("⛔ Accès refusé pour l’export.", "danger")
        return redirect(url_for("main_bp.dashboard", evenement_id=evenement.id))

    # Fiches
    fiches = (
        FicheImplique.query
        .filter_by(evenement_id=evenement.id)
        .order_by(FicheImplique.id.asc())
        .all()
    )

    # Comptes
    nb_total = len(fiches)
    nb_present = sum(1 for f in fiches if (f.statut or "").lower() == "présent")
    nb_sorti = sum(1 for f in fiches if (f.statut or "").lower() == "sorti")

    # Timezone Paris
    paris = pytz.timezone("Europe/Paris")
    def to_paris_dt(dt):
        if not dt: return None
        try:
            return dt.astimezone(paris).replace(tzinfo=None)
        except Exception:
            return None

    # ====== Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Fiches Impliqués"

    # Couleurs
    BLEU = "002F6C"
    ORANGE = "F58220"
    GRIS_LIGNE = "E9EDF3"
    ZEBRA = "F8FAFF"

    # Styles
    th_font = Font(bold=True, color="FFFFFF")
    th_fill = PatternFill("solid", fgColor=BLEU)
    title_font = Font(bold=True, color="FFFFFF", size=16)
    banner_fill = PatternFill("solid", fgColor=ORANGE)
    key_cell = PatternFill("solid", fgColor="FFF3E6")
    val_cell = PatternFill("solid", fgColor="FFFFFFFF")
    txt_center = Alignment(horizontal="center", vertical="center", wrap_text=True)
    txt_left = Alignment(horizontal="left", vertical="center", wrap_text=True)
    border_thin = Border(
        left=Side(style="thin", color=GRIS_LIGNE),
        right=Side(style="thin", color=GRIS_LIGNE),
        top=Side(style="thin", color=GRIS_LIGNE),
        bottom=Side(style="thin", color=GRIS_LIGNE),
    )

    # ====== En-tête événement
    # Titre bandeau
    headers = [
        "Numéro", "Code Sinus", "Nom", "Prénom", "Date de naissance", "Téléphone",
        "Adresse", "Statut", "Heure d’arrivée", "Heure de sortie", "Destination",
        "Moyen de transport", "Recherche personne", "N° recherche",
        "Personne à prévenir", "Tél. à prévenir", "Difficultés",
        "Compétences", "Bagages", "Autres informations",
    ]
    last_col = get_column_letter(len(headers))

    ws.merge_cells(f"A1:{last_col}1")
    c = ws["A1"]
    c.value = "📋 Export Fiches Impliqués — Protection Civile"
    c.font = title_font
    c.alignment = txt_left
    c.fill = banner_fill
    ws.row_dimensions[1].height = 26

    # Tableau d’infos évènement (2 colonnes: clé / valeur) sur 2 colonnes x 4 lignes (8 infos)
    evt_pairs = [
        ("Évènement", evenement.nom or ""),
        ("Numéro", evenement.numero or ""),
        ("Adresse", evenement.adresse or ""),
        ("Statut", evenement.statut or ""),
        ("Type", evenement.type_evt or ""),
        ("Ouverture", to_paris_dt(evenement.date_ouverture)),
        ("Présents", nb_present),
        ("Total / Sortis", f"{nb_total} / {nb_sorti}"),
    ]

    start_row = 3
    for idx, (k, v) in enumerate(evt_pairs):
        r = start_row + idx
        # clé
        ws[f"A{r}"].value = k
        ws[f"A{r}"].fill = key_cell
        ws[f"A{r}"].font = Font(bold=True, color=BLEU)
        ws[f"A{r}"].alignment = txt_left
        ws[f"A{r}"].border = border_thin
        # valeur (colonne B fusionnée jusqu’à D pour laisser de l'espace)
        ws.merge_cells(f"B{r}:D{r}")
        cell = ws[f"B{r}"]
        if isinstance(v, datetime):
            cell.value = v
            cell.number_format = "DD/MM/YYYY HH:MM"
        else:
            cell.value = v
        cell.fill = val_cell
        cell.alignment = txt_left
        cell.border = border_thin

    # Ligne vide
    table_start_row = start_row + len(evt_pairs) + 2

    # ====== En-têtes du tableau
    for col_idx, h in enumerate(headers, start=1):
        cell = ws.cell(row=table_start_row, column=col_idx, value=h)
        cell.font = th_font
        cell.fill = th_fill
        cell.alignment = txt_center
        cell.border = border_thin
    ws.freeze_panes = ws[f"A{table_start_row+1}"]  # fige titres
    ws.auto_filter.ref = f"A{table_start_row}:{last_col}{table_start_row}"

    # ====== Lignes
    for i, f in enumerate(fiches, start=1):
        r = table_start_row + i
        # Bagages
        try:
            bag_nums = [b.numero for b in (f.bagages or []) if b and b.numero]
            bagages_txt = ", ".join(sorted(bag_nums))
        except Exception:
            bagages_txt = ""

        # Dates/Heures (format Excel)
        d_naiss = f.date_naissance  # date ou None
        h_arr = to_paris_dt(getattr(f, "heure_arrivee", None))
        # si propriété *_locale dispo:
        if getattr(f, "heure_arrivee_locale", None):
            h_arr = f.heure_arrivee_locale.replace(tzinfo=None)
        h_sort = to_paris_dt(getattr(f, "heure_sortie", None))
        if getattr(f, "heure_sortie_locale", None):
            h_sort = f.heure_sortie_locale.replace(tzinfo=None)

        row_vals = [
            f.numero or "",
            getattr(f, "code_sinus", "") or "",
            f.nom or "",
            f.prenom or "",
            d_naiss,                # Excel date
            f.telephone or "",
            f.adresse or "",
            f.statut or "",
            h_arr,                  # Excel datetime
            h_sort,                 # Excel datetime
            f.destination or "",
            f.moyen_transport or "",
            f.recherche_personne or "",
            getattr(f, "numero_recherche", "") or "",
            f.personne_a_prevenir or "",
            f.tel_personne_a_prevenir or "",
            f.difficultes or "",
            f.competences or "",
            bagages_txt,
            f.autres_informations or "",
        ]

        for c_idx, val in enumerate(row_vals, start=1):
            cell = ws.cell(row=r, column=c_idx, value=val)
            cell.alignment = txt_left
            cell.border = border_thin
            # formats
            if c_idx == 5 and isinstance(val, datetime):
                cell.number_format = "DD/MM/YYYY"
            if c_idx in (9, 10) and isinstance(val, datetime):
                cell.number_format = "DD/MM/YYYY HH:MM"
            # zébrage
            if i % 2 == 1:
                cell.fill = PatternFill("solid", fgColor=ZEBRA)

    # ====== Largeurs de colonnes (preset + auto approx)
    preset_widths = {
        "A": 12,  # Numéro
        "B": 18,  # Code Sinus
        "C": 20,  # Nom
        "D": 18,  # Prénom
        "E": 14,  # Naissance
        "F": 16,  # Téléphone
        "G": 30,  # Adresse
        "H": 12,  # Statut
        "I": 18,  # Arrivée
        "J": 18,  # Sortie
        "K": 22,  # Destination
        "L": 18,  # Moyen
        "M": 24,  # Recherche personne
        "N": 18,  # N° recherche
        "O": 24,  # Personne à prévenir
        "P": 18,  # Tél à prévenir
        "Q": 28,  # Difficultés
        "R": 28,  # Compétences
        "S": 24,  # Bagages
        "T": 32,  # Autres informations
    }
    for col, w in preset_widths.items():
        ws.column_dimensions[col].width = w

    # ====== Export
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    filename = f"evenement_{evenement.numero or evenement.id}_fiches.xlsx"
    return send_file(
        bio,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )



##################################################################


def can_manage_sharing(user):
    return user.is_admin or user.role in {"codep", "responsable"}

# ===== Création d’un lien de partage (affiche le token UNE fois) =====
@main_bp.route("/evenement/<int:evenement_id>/share/create", methods=["POST"])
@login_required
def create_share_link(evenement_id):
    user = get_current_user()
    evt = Evenement.query.get_or_404(evenement_id)

    if not can_manage_sharing(user):
        abort(403)

    import secrets, hashlib
    token = secrets.token_urlsafe(24)  # clair
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    link = ShareLink(
        token=token,                # ✅ sauvegarde du clair
        token_hash=token_hash,      # ✅ sauvegarde du hash
        evenement_id=evt.id,
        created_by=user.id
    )
    db.session.add(link)
    db.session.commit()

    flash("🔗 Lien de partage créé.", "success")
    return redirect(url_for("main_bp.autorite_dashboard_manage", evenement_id=evt.id))



# ===== Gestion des liens : page opérateur =====
@main_bp.route("/evenement/<int:evenement_id>/autorite", methods=["GET"])
@login_required
def autorite_dashboard_manage(evenement_id):
    user = get_current_user()
    evt = Evenement.query.get_or_404(evenement_id)

    if not (user.is_admin or user.role in {"codep", "responsable"} or evt.createur_id == user.id):
        flash("⛔ Accès refusé.", "danger")
        return redirect(url_for("main_bp.dashboard", evenement_id=evenement_id))

    links = ShareLink.query.filter_by(evenement_id=evenement_id).order_by(ShareLink.created_at.desc()).all()

    # 🔐 si on vient de créer un lien, on reçoit ?token=... pour l'afficher une seule fois
    one_time_token = request.args.get("token")
    return render_template("autorite_dashboard.html",
                           user=user,
                           evenement=evt,
                           links=links,
                           manage=True,
                           one_time_token=one_time_token)


# ===== Révocation par ID (pas par token qu’on ne stocke pas) =====
@main_bp.route("/share/<int:link_id>/revoke", methods=["POST"])
@login_required
def revoke_share_link(link_id):
    user = get_current_user()
    link = ShareLink.query.get_or_404(link_id)

    if not (user.is_admin or user.role in {"codep", "responsable"} or link.evenement.createur_id == user.id):
        abort(403)

    link.revoked = True
    db.session.commit()
    flash("❌ Lien révoqué.", "info")
    return redirect(url_for("main_bp.autorite_dashboard_manage", evenement_id=link.evenement_id))


# ===== JSON public/privé (inchangé si tu as déjà la version qui marche) =====
@main_bp.route("/evenement/<int:evenement_id>/autorite_json", methods=["GET"])
def autorite_json(evenement_id):
    token = request.args.get("token")
    evt = Evenement.query.get_or_404(evenement_id)

    if token:
        import hashlib
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        link = ShareLink.query.filter_by(token_hash=token_hash, evenement_id=evenement_id).first()
        if not link or not link.is_active():
            return jsonify({"error": "forbidden"}), 403
    else:
        if "user_id" not in session:
            return jsonify({"error":"unauthorized"}), 401
        user = get_current_user()
        if (evt not in user.evenements) and not (user.is_admin or user.role in {"codep","responsable"}):
            return jsonify({"error":"forbidden"}), 403

    fiches = FicheImplique.query.filter_by(evenement_id=evenement_id).all()
    nb_present = sum(1 for f in fiches if (f.statut or "").lower() == "présent")
    nb_sorti   = sum(1 for f in fiches if (f.statut or "").lower() == "sorti")
    nb_total   = len(fiches)

    def fmt(dt): 
        try: return dt.strftime("%d/%m/%Y %H:%M") if dt else ""
        except: return ""

    return jsonify({
        "evenement": {
            "id": evt.id,
            "nom": evt.nom or "",
            "adresse": evt.adresse or "",
            "statut": evt.statut or "",
            "date_ouverture": fmt(getattr(evt, "date_ouverture_locale", None)),
        },
        "stats": {"nb_present": nb_present, "nb_sorti": nb_sorti, "nb_total": nb_total}
    })







#######################



def has_ticket_rights(user):
    return bool(
        user.is_admin or
        (user.role or "").lower() in {"codep", "responsable", "logisticien"}
    )


# ===== TICKETS =====

@main_bp.route("/evenement/<int:evenement_id>/tickets")
@login_required
def tickets_board(evenement_id):
    user = get_current_user()
    evenement = Evenement.query.get_or_404(evenement_id)
    users = evenement.utilisateurs  # ou ta logique de sélection
    
    can_manage = user.is_admin or user.role in ["codep", "responsable", "logisticien"]
    
    users_data = [
        {"id": u.id, "nom": u.nom, "role": u.role}
        for u in users
    ]
    
    return render_template(
        "tickets_board.html",
        evenement=evenement,
        users=users,
        users_data=users_data,  # ✅ on passe ici
        can_manage=can_manage,
        user=user
    )

################################################



############################

@main_bp.route("/evenement/<int:evenement_id>/tickets_json", methods=["GET"])
@login_required
def tickets_json(evenement_id):
    user = get_current_user()
    evt = Evenement.query.get_or_404(evenement_id)

    # Accès lecture : toute personne rattachée à l’évènement ou admin
    if (evt not in user.evenements) and (not getattr(user, "is_admin", False)):
        return json_nocache({"error": "forbidden"}, 403)

    tickets = (
        Ticket.query
        .filter_by(evenement_id=evt.id)
        .order_by(Ticket.created_at.desc())
        .all()
    )
    return json_nocache({"tickets": [t.to_dict() for t in tickets]})
############################


@main_bp.route("/tickets/create", methods=["POST"])
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


@main_bp.route("/tickets/<int:ticket_id>/update", methods=["POST"])
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


@main_bp.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
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
@main_bp.route("/admin/backup", methods=["GET"])
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
@main_bp.route("/admin/backup-restore", methods=["GET"])
@login_required
def admin_backup_restore_page():
    user = get_current_user()
    if not user.is_admin:
        abort(403)
    return render_template("admin_backup_restore.html", user=user)

# === Restauration ===
@main_bp.route("/admin/restore", methods=["POST"])
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


@main_bp.route('/healthz')
def _healthz():
    return {'status':'ok'}, 200


# =====================
# Page d'audit (admin uniquement)
# =====================
@main_bp.route("/admin/logs")
@login_required
def admin_logs():
    user = get_current_user()
    if not getattr(user, "is_admin", False):
        flash("⛔ Accès réservé à l'administrateur.", "danger")
        return redirect(url_for("main_bp.dashboard"))
    page = int(request.args.get("page", 1))
    per_page = 50
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return render_template("admin_logs.html", logs=logs, user=user)


# =====================
# Timeline: ajout d'un commentaire
# =====================
@main_bp.route("/fiche/<int:fiche_id>/timeline/add", methods=["POST"])
@login_required
def add_timeline_comment(fiche_id):
    user = get_current_user()
    fiche = FicheImplique.query.get_or_404(fiche_id)
    # TODO: autorisations fines si besoin (mêmes règles que l'édition de fiche)
    content = (request.form.get("comment") or "").strip()
    if not content:
        flash("Le commentaire est vide.", "warning")
        return redirect(url_for("main_bp.fiche_detail", fiche_id=fiche_id))
    entry = TimelineEntry(fiche_id=fiche.id, user_id=user.id, content=content, kind="comment")
    db.session.add(entry)
    db.session.commit()
    log_action("timeline_add", "FicheImplique", fiche.id, extra=content[:200])
    flash("Commentaire ajouté.", "success")
    return redirect(url_for("main_bp.fiche_detail", fiche_id=fiche_id))
