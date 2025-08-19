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
    @bp.route("/fiche/new", methods=["GET", "POST"])
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

    @bp.route("/fiche/<int:id>")
    @login_required
    def fiche_detail(id):
        user = get_current_user()
        fiche = FicheImplique.query.get_or_404(id)

        if fiche.evenement not in user.evenements and not user.is_admin and user.role != "codep":
            flash("⛔ Vous n'avez pas accès à cette fiche.", "danger")
            return redirect(url_for("main_bp.evenement_new"))

        return render_template("fiche_detail.html", fiche=fiche, user=user)


    # ✏️ Modification d’une fiche impliqué
    from datetime import datetime

    # ✏️ Modification d’une fiche impliqué (MÀJ)

    @bp.route("/fiche/edit/<int:id>", methods=["GET", "POST"])
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

    @bp.route("/fiche/delete/<int:id>", methods=["POST"])
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



    @bp.route("/fiche/<int:id>/sortie", methods=["POST"])
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



    @bp.route("/fiche/<int:id>/pdf")
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

    @bp.route("/fiche/<int:fiche_id>/bagages/ajouter", methods=["POST"])
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

    @bp.route("/fiche/<int:fiche_id>/bagages_json")
    @login_required
    def fiche_bagages_json(fiche_id):
        user = get_current_user()
        fiche = FicheImplique.query.get_or_404(fiche_id)

        if fiche.evenement not in user.evenements and not user.is_admin and user.role != "codep":
            return jsonify({"error": "unauthorized"}), 403

        numeros = [b.numero for b in Bagage.query.filter_by(fiche_id=fiche.id).order_by(Bagage.id.asc()).all()]
        return jsonify({"fiche_id": fiche.id, "numero_fiche": fiche.numero, "numeros": numeros})

    ###########################################################

