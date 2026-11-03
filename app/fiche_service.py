"""Shared validation and durable, idempotent fiche creation."""
from datetime import datetime, date, timezone
from uuid import UUID

import pytz
from sqlalchemy.exc import IntegrityError

from .extensions import db
from .models import Evenement, FicheImplique, TimelineEntry, OfflineDeletion
from .time_utils import utcnow

PARIS_TZ = pytz.timezone("Europe/Paris")


class FicheDeletedError(ValueError):
    def __init__(self, receipt):
        super().__init__("Cette fiche a déjà été supprimée du serveur.")
        self.receipt = receipt


def next_fiche_number(event_id):
    prefix = f"{event_id:03d}-"
    numbers = db.session.query(FicheImplique.numero).filter_by(evenement_id=event_id).all()
    suffixes = [int(number[len(prefix):]) for (number,) in numbers
                if number.startswith(prefix) and number[len(prefix):].isdigit()]
    return f"{prefix}{max(suffixes, default=0) + 1:04d}"


def save_fiche(form, evenement, user, client_uuid=None):
    # Every creation path takes this lock. The unique constraints also protect
    # SQLite and the case where two requests start with the same UUID.
    event_id, user_id = evenement.id, user.id
    for attempt in range(5):
        try:
            db.session.execute(db.select(Evenement.id).where(
                Evenement.id == event_id).with_for_update())
            if client_uuid:
                existing = FicheImplique.query.filter_by(client_uuid=client_uuid).first()
                if existing:
                    if existing.evenement_id != event_id or existing.utilisateur_id != user_id:
                        raise ValueError("Cet identifiant de saisie appartient à une autre fiche.")
                    return existing
                deleted = OfflineDeletion.query.filter_by(evenement_id=event_id, fiche_uuid=client_uuid).first()
                if deleted:
                    raise FicheDeletedError(deleted)
            fiche = build_fiche(form, evenement, user, next_fiche_number(event_id))
            fiche.client_uuid = client_uuid
            db.session.add(fiche)
            db.session.flush()
            from .fiche_updates import creation_metadata
            creation_metadata(fiche, form, user_id)
            db.session.add(TimelineEntry(
                fiche_id=fiche.id, user_id=user_id, kind="create",
                content="Création de la fiche" + (" (synchronisation)" if client_uuid else ""),
            ))
            db.session.commit()
            return fiche
        except IntegrityError:
            db.session.rollback()
            if attempt == 4:
                raise


def build_fiche(form, evenement, user, numero):
    fiche_type = (form.get("type_fiche") or "humain").strip().lower()
    if fiche_type not in {"humain", "animal"}:
        raise ValueError("Type de fiche invalide.")
    # PostgreSQL enforces these sizes; validate before persisting on all engines.
    for name, limit in {"nom": 100, "prenom": 100, "adresse": 200, "telephone": 20,
                        "personne_a_prevenir": 255, "tel_personne_a_prevenir": 50,
                        "numero_recherche": 20, "animal_nom": 100}.items():
        if len(form.get(name, "")) > limit:
            raise ValueError(f"Le champ {name} ne peut pas dépasser {limit} caractères.")
    # --- Heure d'arrivée envoyée par le front: "YYYY-MM-DD HH:MM:SS"
    heure_js_str = (form.get("heure_arrivee_js") or "").strip()
    try:
        parsed_local = datetime.strptime(heure_js_str, "%Y-%m-%d %H:%M:%S")
        local_dt = PARIS_TZ.localize(parsed_local)
        heure_arrivee = local_dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        # fallback si vide ou format inattendu
        heure_arrivee = utcnow()
    if form.get("heure_arrivee_utc"):
        try:
            parsed = datetime.fromisoformat(form["heure_arrivee_utc"].replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
            heure_arrivee = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            raise ValueError("Heure d’arrivée invalide.")

    if fiche_type == "animal":
        animal_nom = (form.get("animal_nom") or "").strip()
        if not animal_nom:
            raise ValueError("Le nom de l’animal est obligatoire.")

        animal_espece = (form.get("animal_espece") or "").strip()
        if len(animal_espece) > 120:
            raise ValueError("L’espèce de l’animal ne peut pas dépasser 120 caractères.")

        animal_particularites = (form.get("animal_particularites") or "").strip()
        if len(animal_particularites) > 200:
            raise ValueError("Le champ ‘Particularités’ ne peut pas dépasser 200 caractères.")

        animal_notes = (form.get("animal_notes") or "").strip()
        if len(animal_notes) > 200:
            raise ValueError("Le champ ‘Notes complémentaires’ ne peut pas dépasser 200 caractères.")

        referent_id_raw = (form.get("animal_referent_id") or "").strip()
        referent = None
        if referent_id_raw:
            try:
                referent_filter = FicheImplique.id == int(referent_id_raw)
            except ValueError:
                try:
                    referent_filter = FicheImplique.client_uuid == str(UUID(referent_id_raw))
                except ValueError:
                    raise ValueError("La personne sélectionnée n’est pas valide.")

            referent = (
                FicheImplique.query
                .filter(
                    referent_filter,
                    FicheImplique.evenement_id == evenement.id,
                    FicheImplique.est_animal.is_(False),
                )
                .first()
            )
            if not referent:
                raise ValueError("La personne sélectionnée n’existe plus.")

        fiche = FicheImplique(
            numero=numero,
            nom=animal_nom,
            prenom="",
            adresse=None,
            telephone=None,
            personne_a_prevenir=None,
            tel_personne_a_prevenir=None,
            recherche_personne=None,
            difficultes=animal_particularites,
            competences="",
            est_animal=True,
            humain=False,
            type_fiche="animal",
            animal_espece=animal_espece or None,
            animal_details=animal_notes or None,
            referent_humain=referent,
            statut="présent",
            heure_arrivee=heure_arrivee,
            date_naissance=None,
            utilisateur_id=user.id,
            evenement_id=evenement.id,
            autres_informations=animal_notes or None,
            code_sinus=None,
        )

        return fiche

    # --- Date de naissance (obligatoire) pour les humains
    date_naissance_str = (form.get("date_naissance") or "").strip()
    if not date_naissance_str:
        raise ValueError("La date de naissance est obligatoire.")
    try:
        date_naissance = datetime.strptime(date_naissance_str, "%Y-%m-%d").date()
    except ValueError:
        raise ValueError("Format de date de naissance invalide.")
    if date_naissance > date.today():
        raise ValueError("La date de naissance ne peut pas être dans le futur.")

    # --- Champs de base
    nom = (form.get("nom") or "").strip()
    prenom = (form.get("prenom") or "").strip()
    adresse = (form.get("adresse") or "").strip()
    telephone = (form.get("telephone") or "").strip()
    personne_a_prevenir = (form.get("personne_a_prevenir") or "").strip()
    tel_personne_a_prevenir = (form.get("tel_personne_a_prevenir") or "").strip()
    recherche_personne = (form.get("recherche_personne") or "").strip()
    difficulte = (form.get("difficulte") or "").strip()
    numero_recherche = (form.get("numero_recherche") or "").strip()

    code_sinus = (form.get("code_sinus") or "").strip()
    if len(code_sinus) > 30:
        raise ValueError("Le Code Sinus ne doit pas dépasser 30 caractères.")

    selected_comps = form.getlist("competences")
    if "Autre" in selected_comps:
        autre_txt = (form.get("competence_autre") or "").strip()
        if not autre_txt:
            raise ValueError("Merci de préciser l’autre compétence (20 caractères max).")
        if len(autre_txt) > 20:
            raise ValueError("La compétence 'Autre' ne doit pas dépasser 20 caractères.")
        selected_comps = [c for c in selected_comps if c != "Autre"]
        if autre_txt not in selected_comps:
            selected_comps.append(autre_txt)
    if len(selected_comps) > 4:
        raise ValueError("⛔ Vous ne pouvez sélectionner que 4 compétences maximum.")
    competences = ",".join(selected_comps)

    autres_infos = (form.get("autres_informations") or "").strip()
    if len(autres_infos) > 200:
        raise ValueError("Le champ « Autres informations » ne peut pas dépasser 200 caractères.")

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
        est_animal=False,
        humain=True,
        type_fiche="humain",
        numero_recherche=numero_recherche,
        statut="présent",
        heure_arrivee=heure_arrivee,
        date_naissance=date_naissance,
        utilisateur_id=user.id,
        evenement_id=evenement.id,
        autres_informations=autres_infos,
        code_sinus=code_sinus if hasattr(FicheImplique, "code_sinus") else None,
    )

    return fiche

