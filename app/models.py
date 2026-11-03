from .time_utils import utcnow
from .extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import pytz  # ✅ Conversion UTC → Europe/Paris
from flask_login import UserMixin
import secrets
from uuid import uuid4

# 🌍 Utilitaire : UTC -> heure locale Paris
def convertir_heure_locale(dt_utc):
    if not dt_utc:
        return None
    paris = pytz.timezone("Europe/Paris")
    if dt_utc.tzinfo is None:
        dt_utc = pytz.utc.localize(dt_utc)
    return dt_utc.astimezone(paris)

# Association utilisateur <-> evenement (many-to-many)
utilisateur_evenement = db.Table(
    'utilisateur_evenement',
    db.Column('utilisateur_id', db.Integer, db.ForeignKey('utilisateur.id'), primary_key=True),
    db.Column('evenement_id', db.Integer, db.ForeignKey('evenement.id'), primary_key=True)
)

# ======================
# Utilisateur
# ======================
class Utilisateur(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nom_utilisateur = db.Column(db.String(64), unique=True, nullable=False)
    mot_de_passe_hash = db.Column(db.Text, nullable=False)

    nom = db.Column(db.String(100), nullable=True)
    prenom = db.Column(db.String(100), nullable=True)

    role = db.Column(db.String(50), nullable=False)
    type_utilisateur = db.Column(db.String(20), nullable=False)
    niveau = db.Column(db.String(20), nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    provisional_expires_at = db.Column(db.DateTime, nullable=True, index=True)

    fiches = db.relationship('FicheImplique', backref='createur', lazy=True)

    is_admin = db.Column(db.Boolean, default=False)
    actif = db.Column(db.Boolean, default=True)

    evenements = db.relationship(
        'Evenement',
        secondary=utilisateur_evenement,
        backref=db.backref('utilisateurs', lazy='dynamic')
    )

    broadcasts_envoyes = db.relationship(
        'BroadcastNotification',
        back_populates='created_by',
        lazy='dynamic',
    )

    def set_password(self, password):
        self.mot_de_passe_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.mot_de_passe_hash, password)

    @property
    def is_active(self):
        return bool(self.actif) and not (
            self.is_provisional and self.provisional_expires_at
            and self.provisional_expires_at <= utcnow()
        )

    def __repr__(self):
        return f'<Utilisateur {self.nom_utilisateur}>'

    @property
    def is_provisional(self) -> bool:
        return (self.type_utilisateur or "").lower() == "provisoire"

    @property
    def provisional_time_left(self):
        if not self.is_provisional or not self.provisional_expires_at:
            return None
        return self.provisional_expires_at - utcnow()


# ======================
# Évènement
# ======================
class Evenement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.String(50), unique=True, nullable=False)
    nom = db.Column(db.String(100), nullable=False)
    adresse = db.Column(db.String(200), nullable=True)
    statut = db.Column(db.String(50), nullable=True)
    type_evt = db.Column(db.String(50), nullable=True)
    date_ouverture = db.Column(db.DateTime, default=utcnow)

    archived = db.Column(db.Boolean, default=False, nullable=False, index=True)
    archived_at = db.Column(db.DateTime, nullable=True)

    createur_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=True)
    createur = db.relationship('Utilisateur', backref='evenements_crees', foreign_keys=[createur_id])

    impliques = db.relationship(
        'FicheImplique',
        backref='evenement',
        lazy=True,
        cascade="all, delete-orphan"
    )

    # ✅ utilise back_populates pour matcher Ticket.evenement (pas de backref ici)
    tickets = db.relationship(
        'Ticket',
        back_populates='evenement',
        lazy=True,
        cascade="all, delete-orphan"
    )

    share_links = db.relationship(
        'ShareLink',
        back_populates='evenement',
        lazy=True,
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    news = db.relationship(
        'EventNews',
        back_populates='evenement',
        lazy=True,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @property
    def date_ouverture_locale(self):
        return convertir_heure_locale(self.date_ouverture)

    def __repr__(self):
        return f'<Evenement {self.nom}>'

    @property
    def is_archived(self) -> bool:
        return bool(self.archived)


class BroadcastNotification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=True, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    emoji = db.Column(db.String(8), nullable=False, default="⚠️")
    level = db.Column(db.String(20), nullable=False, default="warning")

    created_by = db.relationship('Utilisateur', back_populates='broadcasts_envoyes')

    def __repr__(self):
        return f"<BroadcastNotification {self.id} active={self.is_active}>"

    def as_payload(self) -> dict[str, str | int | None]:
        return {
            "id": self.id,
            "message": self.message,
            "emoji": self.emoji or "⚠️",
            "level": self.level or "warning",
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ======================
# Fiche impliqué
# ======================
class FicheImplique(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.String(20), unique=True, nullable=False)
    # Stable across retries, independently of the final server number.
    client_uuid = db.Column(db.String(36), unique=True, nullable=True)

    nom = db.Column(db.String(100))
    prenom = db.Column(db.String(100))
    type_fiche = db.Column(db.String(20), nullable=False, default="humain")
    date_naissance = db.Column(db.Date, nullable=True)
    nationalite = db.Column(db.String(50), nullable=True)
    adresse = db.Column(db.String(200), nullable=True)
    telephone = db.Column(db.String(20), nullable=True)
    numero_pec = db.Column(db.String(30))
    personne_a_prevenir = db.Column(db.String(255))
    tel_personne_a_prevenir = db.Column(db.String(50))
    recherche_personne = db.Column(db.Text)
    code_sinus = db.Column(db.String(30), nullable=True)
    difficultes = db.Column(db.Text)
    competences = db.Column(db.Text)

    effets_perso = db.Column(db.String(255))
    destination = db.Column(db.String(255))
    moyen_transport = db.Column(db.String(255))

    est_animal = db.Column(db.Boolean, default=False)
    humain = db.Column(db.Boolean, default=True)
    animal_espece = db.Column(db.String(120), nullable=True)
    animal_details = db.Column(db.Text, nullable=True)
    referent_humain_id = db.Column(db.Integer, db.ForeignKey('fiche_implique.id'), nullable=True)
    referent_humain = db.relationship(
        'FicheImplique',
        remote_side=[id],
        backref=db.backref('animaux_rattaches', lazy='select'),
        foreign_keys=[referent_humain_id],
    )
    heure_sortie = db.Column(db.DateTime, nullable=True)
    numero_recherche = db.Column(db.String(20), nullable=True)

    statut = db.Column(db.String(20), nullable=False, default="présent")
    heure_arrivee = db.Column(db.DateTime, default=utcnow)
    autres_informations = db.Column(db.Text, nullable=True)

    # Timeline relation
    timeline_entries = db.relationship('TimelineEntry', backref='fiche', lazy='dynamic', cascade='all, delete-orphan')
    offline_mutations = db.relationship('OfflineMutation', cascade='all, delete-orphan')

    evenement_id = db.Column(db.Integer, db.ForeignKey('evenement.id'), nullable=False)
    utilisateur_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=False)

    # ✅ Heures locales
    @property
    def heure_arrivee_locale(self):
        return convertir_heure_locale(self.heure_arrivee)

    @property
    def heure_sortie_locale(self):
        return convertir_heure_locale(self.heure_sortie)

    def __repr__(self):
        return f"<FicheImplique {self.nom} {self.prenom}>"


# ======================
# Accusé de réception d’une action synchronisée
# ======================
class OfflineMutation(db.Model):
    """Receipt committed with an offline action, so delivery retries are safe."""
    id = db.Column(db.String(36), primary_key=True)
    evenement_id = db.Column(db.Integer, db.ForeignKey('evenement.id', ondelete='CASCADE'), nullable=False)
    fiche_id = db.Column(db.Integer, db.ForeignKey('fiche_implique.id', ondelete='CASCADE'), nullable=False)
    utilisateur_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id', ondelete='CASCADE'), nullable=False)
    kind = db.Column(db.String(20), nullable=False)
    payload_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class OfflineDeletion(db.Model):
    """Deletion receipt retained after the fiche and its child rows are gone."""
    id = db.Column(db.String(36), primary_key=True)
    evenement_id = db.Column(db.Integer, db.ForeignKey('evenement.id', ondelete='CASCADE'), nullable=False)
    utilisateur_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id', ondelete='SET NULL'), nullable=True)
    fiche_id = db.Column(db.Integer, nullable=True)
    fiche_uuid = db.Column(db.String(36), nullable=True, index=True)
    numero = db.Column(db.String(100), nullable=False)
    target_key = db.Column(db.String(50), nullable=False)
    payload_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


# Animal
class EventSettings(db.Model):
    id = db.Column(db.Integer, db.ForeignKey('evenement.id', ondelete='CASCADE'), primary_key=True)
    capacity = db.Column(db.Integer, nullable=True)
    warning_percent = db.Column(db.Integer, nullable=False, default=80)
    custom_fields = db.Column(db.JSON, nullable=False, default=list)
    choice_lists = db.Column(db.JSON, nullable=False, default=dict)
    evenement = db.relationship('Evenement', backref=db.backref('settings_record', uselist=False, cascade='all, delete-orphan'))


class FicheMetadata(db.Model):
    id = db.Column(db.Integer, db.ForeignKey('fiche_implique.id', ondelete='CASCADE'), primary_key=True)
    qr_token = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid4()))
    family_key = db.Column(db.String(80), nullable=False, default='')
    custom_values = db.Column(db.JSON, nullable=False, default=dict)
    revision = db.Column(db.Integer, nullable=False, default=1)
    generation = db.Column(db.Integer, nullable=False, default=1)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    fiche = db.relationship('FicheImplique', backref=db.backref('metadata_record', uselist=False, cascade='all, delete-orphan'))


class FicheChange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fiche_id = db.Column(db.Integer, db.ForeignKey('fiche_implique.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    kind = db.Column(db.String(20), nullable=False)
    changes = db.Column(db.JSON, nullable=False, default=dict)
    user = db.relationship('Utilisateur')
    fiche = db.relationship('FicheImplique', backref=db.backref('field_changes', cascade='all, delete-orphan'))


class FicheTrash(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    evenement_id = db.Column(db.Integer, db.ForeignKey('evenement.id', ondelete='CASCADE'), nullable=False, index=True)
    original_id = db.Column(db.Integer, nullable=False)
    numero = db.Column(db.String(100), nullable=False)
    deleted_by = db.Column(db.Integer, db.ForeignKey('utilisateur.id', ondelete='SET NULL'), nullable=True)
    deleted_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    restored_at = db.Column(db.DateTime, nullable=True)
    restored_id = db.Column(db.Integer, nullable=True)
    payload = db.Column(db.JSON, nullable=False)
    evenement = db.relationship('Evenement', backref=db.backref('trash_items', cascade='all, delete-orphan'))


class UserPreference(db.Model):
    id = db.Column(db.Integer, db.ForeignKey('utilisateur.id', ondelete='CASCADE'), primary_key=True)
    lock_minutes = db.Column(db.Integer, nullable=False, default=0)
    dashboard = db.Column(db.JSON, nullable=False, default=dict)
    user = db.relationship('Utilisateur', backref=db.backref('preference_record', uselist=False, cascade='all, delete-orphan'))


class Animal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    espece = db.Column(db.String(50), nullable=True)
    nom = db.Column(db.String(50), nullable=True)
    fiche_id = db.Column(db.Integer, db.ForeignKey('fiche_implique.id'), nullable=True)

    def __repr__(self):
        return f"<Animal {self.nom}>"


# ======================
# Bagage
# ======================
class Bagage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.String(50), nullable=False)
    fiche_id = db.Column(db.Integer, db.ForeignKey('fiche_implique.id'), nullable=False)
    evenement_id = db.Column(db.Integer, db.ForeignKey('evenement.id'), nullable=False)

    fiche = db.relationship('FicheImplique', backref=db.backref('bagages', lazy=True, cascade="all, delete-orphan"))
    evenement = db.relationship('Evenement', backref=db.backref('bagages', lazy=True, cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<Bagage {self.numero}>"


# ======================
# Lien de partage (dashboard autorités)
# ======================
from datetime import datetime, timezone
import pytz
import secrets, hashlib

class ShareLink(db.Model):
    __tablename__ = "share_link"

    id = db.Column(db.Integer, primary_key=True)
    evenement_id = db.Column(
        db.Integer,
        db.ForeignKey("evenement.id", ondelete="CASCADE"),
        nullable=False
    )
    created_by   = db.Column(db.Integer, db.ForeignKey("utilisateur.id"), nullable=True)

    # on garde le token en clair pour l'afficher (OPERATIONNEL et pratique)
    token       = db.Column(db.String(64), unique=True, index=True, nullable=False)
    token_hash  = db.Column(db.String(128), unique=True, index=True, nullable=False)
    label       = db.Column(db.String(120), nullable=True)

    created_at  = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    revoked     = db.Column(db.Boolean, default=False, nullable=False)

    # si tu veux: backrefs
    evenement   = db.relationship("Evenement", back_populates="share_links")
    access_logs = db.relationship(
        "ShareLinkAccessLog",
        backref="share_link",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def is_active(self) -> bool:
        # pas d'expiration → juste non révoqué
        return not self.revoked

    @staticmethod
    def new_token() -> tuple[str, str]:
        token = secrets.token_urlsafe(24)  # URL-safe court mais robuste
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return token, token_hash

    @property
    def created_at_locale(self):
        """Retourne la date de création convertie en Europe/Paris"""
        if not self.created_at:
            return None
        tz = pytz.timezone("Europe/Paris")
        return self.created_at.astimezone(tz)


class ShareLinkAccessLog(db.Model):
    __tablename__ = "share_link_access_log"

    id = db.Column(db.Integer, primary_key=True)
    share_link_id = db.Column(db.Integer, db.ForeignKey("share_link.id"), nullable=False, index=True)
    accessed_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    ip = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    referer = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f"<ShareLinkAccessLog link={self.share_link_id} at={self.accessed_at}>"

# ======================
# Tickets (logistique/technique)
# ======================
class Ticket(db.Model):
    __tablename__ = "ticket"
    id = db.Column(db.Integer, primary_key=True)

    evenement_id   = db.Column(db.Integer, db.ForeignKey("evenement.id"), nullable=False)
    created_by_id  = db.Column(db.Integer, db.ForeignKey("utilisateur.id"), nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("utilisateur.id"), nullable=True)

    title       = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    category    = db.Column(db.String(30))     # Logistique / Technique / Secours / Autre
    priority    = db.Column(db.String(10))     # Basse / Normal / Haute
    status      = db.Column(db.String(15))     # Ouvert / En cours / Terminé / Archivé
    created_at  = db.Column(db.DateTime, default=utcnow)  # ✅ UTC

    # Relations cohérentes avec Evenement.tickets
    evenement   = db.relationship("Evenement", back_populates="tickets")
    created_by  = db.relationship("Utilisateur", foreign_keys=[created_by_id])
    assigned_to = db.relationship("Utilisateur", foreign_keys=[assigned_to_id])

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description or "",
            "category": self.category or "",
            "priority": self.priority or "Normal",
            "status": self.status or "Ouvert",
            "created_at": (self.created_at.replace(tzinfo=timezone.utc).isoformat() if self.created_at else None),
            "created_by": (self.created_by.nom if self.created_by else None),
            "assigned_to": (self.assigned_to.nom if self.assigned_to else None),
            "assigned_to_id": (self.assigned_to_id or None),
        }


# ======================
# Audit log
# ======================

class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("utilisateur.id"), nullable=True)
    action = db.Column(db.String(200), nullable=False)
    entity_type = db.Column(db.String(50), nullable=True)
    entity_id = db.Column(db.Integer, nullable=True)
    ip = db.Column(db.String(64), nullable=True)
    extra = db.Column(db.Text, nullable=True)
    user = db.relationship("Utilisateur", backref="audit_logs", lazy="joined")


# ======================
# Timeline / Suivi des fiches
# ======================

class TimelineEntry(db.Model):
    __tablename__ = "timeline_entry"
    id = db.Column(db.Integer, primary_key=True)
    fiche_id = db.Column(db.Integer, db.ForeignKey("fiche_implique.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("utilisateur.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, index=True, nullable=False)
    kind = db.Column(db.String(20), default="comment", nullable=False)  # comment/status/etc.
    user = db.relationship("Utilisateur", backref="timeline_comments")
    content = db.Column(db.Text, nullable=False)



############################

class EventNews(db.Model):
    __tablename__ = "event_news"
    id = db.Column(db.Integer, primary_key=True)
    evenement_id = db.Column(
        db.Integer,
        db.ForeignKey("evenement.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by   = db.Column(db.Integer, db.ForeignKey("utilisateur.id"), nullable=True)
    created_at   = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # contenu
    message      = db.Column(db.Text, nullable=False)
    # priorité: 1=Urgent, 2=Important, 3=Info (plus petit = plus prioritaire)
    priority     = db.Column(db.Integer, default=3, nullable=False)
    # symbole (classe FontAwesome ex: "fa-triangle-exclamation", "fa-bullhorn", "fa-circle-info")
    icon         = db.Column(db.String(64), nullable=False, default="fa-circle-info")

    # affichage
    is_active    = db.Column(db.Boolean, nullable=False, default=True)

    evenement    = db.relationship("Evenement", back_populates="news")
