from .extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import pytz  # ✅ Conversion UTC → Europe/Paris
from flask_login import UserMixin
import secrets

# 🌍 Utilitaire : UTC -> heure locale Paris
def convertir_heure_locale(dt_utc):
    if not dt_utc:
        return None
    paris = pytz.timezone("Europe/Paris")
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

    fiches = db.relationship('FicheImplique', backref='createur', lazy=True)

    is_admin = db.Column(db.Boolean, default=False)
    actif = db.Column(db.Boolean, default=True)

    evenements = db.relationship(
        'Evenement',
        secondary=utilisateur_evenement,
        backref=db.backref('utilisateurs', lazy='dynamic')
    )

    def set_password(self, password):
        self.mot_de_passe_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.mot_de_passe_hash, password)

    def __repr__(self):
        return f'<Utilisateur {self.nom_utilisateur}>'


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
    date_ouverture = db.Column(db.DateTime, default=datetime.utcnow)

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

    @property
    def date_ouverture_locale(self):
        return convertir_heure_locale(self.date_ouverture)

    def __repr__(self):
        return f'<Evenement {self.nom}>'


# ======================
# Fiche impliqué
# ======================
class FicheImplique(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.String(20), unique=True, nullable=False)

    nom = db.Column(db.String(100))
    prenom = db.Column(db.String(100))
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
    heure_sortie = db.Column(db.DateTime, nullable=True)
    numero_recherche = db.Column(db.String(20), nullable=True)

    statut = db.Column(db.String(20), nullable=False, default="présent")
    heure_arrivee = db.Column(db.DateTime, default=datetime.utcnow)
    autres_informations = db.Column(db.Text, nullable=True)

    # Timeline relation
    timeline_entries = db.relationship('TimelineEntry', backref='fiche', lazy='dynamic', cascade='all, delete-orphan')

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
# Animal
# ======================
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
    evenement_id = db.Column(db.Integer, db.ForeignKey("evenement.id"), nullable=False)
    created_by   = db.Column(db.Integer, db.ForeignKey("utilisateur.id"), nullable=True)

    # on garde le token en clair pour l'afficher (OPERATIONNEL et pratique)
    token       = db.Column(db.String(64), unique=True, index=True, nullable=False)
    token_hash  = db.Column(db.String(128), unique=True, index=True, nullable=False)

    created_at  = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    revoked     = db.Column(db.Boolean, default=False, nullable=False)

    # si tu veux: backrefs
    evenement   = db.relationship("Evenement", backref=db.backref("share_links", lazy="dynamic"))

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
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)  # ✅ UTC

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
            "created_at": (self.created_at.isoformat() if self.created_at else None),
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True, nullable=False)
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True, nullable=False)
    kind = db.Column(db.String(20), default="comment", nullable=False)  # comment/status/etc.
    content = db.Column(db.Text, nullable=False)



############################

class EventNews(db.Model):
    __tablename__ = "event_news"
    id = db.Column(db.Integer, primary_key=True)
    evenement_id = db.Column(db.Integer, db.ForeignKey("evenement.id"), nullable=False, index=True)
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

    evenement    = db.relationship("Evenement", backref=db.backref("news", lazy="dynamic"))