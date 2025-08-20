from .extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
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
    db.Column('utilisateur_id', db.Integer, db.ForeignKey('utilisateur.id', ondelete='CASCADE'), primary_key=True),
    db.Column('evenement_id', db.Integer, db.ForeignKey('evenement.id', ondelete='CASCADE'), primary_key=True)
)

# ======================
# Utilisateur
# ======================
class Utilisateur(db.Model, UserMixin):
    __tablename__ = "utilisateur"

    id = db.Column(db.Integer, primary_key=True)
    nom_utilisateur = db.Column(db.String(64), unique=True, nullable=False, index=True)
    mot_de_passe_hash = db.Column(db.Text, nullable=False)  # TEXT -> accepte scrypt/argon2 longs

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
        backref=db.backref('utilisateurs', lazy='dynamic'),
        passive_deletes=True
    )

    def set_password(self, password):
        self.mot_de_passe_hash = generate_password_hash(password)  # scrypt par défaut

    def check_password(self, password):
        return check_password_hash(self.mot_de_passe_hash, password)

    def __repr__(self):
        return f'<Utilisateur {self.nom_utilisateur}>'


# ======================
# Évènement
# ======================
class Evenement(db.Model):
    __tablename__ = "evenement"

    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.String(50), unique=True, nullable=False, index=True)
    nom = db.Column(db.String(100), nullable=False)
    adresse = db.Column(db.String(200), nullable=True)
    statut = db.Column(db.String(50), nullable=True, index=True)
    type_evt = db.Column(db.String(50), nullable=True, index=True)
    date_ouverture = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    createur_id = db.Column(db.Integer, db.ForeignKey('utilisateur.id'), nullable=True)
    createur = db.relationship('Utilisateur', backref='evenements_crees', foreign_keys=[createur_id])

    impliques = db.relationship(
        'FicheImplique',
        backref='evenement',
        lazy=True,
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    # ✅ relation cohérente avec Ticket.evenement (back_populates)
    tickets = db.relationship(
        'Ticket',
        back_populates='evenement',
        lazy=True,
        cascade="all, delete-orphan",
        passive_deletes=True
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
    __tablename__ = "fiche_implique"

    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.String(20), unique=True, nullable=False, index=True)

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

    est_animal = db.Column(db.Boolean, default=False, index=True)
    humain = db.Column(db.Boolean, default=True, index=True)
    heure_sortie = db.Column(db.DateTime, nullable=True)
    numero_recherche = db.Column(db.String(20), nullable=True)

    statut = db.Column(db.String(20), nullable=False, default="présent", index=True)
    heure_arrivee = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    autres_informations = db.Column(db.Text, nullable=True)

    evenement_id = db.Column(db.Integer, db.ForeignKey('evenement.id', ondelete='CASCADE'), nullable=False)
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
    __tablename__ = "animal"

    id = db.Column(db.Integer, primary_key=True)
    espece = db.Column(db.String(50), nullable=True)
    nom = db.Column(db.String(50), nullable=True)
    fiche_id = db.Column(db.Integer, db.ForeignKey('fiche_implique.id', ondelete='CASCADE'), nullable=True)

    def __repr__(self):
        return f"<Animal {self.nom}>"


# ======================
# Bagage
# ======================
class Bagage(db.Model):
    __tablename__ = "bagage"

    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.String(50), nullable=False)
    fiche_id = db.Column(db.Integer, db.ForeignKey('fiche_implique.id', ondelete='CASCADE'), nullable=False)
    evenement_id = db.Column(db.Integer, db.ForeignKey('evenement.id', ondelete='CASCADE'), nullable=False)

    fiche = db.relationship(
        'FicheImplique',
        backref=db.backref('bagages', lazy=True, cascade="all, delete-orphan", passive_deletes=True)
    )
    evenement = db.relationship(
        'Evenement',
        backref=db.backref('bagages', lazy=True, cascade="all, delete-orphan", passive_deletes=True)
    )

    def __repr__(self):
        return f"<Bagage {self.numero}>"


# ======================
# Lien de partage (dashboard autorités)
# ======================
class ShareLink(db.Model):
    __tablename__ = "share_links"

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, index=True, nullable=False)
    evenement_id = db.Column(db.Integer, db.ForeignKey("evenement.id", ondelete='CASCADE'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("utilisateur.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)   # None = pas d’expiration
    revoked = db.Column(db.Boolean, default=False, nullable=False)

    evenement = db.relationship("Evenement", backref=db.backref("share_links", lazy=True, cascade="all, delete-orphan", passive_deletes=True))
    auteur = db.relationship("Utilisateur")

    @staticmethod
    def new_token():
        return secrets.token_urlsafe(32)

    def is_active(self):
        if self.revoked:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True


# ======================
# Tickets (logistique/technique)
# ======================
class Ticket(db.Model):
    __tablename__ = "ticket"

    id = db.Column(db.Integer, primary_key=True)

    evenement_id   = db.Column(db.Integer, db.ForeignKey("evenement.id", ondelete='CASCADE'), nullable=False)
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
