# app/backup_utils.py
from sqlalchemy import select, text
from io import BytesIO
import json
from datetime import datetime, date, timezone

from . import db
from .models import (
    Utilisateur, Evenement, FicheImplique, Bagage, Animal,
    ShareLink, Ticket, utilisateur_evenement
)

def _json_default(o):
    if isinstance(o, (datetime, date)):
        # ISO 8601 (ex: "2025-08-12T13:45:00" / "2025-08-12")
        return o.isoformat()
    return str(o)  # fallback très prudent (ne devrait pas servir)



def is_db_empty():
    # Vérifie rapidement si des données existent
    if (Utilisateur.query.first() or Evenement.query.first() or FicheImplique.query.first()
        or Bagage.query.first() or Animal.query.first() or ShareLink.query.first() or Ticket.query.first()):
        return False
    # table d'association
    with db.engine.connect() as conn:
        row = conn.execute(select(utilisateur_evenement.c.utilisateur_id)).first()
        if row:
            return False
    return True

def backup_to_bytesio():

    payload = {
        "utilisateurs": [u.__dict__ | {"_sa_instance_state": None} for u in Utilisateur.query.all()],
        "evenements":   [e.__dict__ | {"_sa_instance_state": None} for e in Evenement.query.all()],
        "fiches":       [f.__dict__ | {"_sa_instance_state": None} for f in FicheImplique.query.all()],
        "bagages":      [b.__dict__ | {"_sa_instance_state": None} for b in Bagage.query.all()],
        "animaux":      [a.__dict__ | {"_sa_instance_state": None} for a in Animal.query.all()],
        "share_links":  [s.__dict__ | {"_sa_instance_state": None} for s in ShareLink.query.all()],
        "tickets":      [t.__dict__ | {"_sa_instance_state": None} for t in Ticket.query.all()],
        "assoc_utilisateur_evenement": []
    }

    with db.engine.connect() as conn:
        res = conn.execute(utilisateur_evenement.select()).mappings()
        payload["assoc_utilisateur_evenement"] = [dict(r) for r in res]

    # Nettoyage des champs SQLAlchemy
    def clean(d):
        d.pop("_sa_instance_state", None)
        return d

    for k, v in list(payload.items()):
        if isinstance(v, list):
            payload[k] = [clean(x) for x in v]

    buf = BytesIO()
    # 👇 ICI la différence: on passe default=_json_default
    buf.write(json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default).encode("utf-8"))
    buf.seek(0)
    return buf

def wipe_db(max_retries: int = 5, sleep_seconds: float = 0.5):
    """
    Efface les données dans le bon ordre avec gestion de verrous SQLite.
    - ferme les sessions
    - applique busy_timeout
    - désactive/active les FK
    - réessaie si "database is locked"
    """
    last_err = None
    for attempt in range(1, max_retries + 1):
        try:
            # 1) Nettoyer la session courante
            db.session.rollback()
            db.session.close()
            db.session.remove()

            # 2) Utiliser une transaction explicite sur une connexion dédiée
            with db.engine.begin() as conn:
                # Donne un délai d’attente au cas où
                conn.exec_driver_sql("PRAGMA busy_timeout = 5000;")
                # Pour éviter les échecs de contraintes pendant le wipe
                conn.exec_driver_sql("PRAGMA foreign_keys = OFF;")

                # Vider la table d’association d’abord
                conn.execute(text("DELETE FROM utilisateur_evenement"))

                # Puis du plus enfant au plus parent (ordre important)
                conn.execute(text("DELETE FROM ticket"))
                conn.execute(text("DELETE FROM bagage"))
                conn.execute(text("DELETE FROM animal"))
                conn.execute(text("DELETE FROM fiche_implique"))
                conn.execute(text("DELETE FROM share_links"))
                conn.execute(text("DELETE FROM evenement"))
                conn.execute(text("DELETE FROM utilisateur"))

                # Réactive les FK
                conn.exec_driver_sql("PRAGMA foreign_keys = ON;")

            # 3) Jette les connexions du pool (au cas où)
            db.engine.dispose()

            return  # succès

        except Exception as e:
            last_err = e
            msg = str(e).lower()
            if "database is locked" in msg or "database is locked" in repr(e):
                # petite pause puis retry
                time.sleep(sleep_seconds)
                continue
            # autre erreur => on remonte tout de suite
            raise

    # Si tous les essais échouent
    raise last_err

# --- Helpers de parsing ---
def _parse_dt(val):
    """Accepte None, datetime, ou str ISO (avec ou sans 'Z') -> datetime (timezone-aware si possible)."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        s = val.strip()
        # Supporte 'Z' (UTC)
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        try:
            dt = datetime.fromisoformat(s)
            # Si naïf, force UTC (évite les surprises)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None
    return None

def _parse_date(val):
    """Accepte None, date, datetime, ou str ISO -> date."""
    if not val:
        return None
    if isinstance(val, date) and not isinstance(val, datetime):
        return val
    if isinstance(val, datetime):
        return val.date()
    if isinstance(val, str):
        s = val.strip()
        # Autorise soit 'YYYY-MM-DD', soit un ISO datetime
        try:
            if 'T' in s:
                return _parse_dt(s).date() if _parse_dt(s) else None
            return date.fromisoformat(s)
        except Exception:
            return None
    return None

def _coerce_fields(items, map_fields):
    """
    items: list[dict]
    map_fields: dict[str, callable]  -> ex: {"created_at": _parse_dt, "date_naissance": _parse_date}
    Modifie in-place.
    """
    for d in items:
        for field, fn in map_fields.items():
            if field in d:
                d[field] = fn(d.get(field))


# --- Restauration ---
def bulk_restore(payload: dict):
    """
    Insère dans le bon ordre, en retypant les champs date/datetime attendus par SQLAlchemy.
    Suppose que les IDs du dump sont cohérents (on réinsère avec les mêmes id).
    """
    # 1) Utilisateurs
    utilisateurs = payload.get("utilisateurs", []) or []
    db.session.bulk_insert_mappings(Utilisateur, utilisateurs)
    db.session.flush()

    # 2) Évènements (date_ouverture -> datetime)
    evenements = payload.get("evenements", []) or []
    _coerce_fields(evenements, {
        "date_ouverture": _parse_dt,
    })
    db.session.bulk_insert_mappings(Evenement, evenements)
    db.session.flush()

    # 3) Fiches (date_naissance -> date ; heure_arrivee/heure_sortie -> datetime)
    fiches = payload.get("fiches", []) or []
    _coerce_fields(fiches, {
        "date_naissance": _parse_date,
        "heure_arrivee": _parse_dt,
        "heure_sortie": _parse_dt,
    })
    db.session.bulk_insert_mappings(FicheImplique, fiches)
    db.session.flush()

    # 4) Animaux & Bagages
    animaux = payload.get("animaux", []) or []
    bagages = payload.get("bagages", []) or []
    db.session.bulk_insert_mappings(Animal, animaux)
    db.session.bulk_insert_mappings(Bagage, bagages)
    db.session.flush()

    # 5) ShareLinks (created_at/expires_at -> datetime)
    share_links = payload.get("share_links", []) or []
    _coerce_fields(share_links, {
        "created_at": _parse_dt,
        "expires_at": _parse_dt,
    })
    db.session.bulk_insert_mappings(ShareLink, share_links)
    db.session.flush()

    # 6) Tickets (created_at -> datetime)
    tickets = payload.get("tickets", []) or []
    _coerce_fields(tickets, {
        "created_at": _parse_dt,
    })
    db.session.bulk_insert_mappings(Ticket, tickets)
    db.session.flush()

    # 7) Table d’association utilisateurs↔évènements
    assoc = payload.get("assoc_utilisateur_evenement", []) or []
    if assoc:
        db.session.execute(utilisateur_evenement.insert(), assoc)

    db.session.commit()
