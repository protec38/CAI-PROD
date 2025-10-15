# app/backup_utils.py
from sqlalchemy import select, text
from io import BytesIO
import json
from datetime import datetime, date, timezone

from . import db
from .models import (
    Utilisateur,
    Evenement,
    FicheImplique,
    Bagage,
    Animal,
    ShareLink,
    ShareLinkAccessLog,
    Ticket,
    utilisateur_evenement,
)

# -------------------------------------------------------------------
# JSON helpers
# -------------------------------------------------------------------

def _json_default(o):
    """Sérialisation sûre pour datetime/date en ISO 8601."""
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    return str(o)

# -------------------------------------------------------------------
# DB state
# -------------------------------------------------------------------

def is_db_empty() -> bool:
    """
    Retourne True si la base est vide (aucun utilisateur/évènement/fiche),
    et si la table d'association n'a pas de lignes.
    """
    if (Utilisateur.query.first() or Evenement.query.first() or FicheImplique.query.first()):
        return False
    # Vérifie aussi la table d'association
    row = db.session.execute(select(utilisateur_evenement.c.utilisateur_id)).first()
    if row:
        return False
    return True

# -------------------------------------------------------------------
# BACKUP (export)
# -------------------------------------------------------------------

def backup_to_bytesio(evenement_ids: list[int] | None = None) -> BytesIO:
    """Exporte un instantané JSON centré sur les évènements.

    ⚠️ Nouvel impératif : on exclut totalement les comptes utilisateurs pour ne
    conserver que les données opérationnelles (évènements, fiches, bagages,
    animaux, tickets, etc.). Cela évite d’écraser / de divulguer des comptes lors
    d’une restauration.

    - Si ``evenement_ids`` est fourni, on limite aux évènements sélectionnés et à
      leurs objets associés.
    - Sinon, export global de tous les évènements.
    """

    evenement_query = Evenement.query
    if evenement_ids:
        evenement_query = evenement_query.filter(Evenement.id.in_(evenement_ids))
    evenements = evenement_query.all()
    evenement_id_list = [e.id for e in evenements]

    fiche_query = FicheImplique.query
    bagage_query = Bagage.query
    animal_query = Animal.query
    share_link_query = ShareLink.query
    ticket_query = Ticket.query

    if evenement_id_list:
        fiche_query = fiche_query.filter(FicheImplique.evenement_id.in_(evenement_id_list))
        bagage_query = bagage_query.filter(Bagage.evenement_id.in_(evenement_id_list))
        share_link_query = share_link_query.filter(ShareLink.evenement_id.in_(evenement_id_list))
        ticket_query = ticket_query.filter(Ticket.evenement_id.in_(evenement_id_list))

    fiches = fiche_query.all()
    fiche_ids = [f.id for f in fiches]
    if fiche_ids:
        animal_query = animal_query.filter(Animal.fiche_id.in_(fiche_ids))

    bagages = bagage_query.all()
    animaux = animal_query.all()
    share_links = share_link_query.all()
    share_link_ids = [s.id for s in share_links]

    if share_link_ids:
        share_link_logs = ShareLinkAccessLog.query.filter(
            ShareLinkAccessLog.share_link_id.in_(share_link_ids)
        ).all()
    else:
        share_link_logs = []

    tickets = ticket_query.all()

    # On conserve les associations pour rebrancher les comptes existants après restauration
    if evenement_id_list:
        with db.engine.connect() as conn:
            res = conn.execute(
                utilisateur_evenement.select().where(
                    utilisateur_evenement.c.evenement_id.in_(evenement_id_list)
                )
            ).mappings()
            assoc_rows = [dict(r) for r in res]
    else:
        with db.engine.connect() as conn:
            res = conn.execute(utilisateur_evenement.select()).mappings()
            assoc_rows = [dict(r) for r in res]

    payload = {
        "evenements":   [e.__dict__ | {"_sa_instance_state": None} for e in evenements],
        "fiches":       [f.__dict__ | {"_sa_instance_state": None} for f in fiches],
        "bagages":      [b.__dict__ | {"_sa_instance_state": None} for b in bagages],
        "animaux":      [a.__dict__ | {"_sa_instance_state": None} for a in animaux],
        "share_links":  [s.__dict__ | {"_sa_instance_state": None} for s in share_links],
        "share_link_access_logs": [
            log.__dict__ | {"_sa_instance_state": None} for log in share_link_logs
        ],
        "tickets":      [t.__dict__ | {"_sa_instance_state": None} for t in tickets],
        "assoc_utilisateur_evenement": assoc_rows if evenement_ids else assoc_rows,
    }

    # Nettoyage des champs SQLAlchemy
    def clean(d):
        d.pop("_sa_instance_state", None)
        return d

    for k, v in list(payload.items()):
        if isinstance(v, list):
            payload[k] = [clean(x) for x in v]

    buf = BytesIO()
    buf.write(json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default).encode("utf-8"))
    buf.seek(0)
    return buf

# -------------------------------------------------------------------
# WIPE (danger)
# -------------------------------------------------------------------

def wipe_db(max_retries: int = 5, sleep_seconds: float = 0.5, *, preserve_users: bool = False):
    """
    Vide proprement toutes les tables applicatives.
    Conserve le schéma ; utile avant un bulk_restore.
    """
    last_err = None
    for attempt in range(1, max_retries + 1):
        try:
            db.session.rollback()
            db.session.close()
            db.session.remove()

            with db.engine.begin() as conn:
                # Désactive temporairement les contraintes (Postgres/SQLite)
                try:
                    conn.execute(text("SET session_replication_role = 'replica'"))
                    has_replica_toggle = True
                except Exception:
                    has_replica_toggle = False

                # Ordre important (FK)
                conn.execute(text(f"DELETE FROM {Ticket.__tablename__}"))
                conn.execute(text(f"DELETE FROM {ShareLinkAccessLog.__tablename__}"))
                conn.execute(text(f"DELETE FROM {ShareLink.__tablename__}"))
                conn.execute(text(f"DELETE FROM {Animal.__tablename__}"))
                conn.execute(text(f"DELETE FROM {Bagage.__tablename__}"))
                conn.execute(text(f"DELETE FROM {FicheImplique.__tablename__}"))
                conn.execute(text(f"DELETE FROM {Evenement.__tablename__}"))
                if not preserve_users:
                    conn.execute(text(f"DELETE FROM {Utilisateur.__tablename__}"))
                # table d’association (toujours vidée car dépend des évènements)
                conn.execute(utilisateur_evenement.delete())

                if has_replica_toggle:
                    conn.execute(text("SET session_replication_role = 'origin'"))

            return  # OK
        except Exception as e:
            last_err = e
            # petite attente pour SQLite "database is locked"
            try:
                import time
                time.sleep(sleep_seconds)
            except Exception:
                pass
    # si on arrive ici, on lève la dernière erreur vue
    raise last_err

# -------------------------------------------------------------------
# RESTORE (import)
# -------------------------------------------------------------------

# --- Helpers de parsing ---
def _parse_dt(val):
    """Accepte None, datetime, ou str ISO (avec ou sans 'Z') -> datetime (timezone-aware si possible)."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        s = val.strip()
        if s.endswith('Z'):  # supporte 'Z'
            s = s[:-1] + '+00:00'
        try:
            dt = datetime.fromisoformat(s)
            # si naïf, force UTC
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
        try:
            return date.fromisoformat(val.strip()[:10])
        except Exception:
            return None
    return None

def _coerce_fields(items, mapping):
    """
    Applique un mapping {champ: fonction} à chaque dict d'une liste.
    Exemple: {"created_at": _parse_dt}
    """
    if not items:
        return
    for it in items:
        for k, fn in mapping.items():
            if k in it:
                it[k] = fn(it.get(k))

def bulk_restore(payload: dict):
    """
    Restaure un export (JSON -> dict déjà chargé).
    - Vide la base (wipe_db)
    - Insère en masse (bulk_insert_mappings)
    - Gère la rétro‑compatibilité (ShareLink: token -> token_hash, suppression expires_at)
    """
    # Sécurité : tout doit être transactionnel
    wipe_db(preserve_users=True)

    # 1) Utilisateurs — ignorés volontairement (préservation comptes existants)
    # On se contente de garder les associations si les IDs correspondent.

    # 1) Evènements
    evenements = payload.get("evenements", []) or []
    _coerce_fields(evenements, {
        "date": _parse_date,
        "created_at": _parse_dt,
        "updated_at": _parse_dt,
    })
    db.session.bulk_insert_mappings(Evenement, evenements)
    db.session.flush()

    # 2) Fiches
    fiches = payload.get("fiches", []) or []
    _coerce_fields(fiches, {
        "heure_arrivee": _parse_dt,
        "heure_sortie": _parse_dt,
        "date_naissance": _parse_date,
        "created_at": _parse_dt,
        "updated_at": _parse_dt,
    })
    db.session.bulk_insert_mappings(FicheImplique, fiches)
    db.session.flush()

    # 3) Bagages / Animaux
    bagages = payload.get("bagages", []) or []
    _coerce_fields(bagages, {"created_at": _parse_dt})
    db.session.bulk_insert_mappings(Bagage, bagages)
    db.session.flush()

    animaux = payload.get("animaux", []) or []
    _coerce_fields(animaux, {"created_at": _parse_dt})
    db.session.bulk_insert_mappings(Animal, animaux)
    db.session.flush()

    # 4) ShareLinks (expiration supprimée, token hashé)
    share_links = payload.get("share_links", []) or []
    _coerce_fields(share_links, {
        "created_at": _parse_dt,
    })
    # Migration d’anciens exports :
    #  - drop 'expires_at'
    #  - convertir 'token' -> 'token_hash' (sha256)
    for sl in share_links:
        sl.pop("expires_at", None)
        if "token" in sl and sl.get("token") is not None and "token_hash" not in sl:
            import hashlib
            sl["token_hash"] = hashlib.sha256(sl["token"].encode()).hexdigest()
        if "token" not in sl:
            sl["token"] = None

    db.session.bulk_insert_mappings(ShareLink, share_links)
    db.session.flush()

    # 5) Journaux d'accès aux liens de partage
    share_link_access_logs = payload.get("share_link_access_logs", []) or []
    _coerce_fields(share_link_access_logs, {"accessed_at": _parse_dt})
    if share_link_access_logs:
        db.session.bulk_insert_mappings(ShareLinkAccessLog, share_link_access_logs)
        db.session.flush()

    # 6) Tickets
    tickets = payload.get("tickets", []) or []
    _coerce_fields(tickets, {"created_at": _parse_dt})
    db.session.bulk_insert_mappings(Ticket, tickets)
    db.session.flush()

    # 7) Table d’association utilisateurs ↔ évènements
    assoc = payload.get("assoc_utilisateur_evenement", []) or []
    if assoc:
        db.session.execute(utilisateur_evenement.insert(), assoc)

    db.session.commit()
