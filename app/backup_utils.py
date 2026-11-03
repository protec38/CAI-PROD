"""Operational backups. Accounts are preserved; replacement is atomic."""
from datetime import date, datetime, timezone
from io import BytesIO
import hashlib
import json

from sqlalchemy import Date, DateTime, Integer, func, select, text

from .extensions import db
from .models import (
    EventSettings, FicheMetadata, FicheChange, FicheTrash, PersonSearch,
    Animal, Bagage, Evenement, EventNews, FicheImplique, ShareLink,
    ShareLinkAccessLog, Ticket, TimelineEntry, Utilisateur, utilisateur_evenement, OfflineMutation, OfflineDeletion,
)

BACKUP_MODELS = {
    "evenements": Evenement, "fiches": FicheImplique, "bagages": Bagage,
    "animaux": Animal, "share_links": ShareLink,
    "share_link_access_logs": ShareLinkAccessLog, "tickets": Ticket,
    "news": EventNews, "timeline_entries": TimelineEntry,
    "offline_mutations": OfflineMutation,
    "offline_deletions": OfflineDeletion,
    "event_settings": EventSettings, "fiche_metadata": FicheMetadata,
    "fiche_changes": FicheChange, "fiche_trash": FicheTrash, "person_searches": PersonSearch,
}


def is_db_empty() -> bool:
    return not any(db.session.query(model.id).first() for model in BACKUP_MODELS.values())


def _row(obj):
    return {column.name: getattr(obj, column.name) for column in obj.__table__.columns}


def backup_to_bytesio(evenement_ids: list[int] | None = None) -> BytesIO:
    events = Evenement.query
    if evenement_ids is not None:
        events = events.filter(Evenement.id.in_(evenement_ids))
    events = events.all()
    event_ids = [event.id for event in events]
    fiches = FicheImplique.query.filter(FicheImplique.evenement_id.in_(event_ids)).all()
    fiche_ids = [fiche.id for fiche in fiches]
    links = ShareLink.query.filter(ShareLink.evenement_id.in_(event_ids)).all()
    objects = {
        "evenements": events, "fiches": fiches, "share_links": links,
        "animaux": Animal.query.filter(Animal.fiche_id.in_(fiche_ids)).all(),
        "share_link_access_logs": ShareLinkAccessLog.query.filter(
            ShareLinkAccessLog.share_link_id.in_([link.id for link in links])
        ).all(),
        "timeline_entries": TimelineEntry.query.filter(TimelineEntry.fiche_id.in_(fiche_ids)).all(),
    }
    objects['event_settings'] = EventSettings.query.filter(EventSettings.id.in_(event_ids)).all()
    objects['fiche_metadata'] = FicheMetadata.query.filter(FicheMetadata.id.in_(fiche_ids)).all()
    objects['fiche_changes'] = FicheChange.query.filter(FicheChange.fiche_id.in_(fiche_ids)).all()
    objects['person_searches'] = PersonSearch.query.filter(PersonSearch.evenement_id.in_(event_ids)).all()
    objects['fiche_trash'] = FicheTrash.query.filter(FicheTrash.evenement_id.in_(event_ids)).all()
    for key, model in (("bagages", Bagage), ("tickets", Ticket), ("news", EventNews),
                       ("offline_mutations", OfflineMutation), ("offline_deletions", OfflineDeletion)):
        objects[key] = model.query.filter(model.evenement_id.in_(event_ids)).all()
    payload = {key: [_row(obj) for obj in rows] for key, rows in objects.items()}
    payload["assoc_utilisateur_evenement"] = [dict(row) for row in db.session.execute(
        select(utilisateur_evenement).where(utilisateur_evenement.c.evenement_id.in_(event_ids))
    ).mappings()]
    payload["version"] = 2
    return BytesIO(json.dumps(payload, ensure_ascii=False, indent=2,
                             default=lambda value: value.isoformat()).encode("utf-8"))


def validate_backup(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("evenements"), list):
        raise ValueError("La sauvegarde doit contenir une liste 'evenements'.")
    for key in (*BACKUP_MODELS, "assoc_utilisateur_evenement"):
        rows = payload.get(key, [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f"Liste de données invalide : {key}")


def _delete_operational_data():
    # Children before parents, with foreign keys enabled on both database engines.
    for model in (PersonSearch, FicheTrash, FicheChange, FicheMetadata, EventSettings, OfflineDeletion, OfflineMutation, TimelineEntry, EventNews, Ticket, ShareLinkAccessLog, ShareLink, Animal, Bagage):
        db.session.execute(model.__table__.delete())
    db.session.execute(utilisateur_evenement.delete())
    db.session.execute(FicheImplique.__table__.update().values(referent_humain_id=None))
    db.session.execute(FicheImplique.__table__.delete())
    db.session.execute(Evenement.__table__.delete())


def bulk_restore(payload: dict):
    """Replace operational data in one transaction; any failure preserves it all."""
    validate_backup(payload)
    prepared = {}
    for key, model in BACKUP_MODELS.items():
        rows = []
        for source in payload.get(key, []):
            row = {column.name: source[column.name] for column in model.__table__.columns
                   if column.name in source}
            if model is ShareLink and source.get("token") and not row.get("token_hash"):
                row["token_hash"] = hashlib.sha256(source["token"].encode()).hexdigest()
            for column in model.__table__.columns:
                value = row.get(column.name)
                if value is not None and isinstance(column.type, (DateTime, Date)):
                    if isinstance(value, str):
                        value = (datetime.fromisoformat(value.replace("Z", "+00:00"))
                                 if isinstance(column.type, DateTime) else date.fromisoformat(value))
                    if isinstance(value, datetime) and isinstance(column.type, DateTime) and not column.type.timezone:
                        if value.tzinfo:
                            value = value.astimezone(timezone.utc).replace(tzinfo=None)
                    row[column.name] = value
            rows.append(row)
        prepared[key] = rows
    user_ids = set(db.session.scalars(select(Utilisateur.id)))
    for key, model in BACKUP_MODELS.items():
        for row in prepared[key]:
            for column in model.__table__.columns:
                if any(fk.target_fullname == "utilisateur.id" for fk in column.foreign_keys):
                    if row.get(column.name) is not None and row[column.name] not in user_ids:
                        if not column.nullable:
                            raise ValueError(f"Compte utilisateur absent pour {key}.{column.name}")
                        row[column.name] = None
    try:
        _delete_operational_data()
        references = [(row["id"], row.pop("referent_humain_id")) for row in prepared["fiches"]
                      if row.get("referent_humain_id") is not None]
        for key, model in BACKUP_MODELS.items():
            if prepared[key]:
                db.session.bulk_insert_mappings(model, prepared[key])
        for fiche_id, referent_id in references:
            db.session.execute(FicheImplique.__table__.update().where(
                FicheImplique.id == fiche_id).values(referent_humain_id=referent_id))
        assoc = [dict(row) for row in payload.get("assoc_utilisateur_evenement", [])
                 if row.get("utilisateur_id") in user_ids]
        if assoc:
            db.session.execute(utilisateur_evenement.insert(), assoc)
        if db.engine.dialect.name == "postgresql":
            for model in BACKUP_MODELS.values():
                if not isinstance(model.__table__.c.id.type, Integer) or model.__table__.c.id.foreign_keys:
                    continue
                next_id = (db.session.scalar(select(func.max(model.id))) or 0) + 1
                db.session.execute(text("SELECT setval(pg_get_serial_sequence(:table, 'id'), :next_id, false)"),
                                   {"table": model.__tablename__, "next_id": next_id})
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
