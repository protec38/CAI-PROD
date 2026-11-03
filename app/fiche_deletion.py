"""Deletion identities and receipts survive removal of the original fiche."""
import hashlib
from uuid import uuid4

from .extensions import db
from .models import Animal, Evenement, OfflineDeletion


def identity_token(fiche):
    value = f"{fiche.evenement_id}:{fiche.id}:{fiche.numero}:{fiche.client_uuid}:{fiche.heure_arrivee}"
    from .models import FicheMetadata
    meta = db.session.get(FicheMetadata, fiche.id)
    if meta and meta.generation > 1:
        value += f':{meta.generation}'
    return hashlib.sha256(value.encode()).hexdigest()


def delete_fiche(fiche, user_id, operation_id=None, target_key=None, payload_hash="native"):
    db.session.execute(db.select(Evenement.id).where(Evenement.id == fiche.evenement_id).with_for_update())
    from .recycle import archive
    archive(fiche, user_id)
    receipt = OfflineDeletion(id=operation_id or str(uuid4()), evenement_id=fiche.evenement_id,
        utilisateur_id=user_id, fiche_id=fiche.id, fiche_uuid=fiche.client_uuid,
        numero=fiche.numero, target_key=target_key or f"id:{fiche.id}", payload_hash=payload_hash)
    db.session.add(receipt)
    Animal.query.filter_by(fiche_id=fiche.id).delete(synchronize_session=False)
    db.session.delete(fiche)
    return receipt
