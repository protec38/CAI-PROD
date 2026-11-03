"""Transactional recycle bin; restored fiches receive a new lifecycle identity."""
from datetime import date, datetime
from uuid import uuid4

from .extensions import db
from .models import (
    Bagage,
    Evenement,
    FicheChange,
    FicheImplique,
    FicheMetadata,
    FicheTrash,
    OfflineMutation,
    TimelineEntry,
    Utilisateur,
)
from .time_utils import utcnow


def dump(row):
    return {c.name: (value.isoformat() if isinstance(value, (date, datetime)) else value)
            for c in row.__table__.columns for value in [getattr(row, c.name)]}


def load(model, data, omit=()):
    result = {k: v for k, v in data.items() if k not in omit}
    for column in model.__table__.columns:
        if result.get(column.name) and isinstance(column.type, db.DateTime):
            result[column.name] = datetime.fromisoformat(result[column.name])
        elif result.get(column.name) and isinstance(column.type, db.Date):
            result[column.name] = date.fromisoformat(result[column.name])
    return result


def archive(fiche, user_id):
    from .fiche_updates import metadata
    meta = metadata(fiche)
    from .fiche_deletion import identity_token
    payload = {'parent_identity': identity_token(fiche.referent_humain) if fiche.referent_humain else None,
               'fiche': dump(fiche), 'metadata': dump(meta),
               'bagages': [dump(row) for row in fiche.bagages],
               'timeline': [dump(row) for row in fiche.timeline_entries],
               'changes': [dump(row) for row in FicheChange.query.filter_by(fiche_id=fiche.id)],
               'receipts': [dump(row) for row in OfflineMutation.query.filter_by(fiche_id=fiche.id)],
               'children': [{'id': row.id, 'client_uuid': row.client_uuid, 'arrival': row.heure_arrivee.isoformat() if row.heure_arrivee else None, 'identity': identity_token(row)}
                            for row in fiche.animaux_rattaches]}
    payload['changes'].append({'fiche_id': fiche.id, 'user_id': user_id, 'kind': 'delete',
        'created_at': utcnow().isoformat(), 'changes': {'suppression': {'old': 'Fiche active', 'new': 'Corbeille'}}})
    db.session.add(FicheTrash(id=str(uuid4()), evenement_id=fiche.evenement_id, original_id=fiche.id,
                              numero=fiche.numero, deleted_by=user_id, payload=payload))


def restore(item, user_id):
    from .fiche_deletion import identity_token
    from .fiche_service import next_fiche_number
    from .fiche_updates import record_change
    db.session.execute(db.select(Evenement.id).where(Evenement.id == item.evenement_id).with_for_update())
    db.session.refresh(item)
    if item.restored_at:
        return db.session.get(FicheImplique, item.restored_id)
    payload = item.payload
    data = load(FicheImplique, payload['fiche'])
    for bag in payload['bagages']:
        if Bagage.query.filter_by(evenement_id=item.evenement_id, numero=bag['numero']).first():
            raise ValueError(f"Le bagage {bag['numero']} est déjà attribué. Libérez ce numéro avant de restaurer.")
    if data.get('client_uuid') and FicheImplique.query.filter_by(client_uuid=data['client_uuid']).first():
        raise ValueError('Une fiche utilise déjà cet identifiant.')
    if db.session.get(FicheImplique, data['id']):
        data.pop('id')
    if FicheImplique.query.filter_by(numero=data['numero']).first():
        data['numero'] = next_fiche_number(item.evenement_id)
    parent = db.session.get(FicheImplique, data.get('referent_humain_id')) if data.get('referent_humain_id') else None
    if (not parent or parent.evenement_id != item.evenement_id or parent.est_animal
            or (payload.get('parent_identity') and identity_token(parent) != payload['parent_identity'])):
        data['referent_humain_id'] = None
    if not db.session.get(Utilisateur, data['utilisateur_id']):
        data['utilisateur_id'] = user_id
    fiche = FicheImplique(**data)
    db.session.add(fiche)
    db.session.flush()
    meta = load(FicheMetadata, payload['metadata'], ('id',))
    meta['generation'] = meta.get('generation', 1) + 1
    db.session.add(FicheMetadata(id=fiche.id, **meta))
    for model, key in ((Bagage, 'bagages'), (TimelineEntry, 'timeline'), (FicheChange, 'changes'), (OfflineMutation, 'receipts')):
        for original in payload[key]:
            values = load(model, original, () if model is OfflineMutation else ('id',))
            values['fiche_id'] = fiche.id
            author_key = 'utilisateur_id' if model is OfflineMutation else 'user_id'
            if author_key in values and not db.session.get(Utilisateur, values[author_key]):
                values[author_key] = user_id
            if model is not OfflineMutation or not db.session.get(model, values['id']):
                db.session.add(model(**values))
    for child in payload.get('children', []):
        animal = db.session.get(FicheImplique, child['id'])
        if (animal and animal.evenement_id == item.evenement_id and not animal.referent_humain_id
                and (not child.get('identity') or identity_token(animal) == child['identity'])
                and animal.client_uuid == child['client_uuid'] and (animal.heure_arrivee.isoformat() if animal.heure_arrivee else None) == child['arrival']):
            animal.referent_humain_id = fiche.id
    db.session.flush()
    item.restored_at, item.restored_id = utcnow(), fiche.id
    record_change(fiche, user_id, 'restore', {}, {'restauration': fiche.numero})
    db.session.add(TimelineEntry(fiche_id=fiche.id, user_id=user_id, kind='restore', content='Fiche restaurée depuis la corbeille'))
    return fiche
