"""Versioned field updates shared by the online and offline interfaces."""
import json
import unicodedata
from datetime import date

from .extensions import db
from .models import (
    EventSettings,
    FicheChange,
    FicheImplique,
    FicheMetadata,
    TimelineEntry,
)
from .time_utils import utcnow

FIELDS = ['nom', 'prenom', 'type_fiche', 'date_naissance', 'nationalite', 'adresse', 'telephone', 'numero_pec', 'personne_a_prevenir', 'tel_personne_a_prevenir', 'recherche_personne', 'code_sinus', 'difficultes', 'competences', 'effets_perso', 'destination', 'moyen_transport', 'statut', 'animal_espece', 'animal_details', 'referent_humain_id', 'numero_recherche', 'autres_informations']


def metadata(fiche):
    row = fiche.metadata_record
    if row is None:
        # An insert with a conflict clause also handles two first reads of a legacy fiche.
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        insert = pg_insert if db.engine.dialect.name == 'postgresql' else sqlite_insert
        db.session.execute(insert(FicheMetadata).values(id=fiche.id,
            **({'qr_token': fiche.client_uuid} if fiche.client_uuid else {})).on_conflict_do_nothing(index_elements=['id']))
        row = db.session.get(FicheMetadata, fiche.id)
        fiche.metadata_record = row
    return row


def settings(event_id):
    row = db.session.get(EventSettings, event_id)
    return {'capacity': row.capacity if row else None, 'warning_percent': row.warning_percent if row else 80,
            'custom_fields': row.custom_fields if row else [], 'choice_lists': row.choice_lists if row else {}}


def state(fiche):
    result = {key: getattr(fiche, key) or '' for key in FIELDS}
    result['date_naissance'] = fiche.date_naissance.isoformat() if fiche.date_naissance else ''
    result['referent_humain_id'] = str(fiche.referent_humain_id or '')
    meta = metadata(fiche)
    result.update(family_key=meta.family_key, custom_values=dict(meta.custom_values))
    return result


def normalized(value):
    return ' '.join(''.join(c for c in unicodedata.normalize('NFKD', value or '').casefold()
                           if not unicodedata.combining(c)).split())


def present_family_count(fiches):
    return len({normalized(f.nom) for f in fiches
                if not f.est_animal and normalized(f.statut) == 'present' and normalized(f.nom)})


def duplicates(event_id, nom, prenom, birth, exclude=None):
    if not nom or not birth:
        return []
    try:
        birth = date.fromisoformat(birth)
    except ValueError:
        return []
    return [f for f in FicheImplique.query.filter_by(evenement_id=event_id, date_naissance=birth, est_animal=False)
            if f.id != exclude and normalized(f.nom) == normalized(nom) and normalized(f.prenom) == normalized(prenom)]


def record_change(fiche, user_id, kind, before, after):
    changes = {key: {'old': before.get(key, ''), 'new': value} for key, value in after.items()
               if before.get(key, '') != value}
    if changes:
        meta = metadata(fiche)
        meta.revision += 1
        meta.updated_at = utcnow()
        db.session.add(FicheChange(fiche_id=fiche.id, user_id=user_id, kind=kind, changes=changes))
    return changes


class FieldConflict(ValueError):
    def __init__(self, conflicts, current):
        super().__init__('Certains champs ont été modifiés sur le serveur. Choisissez les valeurs à conserver.')
        self.conflicts, self.current = conflicts, current


def validate_custom(event_id, values, fiche_type):
    if not isinstance(values, dict) or len(json.dumps(values, ensure_ascii=False)) > 20000:
        raise ValueError('Les champs personnalisés sont invalides ou trop longs.')
    result = dict(values)
    for field in settings(event_id)['custom_fields']:
        if field.get('scope', 'all') not in ('all', fiche_type):
            continue
        key, kind = field['key'], field['type']
        value = values.get(key, '')
        if field.get('required') and value in ('', None, False):
            raise ValueError(f"Le champ « {field['label']} » est obligatoire.")
        if value in ('', None):
            continue
        if kind == 'checkbox':
            if not isinstance(value, bool):
                raise ValueError(f"Valeur incorrecte pour {field['label']}.")
        elif not isinstance(value, str) or len(value) > 1000:
            raise ValueError(f"Valeur trop longue pour {field['label']}.")
        elif kind == 'number':
            try:
                import math
                if not math.isfinite(float(value)):
                    raise ValueError
            except ValueError:
                raise ValueError(f"Nombre incorrect pour {field['label']}.")
        elif kind == 'date':
            try:
                date.fromisoformat(value)
            except ValueError:
                raise ValueError(f"Date incorrecte pour {field['label']}.")
        elif kind == 'choice' and value not in field.get('choices', []):
            raise ValueError(f"Choix incorrect pour {field['label']}.")
    return result


def creation_metadata(fiche, form, user_id):
    meta = metadata(fiche)
    for key, limit in {'nationalite': 50, 'effets_perso': 255, 'numero_pec': 30}.items():
        value = (form.get(key) or '').strip()
        if len(value) > limit:
            raise ValueError(f'Le champ {key} est limité à {limit} caractères.')
        if key == 'numero_pec' and value:
            from .models import Utilisateur
            user = db.session.get(Utilisateur, user_id)
            if not user.is_admin and user.role.lower() in {'technicien', 'logisticien'}:
                raise ValueError('Vous ne pouvez pas modifier le numéro PEC.')
        setattr(fiche, key, value)
    meta.family_key = (form.get('family_key') or '').strip()
    if len(meta.family_key) > 80:
        raise ValueError('Le nom du groupe est limité à 80 caractères.')
    try:
        custom = json.loads(form.get('custom_values') or '{}')
    except (ValueError, TypeError):
        raise ValueError('Champs personnalisés invalides.')
    meta.custom_values = validate_custom(fiche.evenement_id, custom, fiche.type_fiche)
    record_change(fiche, user_id, 'create', {}, state(fiche))


def apply_edit(fiche, user, changes, base):
    if not isinstance(changes, dict) or not isinstance(base, dict):
        raise TypeError('Modification invalide.')
    current = state(fiche)
    allowed = set(FIELDS) | {'family_key', 'custom_values'}
    if set(changes) - allowed:
        raise ValueError('Un champ de cette modification est inconnu.')
    conflicts = []
    merged = dict(current)
    for key, value in changes.items():
        if key not in base:
            raise ValueError('La valeur initiale manque : actualisez la fiche.')
        if key == 'custom_values':
            if not isinstance(value, dict) or not isinstance(base[key], dict):
                raise ValueError('Champs personnalisés invalides.')
            custom = dict(current[key])
            for name in set(value) | set(base[key]):
                old, mine, server = base[key].get(name, ''), value.get(name, ''), current[key].get(name, '')
                if mine == old:
                    continue
                if server != old and server != mine:
                    conflicts.append({'field': f'custom_values.{name}', 'base': old, 'mine': mine, 'server': server})
                custom[name] = mine
            merged[key] = custom
        else:
            if not isinstance(value, str) or len(value) > 10000:
                raise ValueError('Valeur incorrecte ou trop longue.')
            if current[key] != base[key] and current[key] != value:
                conflicts.append({'field': key, 'base': base[key], 'mine': value, 'server': current[key]})
            merged[key] = value.strip()
    if conflicts:
        raise FieldConflict(conflicts, current)
    if 'statut' in changes and not (user.is_admin or user.role.lower() == 'codep' or
            (user.role.lower() == 'responsable' and user in fiche.evenement.utilisateurs)):
        raise ValueError('Vous ne pouvez pas modifier le statut depuis ce formulaire.')
    if 'numero_pec' in changes and user.role.lower() in {'technicien', 'logisticien'} and not user.is_admin:
        raise ValueError('Vous ne pouvez pas modifier le numéro PEC.')
    if changes.get('statut') == 'supprimé' and fiche.statut != 'supprimé':
        raise ValueError('Utilisez le bouton Supprimer pour placer cette fiche dans la corbeille.')
    if len([v for v in merged['competences'].split(',') if v]) > 4:
        raise ValueError('Vous pouvez sélectionner 4 compétences maximum.')
    for key in FIELDS:
        column = FicheImplique.__table__.columns[key]
        limit = getattr(column.type, 'length', None)
        if limit and len(str(merged[key])) > limit:
            raise ValueError(f'Le champ {key} est limité à {limit} caractères.')
    if merged['type_fiche'] not in {'humain', 'animal'} or merged['statut'] not in {'présent', 'sorti', 'supprimé'}:
        raise ValueError('Type ou statut incorrect.')
    if merged['date_naissance']:
        try:
            birth = date.fromisoformat(merged['date_naissance'])
        except ValueError:
            raise ValueError('Date de naissance incorrecte.')
        if birth > date.today():
            raise ValueError('La date de naissance ne peut pas être dans le futur.')
    else:
        birth = None
        if ('date_naissance' in changes or current['type_fiche'] == 'animal') and merged['type_fiche'] == 'humain':
            raise ValueError('La date de naissance est obligatoire.')
    if len(merged['family_key']) > 80:
        raise ValueError('Le nom du groupe est limité à 80 caractères.')
    ref = merged['referent_humain_id']
    if ref:
        query = FicheImplique.query.filter_by(evenement_id=fiche.evenement_id, est_animal=False)
        parent = query.filter_by(id=int(ref)).first() if ref.isdigit() else query.filter_by(client_uuid=ref).first()
        if not parent or parent.id == fiche.id:
            raise ValueError('La personne référente est invalide.')
        ref = parent.id
    custom = validate_custom(fiche.evenement_id, merged['custom_values'], merged['type_fiche'])
    old_status = fiche.statut
    for key in FIELDS:
        if key not in ('date_naissance', 'referent_humain_id'):
            setattr(fiche, key, merged[key])
    fiche.date_naissance = birth
    fiche.referent_humain_id = ref or None
    fiche.est_animal = fiche.type_fiche == 'animal'
    fiche.humain = not fiche.est_animal
    if fiche.statut != old_status:
        fiche.heure_sortie = utcnow() if fiche.statut == 'sorti' else None
    meta = metadata(fiche)
    meta.family_key, meta.custom_values = merged['family_key'], custom
    after = state(fiche)
    if record_change(fiche, user.id, 'edit', current, after):
        db.session.add(TimelineEntry(fiche_id=fiche.id, user_id=user.id, kind='update', content='Modification de la fiche (voir historique détaillé)'))


def history(fiche_id):
    return [{'at': row.created_at.isoformat() + 'Z', 'author': row.user.nom_utilisateur if row.user else 'Compte supprimé',
             'kind': row.kind, 'changes': row.changes} for row in FicheChange.query.filter_by(fiche_id=fiche_id)
            .order_by(FicheChange.created_at.desc(), FicheChange.id.desc())]
