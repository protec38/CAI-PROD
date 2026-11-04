"""Event-scoped searches and identity matches for new fiches."""
from datetime import UTC, datetime

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for

from .extensions import db
from .features import access
from .fiche_updates import normalized
from .models import Evenement, FicheImplique, PersonSearch
from .routes import get_current_user, json_nocache, user_can_access_event
from .time_utils import utcnow

search_bp = Blueprint('person_search', __name__)


@search_bp.get('/recherches')
def event_selector():
    user = get_current_user()
    if not user or not user.is_active:
        abort(401)
    events = [event for event in Evenement.query.filter_by(archived=False).order_by(Evenement.nom)
              if user_can_access_event(user, event)]
    return render_template('search_events.html', events=events)


def serialize(row):
    return {'id': row.id, 'seeker_nom': row.seeker_nom, 'seeker_prenom': row.seeker_prenom,
            'seeker_fiche_id': row.seeker_fiche_id,
            'target_nom': row.target_nom, 'target_prenom': row.target_prenom,
            'created_at': row.created_at.isoformat() + 'Z',
            'resolved_at': row.resolved_at.isoformat() + 'Z' if row.resolved_at else None}


def active_searches(event_id):
    return [serialize(row) for row in PersonSearch.query.filter_by(evenement_id=event_id, resolved_at=None)
            .order_by(PersonSearch.created_at.desc(), PersonSearch.id.desc())]


def all_searches(event_id):
    if resolve_matching_searches(event_id):
        db.session.commit()
    return [serialize(row) for row in PersonSearch.query.filter_by(evenement_id=event_id)
            .order_by(PersonSearch.created_at.desc(), PersonSearch.id.desc())]


def resolve_matching_searches(event_id):
    """Resolve each matching identity once, including older and corrected fiches."""
    pending = PersonSearch.query.filter_by(evenement_id=event_id, resolved_at=None).all()
    if not pending:
        return 0
    identities = {(normalized(nom), normalized(prenom)) for nom, prenom in
                  db.session.query(FicheImplique.nom, FicheImplique.prenom).filter_by(
                      evenement_id=event_id, est_animal=False).filter(
                          FicheImplique.statut != 'supprimé') if normalized(nom) and normalized(prenom)}
    matching = [row.id for row in pending
                if (normalized(row.target_nom), normalized(row.target_prenom)) in identities]
    if not matching:
        return 0
    # Concurrent screen refreshes must share the same resolution timestamp.
    result = db.session.execute(db.update(PersonSearch).where(
        PersonSearch.id.in_(matching), PersonSearch.resolved_at.is_(None)).values(resolved_at=utcnow()))
    return result.rowcount


@search_bp.get('/api/evenement/<int:event_id>/recherches/etat')
def search_status(event_id):
    access(event_id)
    try:
        since = datetime.fromisoformat(request.args.get('since', ''))
        if since.tzinfo:
            since = since.astimezone(UTC).replace(tzinfo=None)
    except ValueError:
        return json_nocache({'error': 'Date de suivi invalide.'}, 400)
    rows = all_searches(event_id)
    until = utcnow()
    notifications = [row for row in rows if row['resolved_at']
                     and since < datetime.fromisoformat(row['resolved_at'][:-1]) <= until]
    return json_nocache({'searches': rows, 'notifications': notifications,
                         'server_time': until.isoformat() + 'Z'})


def wanted_matches(event_id, nom, prenom):
    if not normalized(nom) or not normalized(prenom):
        return []
    return [row for row in active_searches(event_id) if normalized(row['target_nom']) == normalized(nom)
            and normalized(row['target_prenom']) == normalized(prenom)]


def create_from_fiche(fiche, form, user_id):
    """Create a search in the fiche transaction; UUID retries return before here."""
    if fiche.est_animal:
        return
    target_nom = ' '.join((form.get('recherche_nom') or '').split())
    target_prenom = ' '.join((form.get('recherche_prenom') or '').split())
    if not target_nom and not target_prenom:
        return
    if not target_nom or not target_prenom:
        raise ValueError('Renseignez le nom et le prénom de la personne recherchée.')
    if len(target_nom) > 100 or len(target_prenom) > 100:
        raise ValueError('Le nom et le prénom recherchés sont limités à 100 caractères chacun.')
    seeker_nom = ' '.join((fiche.nom or '').split())
    seeker_prenom = ' '.join((fiche.prenom or '').split())
    if not seeker_nom or not seeker_prenom:
        raise ValueError('Renseignez le nom et le prénom du demandeur de la recherche sur sa fiche.')
    # Keep the existing text column readable by old clients, exports and backups.
    fiche.recherche_personne = f'{target_nom} {target_prenom}'
    db.session.add(PersonSearch(evenement_id=fiche.evenement_id, created_by_id=user_id,
                               seeker_fiche_id=fiche.id,
                               seeker_nom=seeker_nom, seeker_prenom=seeker_prenom,
                               target_nom=target_nom, target_prenom=target_prenom))


@search_bp.route('/evenement/<int:event_id>/recherches', methods=['GET', 'POST'])
def page(event_id):
    user, event = access(event_id)
    watch_since = utcnow().isoformat() + 'Z'
    if request.method == 'POST':
        try:
            action = request.form.get('action', 'create')
            if action == 'create':
                values = {key: ' '.join(request.form.get(key, '').split()) for key in
                          ('seeker_nom', 'seeker_prenom', 'target_nom', 'target_prenom')}
                if any(not value or len(value) > 100 for value in values.values()):
                    raise ValueError('Renseignez les noms et prénoms (100 caractères maximum par champ).')
                seeker_id = request.form.get('seeker_fiche_id', '').strip()
                if seeker_id:
                    if not seeker_id.isdecimal():
                        raise ValueError('Choisissez une fiche valide pour le demandeur.')
                    seeker = db.get_or_404(FicheImplique, int(seeker_id))
                    if seeker.evenement_id != event_id:
                        abort(403)
                    if seeker.est_animal or seeker.statut == 'supprimé':
                        raise ValueError('Choisissez une fiche de personne disponible.')
                    if (normalized(seeker.nom) != normalized(values['seeker_nom'])
                            or normalized(seeker.prenom) != normalized(values['seeker_prenom'])):
                        raise ValueError('Le nom et le prénom doivent correspondre à la fiche choisie.')
                db.session.add(PersonSearch(evenement_id=event_id, created_by_id=user.id,
                                            seeker_fiche_id=int(seeker_id) if seeker_id else None, **values))
                flash('La recherche de personne a été enregistrée.', 'success')
            elif action in {'resolve', 'reopen'}:
                search_id = request.form.get('search_id', type=int)
                if not search_id:
                    raise ValueError('Choisissez la recherche à mettre à jour.')
                row = db.get_or_404(PersonSearch, search_id)
                if row.evenement_id != event_id:
                    abort(403)
                if row.created_by_id != user.id and not (user.is_admin or user.role.lower() == 'responsable'):
                    abort(403)
                if action == 'resolve' and row.resolved_at is None:
                    row.resolved_at = utcnow()
                elif action == 'reopen':
                    row.resolved_at = None
                flash('La recherche a été mise à jour.', 'success')
            else:
                raise ValueError('Action de recherche inconnue.')
            resolve_matching_searches(event_id)
            db.session.commit()
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), 'danger')
        return redirect(url_for('person_search.page', event_id=event_id))
    if resolve_matching_searches(event_id):
        db.session.commit()
    searches = PersonSearch.query.filter_by(evenement_id=event_id).order_by(
        PersonSearch.created_at.desc(), PersonSearch.id.desc()).all()
    fiches = FicheImplique.query.filter_by(evenement_id=event_id, est_animal=False).filter(
        FicheImplique.statut != 'supprimé').all()
    matches = {row.id: [fiche for fiche in fiches if normalized(fiche.nom) == normalized(row.target_nom)
                       and normalized(fiche.prenom) == normalized(row.target_prenom)] for row in searches}
    seekers = {row.id: [fiche for fiche in fiches if (fiche.id == row.seeker_fiche_id if row.seeker_fiche_id
                       else normalized(fiche.nom) == normalized(row.seeker_nom)
                       and normalized(fiche.prenom) == normalized(row.seeker_prenom))] for row in searches}
    return render_template('person_search.html', user=user, evenement=event, searches=searches,
                           search_watch_since=watch_since,
                           matches=matches, seekers=seekers,
                           seeker_choices=[{'id': f.id, 'nom': f.nom or '', 'prenom': f.prenom or '',
                                            'numero': f.numero} for f in fiches if f.nom and f.prenom])


@search_bp.get('/api/evenement/<int:event_id>/recherches/correspondances')
def lookup(event_id):
    access(event_id)
    return json_nocache({'matches': wanted_matches(event_id, request.args.get('nom', ''), request.args.get('prenom', ''))})
