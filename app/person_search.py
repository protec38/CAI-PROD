"""Event-scoped searches and identity matches for new fiches."""
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
            'target_nom': row.target_nom, 'target_prenom': row.target_prenom,
            'created_at': row.created_at.isoformat() + 'Z',
            'resolved_at': row.resolved_at.isoformat() + 'Z' if row.resolved_at else None}


def active_searches(event_id):
    return [serialize(row) for row in PersonSearch.query.filter_by(evenement_id=event_id, resolved_at=None)
            .order_by(PersonSearch.created_at.desc(), PersonSearch.id.desc())]


def wanted_matches(event_id, nom, prenom):
    if not normalized(nom) or not normalized(prenom):
        return []
    return [row for row in active_searches(event_id) if normalized(row['target_nom']) == normalized(nom)
            and normalized(row['target_prenom']) == normalized(prenom)]


@search_bp.route('/evenement/<int:event_id>/recherches', methods=['GET', 'POST'])
def page(event_id):
    user, event = access(event_id)
    if request.method == 'POST':
        try:
            action = request.form.get('action', 'create')
            if action == 'create':
                values = {key: ' '.join(request.form.get(key, '').split()) for key in
                          ('seeker_nom', 'seeker_prenom', 'target_nom', 'target_prenom')}
                if any(not value or len(value) > 100 for value in values.values()):
                    raise ValueError('Renseignez les noms et prénoms (100 caractères maximum par champ).')
                db.session.add(PersonSearch(evenement_id=event_id, created_by_id=user.id, **values))
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
                row.resolved_at = utcnow() if action == 'resolve' else None
                flash('La recherche a été mise à jour.', 'success')
            else:
                raise ValueError('Action de recherche inconnue.')
            db.session.commit()
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), 'danger')
        return redirect(url_for('person_search.page', event_id=event_id))
    searches = PersonSearch.query.filter_by(evenement_id=event_id).order_by(
        PersonSearch.created_at.desc(), PersonSearch.id.desc()).all()
    fiches = FicheImplique.query.filter_by(evenement_id=event_id, est_animal=False).all()
    matches = {row.id: [fiche for fiche in fiches if normalized(fiche.nom) == normalized(row.target_nom)
                       and normalized(fiche.prenom) == normalized(row.target_prenom)] for row in searches}
    return render_template('person_search.html', user=user, evenement=event, searches=searches, matches=matches)


@search_bp.get('/api/evenement/<int:event_id>/recherches/correspondances')
def lookup(event_id):
    access(event_id)
    return json_nocache({'matches': wanted_matches(event_id, request.args.get('nom', ''), request.args.get('prenom', ''))})
