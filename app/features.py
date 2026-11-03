"""Event tools, personal preferences, protected QR links and device locking."""
import json
import re
import time

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf.csrf import generate_csrf

from .extensions import db, limiter
from .fiche_updates import duplicates, history, metadata, settings, state
from .models import (
    Evenement,
    EventSettings,
    FicheImplique,
    FicheMetadata,
    FicheTrash,
    UserPreference,
)
from .routes import (
    _build_safe_redirect,
    get_current_user,
    json_nocache,
    user_can_access_event,
)

features_bp = Blueprint('features', __name__)


def manager(user, event):
    return user.is_admin or user.role.lower() in {'codep', 'responsable'} or event.createur_id == user.id


def access(event_id, manage=False):
    user = get_current_user()
    if not user or not user.is_active:
        abort(401)
    event = db.get_or_404(Evenement, event_id)
    if not user_can_access_event(user, event) or (manage and not manager(user, event)):
        abort(403)
    return user, event


def preferences(user_id):
    row = db.session.get(UserPreference, user_id)
    return {'lock_minutes': row.lock_minutes if row else 0, 'dashboard': row.dashboard if row else {}}


def validate_settings(data):
    if not isinstance(data, dict):
        raise TypeError('Réglages invalides.')
    try:
        capacity = int(data['capacity']) if data.get('capacity') not in ('', None) else None
        warning = int(data.get('warning_percent', 80))
    except (ValueError, TypeError):
        raise ValueError('Capacité ou seuil incorrect.')
    if (capacity is not None and not 1 <= capacity <= 1000000) or not 1 <= warning <= 100:
        raise ValueError('Capacité : 1 à 1 000 000. Seuil : 1 à 100 %.')
    choices = data.get('choice_lists', {})
    if not isinstance(choices, dict) or set(choices) - {'destinations', 'transports', 'zones', 'competences'}:
        raise ValueError('Listes de choix invalides.')
    for values in choices.values():
        if not isinstance(values, list) or len(values) > 100 or any(not isinstance(v, str) or not 1 <= len(v.strip()) <= 80 for v in values):
            raise ValueError('Chaque liste accepte 100 choix de 80 caractères maximum.')
    fields = data.get('custom_fields', [])
    if not isinstance(fields, list) or len(fields) > 20:
        raise ValueError('Vous pouvez définir 20 champs personnalisés maximum.')
    seen, clean = set(), []
    for field in fields:
        if not isinstance(field, dict):
            raise TypeError('Champ personnalisé invalide.')
        key = field.get('key', '')
        label = field.get('label', '')
        kind = field.get('type')
        values = field.get('choices', [])
        if (not isinstance(key, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,39}', key) or key in seen
                or not isinstance(label, str) or not 1 <= len(label.strip()) <= 80
                or kind not in {'text', 'number', 'date', 'choice', 'checkbox'}
                or field.get('scope', 'all') not in {'all', 'humain', 'animal'}
                or not isinstance(values, list) or len(values) > 100
                or any(not isinstance(v, str) or not 1 <= len(v) <= 80 for v in values)
                or (kind == 'choice' and not values)):
            raise ValueError('Vérifiez le nom, le type et les choix de chaque champ personnalisé.')
        seen.add(key)
        clean.append({'key': key, 'label': label.strip(), 'type': kind, 'scope': field.get('scope', 'all'),
                      'required': bool(field.get('required')), 'choices': list(dict.fromkeys(values))})
    return {'capacity': capacity, 'warning_percent': warning, 'custom_fields': clean,
            'choice_lists': {key: list(dict.fromkeys(v.strip() for v in values)) for key, values in choices.items()}}


@features_bp.route('/evenement/<int:event_id>/outils', methods=['GET', 'POST'])
def tools_page(event_id):
    user, event = access(event_id)
    if request.method == 'POST':
        if not manager(user, event):
            abort(403)
        try:
            data = validate_settings(json.loads(request.form.get('settings', '{}')))
            row = db.session.get(EventSettings, event_id) or EventSettings(id=event_id)
            for key, value in data.items():
                setattr(row, key, value)
            db.session.add(row)
            db.session.commit()
            flash('Les réglages de l’évènement ont été enregistrés.', 'success')
        except (ValueError, TypeError) as exc:
            db.session.rollback()
            flash(str(exc), 'danger')
        return redirect(url_for('features.tools_page', event_id=event_id))
    fiches = FicheImplique.query.filter_by(evenement_id=event_id).order_by(FicheImplique.numero).all()
    trash = FicheTrash.query.filter_by(evenement_id=event_id, restored_at=None).order_by(FicheTrash.deleted_at.desc()).all()
    groups = {}
    for fiche in fiches:
        key = metadata(fiche).family_key
        if key:
            groups.setdefault(key, []).append(fiche)
    db.session.commit()
    return render_template('features.html', user=user, evenement=event, settings=settings(event_id),
        manage=manager(user, event), can_restore=user.is_admin or user.role.lower() in {'codep', 'responsable'},
        trash=trash, fiches=fiches, groups=groups)


@features_bp.post('/evenement/<int:event_id>/corbeille/<item_id>/restaurer')
def restore_fiche(event_id, item_id):
    user, event = access(event_id)
    if not (user.is_admin or user.role.lower() in {'codep', 'responsable'}):
        abort(403)
    item = db.get_or_404(FicheTrash, item_id)
    if item.evenement_id != event_id:
        abort(403)
    from .recycle import restore
    try:
        fiche = restore(item, user.id)
        db.session.commit()
        flash(f'Fiche restaurée : {fiche.numero if fiche else item.numero}.', 'success')
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), 'danger')
    return redirect(url_for('features.tools_page', event_id=event.id, _anchor='corbeille'))


@features_bp.get('/api/evenement/<int:event_id>/doublons')
def duplicate_lookup(event_id):
    access(event_id)
    rows = duplicates(event_id, request.args.get('nom', ''), request.args.get('prenom', ''),
                      request.args.get('date_naissance', ''), request.args.get('exclude', type=int))
    return json_nocache({'duplicates': [{'id': f.id, 'numero': f.numero, 'nom': f.nom, 'prenom': f.prenom} for f in rows]})


@features_bp.get('/api/fiche/<int:fiche_id>/complement')
def fiche_extra(fiche_id):
    fiche = db.get_or_404(FicheImplique, fiche_id)
    access(fiche.evenement_id)
    result = extra(fiche, full=True)
    db.session.commit()
    return json_nocache(result)


def extra(fiche, full=False):
    meta = metadata(fiche)
    result = {'family_key': meta.family_key, 'custom_values': meta.custom_values, 'revision': meta.revision,
              'qr_url': url_for('features.qr_link', token=meta.qr_token, _external=True),
              'referent_humain_id': str(fiche.referent_humain_id or ''), 'edit_state': state(fiche)}
    if full:
        import base64

        from .printouts import qr_svg
        result.update(changes=history(fiche.id),
                      qr_data='data:image/svg+xml;base64,' + base64.b64encode(qr_svg(result['qr_url'])).decode())
    return result


@features_bp.get('/q/<token>')
def qr_link(token):
    user = get_current_user()
    if not user or not user.is_active:
        return redirect(url_for('main_bp.login', next=request.path))
    meta = FicheMetadata.query.filter_by(qr_token=token).first()
    if meta:
        fiche = db.get_or_404(FicheImplique, meta.id)
        access(fiche.evenement_id)
        return redirect(url_for('main_bp.fiche_detail', id=fiche.id))
    for item in FicheTrash.query.filter_by(restored_at=None):
        if item.payload.get('metadata', {}).get('qr_token') == token:
            access(item.evenement_id)
            return redirect(url_for('features.tools_page', event_id=item.evenement_id, _anchor='corbeille'))
    abort(404)


@features_bp.post('/evenement/<int:event_id>/etiquettes.pdf')
def labels(event_id):
    _user, event = access(event_id)
    ids = request.form.getlist('fiche_ids', type=int)
    try:
        copies = int(request.form.get('copies', '1'))
        if not ids or len(ids) > 1000 or not 1 <= copies <= 20 or request.form.get('kind', 'fiche') not in {'fiche', 'bagage'}:
            raise ValueError
    except ValueError:
        abort(400)
    fiches = FicheImplique.query.filter(FicheImplique.evenement_id == event_id, FicheImplique.id.in_(ids)).all()
    if len(fiches) != len(set(ids)):
        abort(403)
    from .printouts import labels_pdf
    data = labels_pdf(event, fiches, request.form.get('kind', 'fiche'), copies)
    db.session.commit()
    return Response(data, mimetype='application/pdf', headers={'Content-Disposition': f'attachment; filename="etiquettes-{event_id}.pdf"', 'Cache-Control': 'no-store'})


@features_bp.get('/evenement/<int:event_id>/bilan.pdf')
def report(event_id):
    _user, event = access(event_id, manage=True)
    from .printouts import report_pdf
    return Response(report_pdf(event), mimetype='application/pdf', headers={'Content-Disposition': f'attachment; filename="bilan-{event_id}.pdf"', 'Cache-Control': 'no-store'})


@features_bp.route('/mes-preferences', methods=['GET', 'POST'])
def user_preferences():
    user = get_current_user()
    if not user or not user.is_active:
        abort(401)
    if request.method == 'POST':
        try:
            minutes = int(request.form.get('lock_minutes', 0))
            if minutes not in {0, 1, 5, 10, 15, 30}:
                raise ValueError
            row = db.session.get(UserPreference, user.id) or UserPreference(id=user.id)
            row.lock_minutes = minutes
            row.dashboard = {key: request.form.get(key) == 'on' for key in
                             ('show_counters', 'compact', 'heure_arrivee', 'difficultes', 'competences', 'bagages')}
            db.session.add(row)
            db.session.commit()
            session['last_activity'] = time.time()
            flash('Vos préférences ont été enregistrées.', 'success')
            return redirect(_build_safe_redirect(request.form.get('next'), 'main_bp.evenement_new'))
        except ValueError:
            flash('Durée de verrouillage incorrecte.', 'danger')
    return render_template('preferences.html', prefs=preferences(user.id), user=user, next=_build_safe_redirect(request.args.get('next'), 'main_bp.evenement_new'))


def lock_guard():
    if request.endpoint in {'static', 'main_bp._healthz', 'main_bp.login', 'main_bp.logout',
                            'features.unlock', 'features.lock_state', 'offline.service_worker'} or request.path.startswith('/hors-ligne'):
        return None
    user = get_current_user()
    if not user or not user.is_active:
        return None
    minutes = preferences(user.id)['lock_minutes']
    last = session.get('last_activity')
    if last is None:
        session['last_activity'] = time.time()
    if session.get('device_locked') or (minutes and last is not None and time.time() - last >= minutes * 60):
        session['device_locked'] = True
        if request.path.startswith('/api/') or request.path.endswith('fiches_json'):
            return json_nocache({'error': 'Appareil verrouillé.', 'locked': True}, 423)
        return redirect(url_for('features.unlock', next=request.full_path))
    return None


@features_bp.post('/api/session/activite')
def activity():
    user = get_current_user()
    if not user or not user.is_active:
        abort(401)
    session['last_activity'] = time.time()
    return json_nocache({'ok': True})


@features_bp.route('/api/session/verrouillage', methods=['GET', 'POST'])
def lock_state():
    user = get_current_user()
    if not user or not user.is_active:
        return json_nocache({'error': 'Connexion requise.'}, 401)
    if request.method == 'POST':
        session['device_locked'] = True
    minutes = preferences(user.id)['lock_minutes']
    if minutes and time.time() - session.get('last_activity', time.time()) >= minutes * 60:
        session['device_locked'] = True
    return json_nocache({'locked': bool(session.get('device_locked')), 'csrf_token': generate_csrf()})


@features_bp.route('/session/deverrouiller', methods=['GET', 'POST'])
@limiter.limit('10 per minute', methods=['POST'])
def unlock():
    user = get_current_user()
    if not user or not user.is_active:
        return redirect(url_for('main_bp.login'))
    error = None
    if request.method == 'POST':
        if user.check_password(request.form.get('password', '')):
            session['device_locked'] = False
            session['last_activity'] = time.time()
            if request.form.get('json'):
                return json_nocache({'unlocked': True, 'user_id': user.id})
            return redirect(_build_safe_redirect(request.form.get('next'), 'main_bp.evenement_new'))
        error = 'Mot de passe incorrect.'
        if request.form.get('json'):
            return json_nocache({'error': error}, 403)
    return render_template('unlock.html', user=user, error=error, next=request.args.get('next', ''))


def init_features(app):
    app.register_blueprint(features_bp)
    app.before_request(lock_guard)

    @app.context_processor
    def feature_context():
        user = get_current_user()
        return {'feature_settings': settings, 'personal_preferences': preferences(user.id) if user and user.is_active else {},
                'device_user_id': user.id if user and user.is_active and request.endpoint not in {'main_bp.login', 'features.unlock'} else None}
