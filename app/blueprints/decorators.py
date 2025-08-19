from functools import wraps
from flask import redirect, url_for, session, flash, abort
from app.models import Evenement, Utilisateur

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Vous devez être connecté.", "warning")
            return redirect(url_for("main_bp.login"))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            uid = session.get("user_id")
            if not uid:
                flash("Veuillez vous connecter.", "warning")
                return redirect(url_for("main_bp.login"))
            user = Utilisateur.query.get(uid)
            if not user or (roles and user.role not in roles):
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return wrapper

def event_member_required(param_name="evenement_id"):
    """
    Ensures the current user is linked to the given event id passed as view arg.
    """
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            uid = session.get("user_id")
            if not uid:
                flash("Veuillez vous connecter.", "warning")
                return redirect(url_for("main_bp.login"))
            ev_id = kwargs.get(param_name)
            if ev_id is None:
                return f(*args, **kwargs)  # nothing to check
            ev = Evenement.query.get(ev_id)
            if not ev:
                abort(404)
            user = Utilisateur.query.get(uid)
            if getattr(user, "role", None) == "admin":
                return f(*args, **kwargs)
            if hasattr(user, "evenements") and ev in getattr(user, "evenements"):
                return f(*args, **kwargs)
            abort(403)
        return decorated
    return wrapper
