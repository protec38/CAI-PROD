from functools import wraps
from flask import redirect, url_for, session, flash

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Vous devez être connecté.", "warning")
            return redirect(url_for("main_bp.login"))
        return f(*args, **kwargs)
    return decorated_function
