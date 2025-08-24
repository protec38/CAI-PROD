
from flask import request, session
from .models import AuditLog
from .extensions import db

def log_action(action: str, entity_type: str | None = None, entity_id: int | None = None, extra: str | None = None):
    user_id = session.get("user_id")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    entry = AuditLog(user_id=user_id, action=action, entity_type=entity_type, entity_id=entity_id, ip=ip, extra=extra)
    db.session.add(entry)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
