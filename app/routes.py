from flask import Blueprint
# Central blueprint keeping the same endpoint names for backward compatibility
main_bp = Blueprint('main_bp', __name__)

# Register route groups defined in app.blueprints.*
from .blueprints import auth, evenements, fiches, tickets, admin, public  # noqa: E402

auth.register(main_bp)
evenements.register(main_bp)
fiches.register(main_bp)
tickets.register(main_bp)
admin.register(main_bp)
public.register(main_bp)
