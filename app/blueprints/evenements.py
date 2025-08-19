from flask import render_template, request, redirect, url_for, flash
from app.models import db, Evenement
from app.blueprints.decorators import login_required, role_required, event_member_required

def register(bp):
    # --- Dashboard "générique" pour compatibilité ---
    @bp.route("/dashboard", methods=["GET"], endpoint="dashboard")
    @login_required
    def dashboard():
        """
        Point d'entrée après login.
        - Si au moins un évènement existe : redirige vers le plus récent
        - Sinon : redirige vers la création d'évènement
        """
        ev = Evenement.query.order_by(Evenement.id.desc()).first()
        if ev:
            return redirect(url_for("main_bp.evenement_dashboard", evenement_id=ev.id))
        flash("Aucun évènement trouvé. Créez-en un pour commencer.", "info")
        return redirect(url_for("main_bp.evenement_new"))

    @bp.route("/evenement/new", methods=["GET", "POST"], endpoint="evenement_new")
    @login_required
    @role_required("admin", "encadrant", "codep")
    def evenement_new():
        if request.method == "POST":
            nom = request.form.get("nom", "").strip()
            if not nom:
                flash("Le nom est requis.", "warning")
                return render_template("evenement_new.html")
            ev = Evenement(nom=nom)
            db.session.add(ev)
            db.session.commit()
            flash("Évènement créé.", "success")
            return redirect(url_for("main_bp.evenement_dashboard", evenement_id=ev.id))
        return render_template("evenement_new.html")

    @bp.route("/evenement/<int:evenement_id>/dashboard", methods=["GET"], endpoint="evenement_dashboard")
    @login_required
    @event_member_required("evenement_id")
    def evenement_dashboard(evenement_id):
        ev = Evenement.query.get_or_404(evenement_id)
        return render_template("dashboard.html", evenement=ev)
