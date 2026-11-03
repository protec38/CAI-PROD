"""Shared bagage and departure validation. Callers commit the transaction."""
import re
from datetime import datetime, timezone

from .extensions import db
from .models import Bagage, Evenement, TimelineEntry
from .time_utils import utcnow


def parse_bagages(raw):
    if len(raw) > 300:
        raise ValueError("La liste des bagages ne peut pas dépasser 300 caractères.")
    numbers = list(dict.fromkeys(part for part in re.split(r"[\s,;]+", raw.strip()) if part))
    if any(len(number) > 50 for number in numbers):
        raise ValueError("Un numéro de bagage ne peut pas dépasser 50 caractères.")
    return numbers


def apply_bagages(fiche, user_id, raw, base_raw=None):
    db.session.execute(db.select(Evenement.id).where(Evenement.id == fiche.evenement_id).with_for_update())
    desired = set(parse_bagages(raw))
    existing = Bagage.query.filter_by(fiche_id=fiche.id).all()
    current = {bagage.numero for bagage in existing}
    # Merge only the changes the operator made, keeping other operators' additions.
    base = current if base_raw is None else set(parse_bagages(base_raw))
    additions, removals = desired - base, base - desired
    conflicts = Bagage.query.filter(
        Bagage.evenement_id == fiche.evenement_id, Bagage.fiche_id != fiche.id,
        Bagage.numero.in_(list(additions)),
    ).all()
    if conflicts:
        raise ValueError("Bagages déjà attribués à une autre fiche : " + ", ".join(sorted({b.numero for b in conflicts})))
    for number in sorted(additions - current):
        db.session.add(Bagage(numero=number, fiche_id=fiche.id, evenement_id=fiche.evenement_id))
    for bagage in existing:
        if bagage.numero in removals:
            db.session.delete(bagage)
    db.session.add(TimelineEntry(fiche_id=fiche.id, user_id=user_id, kind="update",
        content="Bagages — ajout : " + (", ".join(sorted(additions - current)) or "aucun") +
                "; retrait : " + (", ".join(sorted(removals & current)) or "aucun")))


def apply_sortie(fiche, user_id, destination, transport, occurred_at=None):
    if len(destination) > 255 or len(transport) > 255:
        raise ValueError("La destination et le transport ne peuvent pas dépasser 255 caractères.")
    departure = utcnow()
    if occurred_at:
        try:
            parsed = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
            departure = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            raise ValueError("Heure de sortie invalide.")
    if destination:
        fiche.destination = destination
    if transport:
        fiche.moyen_transport = transport
    fiche.statut, fiche.heure_sortie = "sorti", departure
    db.session.add(TimelineEntry(fiche_id=fiche.id, user_id=user_id, kind="exit",
        content=f"Sortie (destination={destination}, transport={transport})", created_at=departure))
