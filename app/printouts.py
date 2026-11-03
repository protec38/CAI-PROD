"""Printable A4 labels and an aggregate event closing report."""
from collections import Counter
from functools import lru_cache
from io import BytesIO
from xml.sax.saxutils import escape

from flask import url_for
from reportlab.graphics import renderPDF, renderSVG
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .fiche_updates import metadata, settings
from .models import Bagage, FicheImplique, FicheTrash
from .time_utils import utcnow


def qr_drawing(value, size=25 * mm):
    qr = QrCodeWidget(value, barLevel='M')
    x0, y0, x1, y1 = qr.getBounds()
    return Drawing(size, size, qr, transform=[size / (x1 - x0), 0, 0, size / (y1 - y0), 0, 0])


@lru_cache(maxsize=1024)
def qr_svg(value):
    return renderSVG.drawToString(qr_drawing(value)).encode('utf-8')


def labels_pdf(event, fiches, kind, copies):
    stream = BytesIO()
    pdf = canvas.Canvas(stream, pagesize=A4)
    pdf.setTitle(f'Étiquettes — {event.nom}')
    # A4: 3 columns x 8 rows, 63 x 34 mm, with quiet space around each QR.
    width, height = 63 * mm, 34 * mm
    items = []
    for fiche in fiches:
        values = [bag.numero for bag in fiche.bagages] if kind == 'bagage' else [None]
        for number in values:
            items.extend([(fiche, number)] * copies)
    if not items:
        pdf.setFont('Helvetica', 12)
        pdf.drawString(20 * mm, 270 * mm, 'Aucun bagage à étiqueter dans cette sélection.')
    for index, (fiche, number) in enumerate(items):
        if index and index % 24 == 0:
            pdf.showPage()
        col, row = index % 3, (index % 24) // 3
        x, y = (10 + col * 63) * mm, A4[1] - (12 + (row + 1) * 34) * mm
        pdf.setStrokeColor(colors.HexColor('#b8c7d5'))
        pdf.rect(x, y, width, height)
        link = url_for('features.qr_link', token=metadata(fiche).qr_token, _external=True)
        renderPDF.draw(qr_drawing(link, 27 * mm), pdf, x + 1 * mm, y + 3 * mm)
        from reportlab.lib.utils import simpleSplit
        heading = f'BAGAGE {number}' if number else fiche.numero
        name = f'{fiche.nom or ""} {fiche.prenom or ""}'.strip()
        for text, y_positions, font, size in [
            (heading, [27, 24], 'Helvetica-Bold', 8),
            (name, [18, 15], 'Helvetica', 7),
            (fiche.numero if number else ('Animal' if fiche.est_animal else 'Personne'), [10], 'Helvetica', 7),
            (event.nom, [5], 'Helvetica', 6),
        ]:
            wrapped = simpleSplit(text, font, size, 32 * mm)
            for offset, line in enumerate(wrapped[:len(y_positions)]):
                if offset == len(y_positions) - 1 and len(wrapped) > len(y_positions):
                    line = line.rstrip() + '...'
                while pdf.stringWidth(line, font, size) > 32 * mm:
                    line = line[:-1]
                pdf.setFont(font, size)
                pdf.drawString(x + 29 * mm, y + y_positions[offset] * mm, line)
    pdf.save()
    return stream.getvalue()


def report_pdf(event):
    fiches = FicheImplique.query.filter_by(evenement_id=event.id).all()
    humans = [f for f in fiches if not f.est_animal]
    animals = [f for f in fiches if f.est_animal]
    styles = getSampleStyleSheet()
    body = [Paragraph('Bilan de fin d’évènement', styles['Title']),
            Paragraph(escape(event.nom), styles['Heading1']),
            Paragraph(f'Évènement {escape(event.numero)} · État : {escape(event.statut or "—")}', styles['Normal']),
            Paragraph(f'Édité le {utcnow().strftime("%d/%m/%Y à %H:%M")} UTC', styles['Normal']), Spacer(1, 8 * mm)]
    counts = [['Indicateur', 'Nombre'], ['Personnes accueillies', str(len(humans))],
              ['Personnes présentes', str(sum(f.statut == 'présent' for f in humans))],
              ['Personnes sorties', str(sum(f.statut == 'sorti' for f in humans))],
              ['Animaux accueillis', str(len(animals))], ['Animaux présents', str(sum(f.statut == 'présent' for f in animals))],
              ['Bagages enregistrés', str(Bagage.query.filter_by(evenement_id=event.id).count())],
              ['Fiches en corbeille', str(FicheTrash.query.filter_by(evenement_id=event.id, restored_at=None).count())]]
    capacity = settings(event.id)['capacity']
    if capacity:
        counts.append(['Capacité d’accueil', str(capacity)])

    def table(rows):
        result = Table([[Paragraph(escape(str(v)), styles['Normal']) for v in row] for row in rows], colWidths=[135 * mm, 35 * mm], repeatRows=1)
        result.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e3edf6')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8), ('LINEBELOW', (0, 0), (-1, -1), .3, colors.HexColor('#c6d3df'))]))
        return result

    body.append(table(counts))
    for title, values in [('Arrivées par jour (heure de Paris)', Counter(f.heure_arrivee_locale.strftime('%d/%m/%Y') for f in humans if f.heure_arrivee)),
                          ('Destinations de sortie', Counter(f.destination or 'Non renseignée' for f in humans if f.statut == 'sorti')),
                          ('Moyens de transport', Counter(f.moyen_transport or 'Non renseigné' for f in humans if f.statut == 'sorti'))]:
        body.extend([Spacer(1, 6 * mm), Paragraph(title, styles['Heading2']), table([['Répartition', 'Nombre'], *sorted(values.items())] if values else [['Répartition', 'Nombre'], ['Aucune donnée', '0']])])
    body.extend([Spacer(1, 8 * mm), Paragraph('Ce bilan reflète les données reçues par le serveur au moment de l’édition. Synchronisez les appareils avant le bilan définitif.', styles['Normal'])])
    stream = BytesIO()
    SimpleDocTemplate(stream, pagesize=A4, rightMargin=20 * mm, leftMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm).build(body)
    return stream.getvalue()
