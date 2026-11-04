"""Validate browser-generated offline files with independent format readers."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile
from xml.etree import ElementTree

import pytest
from openpyxl import load_workbook
from reportlab.pdfbase.pdfmetrics import stringWidth


@pytest.fixture(scope="module")
def offline_export_files(tmp_path_factory):
    runtime = shutil.which("node")
    if not runtime and os.name == "nt":
        electron = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Microsoft VS Code/Code.exe"
        if electron.is_file():
            runtime = str(electron)
    if not runtime:
        pytest.skip("Node.js is required to execute the browser exporter")
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp("offline-exports")
    environment = dict(os.environ, ELECTRON_RUN_AS_NODE="1")
    subprocess.run([runtime, str(root / "tests/test_offline_exports.cjs"), str(output)],
                   cwd=root, env=environment, capture_output=True, check=True, timeout=30)
    return output


def test_offline_excel_is_real_workbook_and_keeps_user_text(offline_export_files):
    filename = offline_export_files / "event.xlsx"
    with zipfile.ZipFile(filename) as archive:
        assert archive.testzip() is None
        for part in archive.namelist():
            ElementTree.fromstring(archive.read(part))
        sheet = ElementTree.fromstring(archive.read("xl/worksheets/sheet1.xml"))
        ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        assert sheet.findall(".//m:f", ns) == []
        assert sheet.find("m:autoFilter", ns) is not None
    workbook = load_workbook(filename)
    sheet = workbook["Fiches Impliqués"]
    assert sheet.max_row == 151
    headers = [cell.value for cell in sheet[1]]
    first = dict(zip(headers, list(sheet.values)[1]))
    assert first["Nom"] == "Hélène Cœur"
    assert first["Prénom"] == "François"
    assert first["Date de naissance"] == "31/12/1990"
    assert first["Téléphone"] == "+330600000000"
    assert first["Statut"] == "sorti"
    assert first["Destination"] == "Hôpital"
    assert first["Bagages"] == "B-01, B-02"
    assert first["Zone d’accueil"] == "Étage 2"
    assert first["Synchronisation"] == "En attente de synchronisation"
    assert first["Autres informations"] == '<b>& "notes"'
    assert first["Personne à prévenir"] == '=HYPERLINK("https://example.invalid","x")'
    assert first["Recherche personne"] == "+SUM(1,1)"
    for label in ("Personne à prévenir", "Recherche personne", "Code Sinus", "Tél. à prévenir"):
        assert sheet.cell(2, headers.index(label) + 1).data_type == "s"
    assert sheet.freeze_panes == "A2"
    assert workbook["Évènement"]["B2"].value == "Évènement été — Cœur"
    assert not any(cell.value == "SUPPRIMÉ_CONFIRME" for row in sheet for cell in row)
    assert load_workbook(offline_export_files / "empty.xlsx").worksheets[0].max_row == 1


def read_pdf(filename):
    """Check xref offsets and stream lengths, then decode PDF text operands."""
    content = filename.read_bytes()
    assert content.startswith(b"%PDF-1.4\n")
    assert content.endswith(b"%%EOF\n")
    start = int(re.search(rb"startxref\n(\d+)\n%%EOF", content)[1])
    assert content[start:start + 4] == b"xref"
    entries = content[start:].split(b"\n")
    count = int(entries[1].split()[1])
    for index in range(1, count):
        offset = int(entries[index + 2].split()[0])
        assert content[offset:].startswith(f"{index} 0 obj\n".encode())
    for stream in re.finditer(rb"/Length (\d+) >>\nstream\n", content):
        end = stream.end() + int(stream[1])
        assert content[end:end + 10] == b"\nendstream"
    mapping = {int(source, 16): chr(int(target, 16)) for source, target in
               re.findall(rb"<([0-9a-f]{2})> <([0-9a-f]{4})>", content)}
    operands = re.findall(rb"\(((?:\\[0-7]{3})*)\) Tj", content)
    decoded = []
    for operand in operands:
        codes = [int(value, 8) for value in re.findall(rb"\\([0-7]{3})", operand)]
        decoded.append("".join(mapping.get(code, chr(code)) for code in codes))
    pages = len(re.findall(rb"/Type /Page /Parent", content))
    assert f"/Count {pages} ".encode() in content
    return content, "\n".join(decoded), pages


def test_offline_pdf_pagination_accents_and_last_record(offline_export_files):
    content, text, pages = read_pdf(offline_export_files / "event.pdf")
    assert pages >= 3
    assert "841.89 595.28".encode() in content
    assert "Hélène Cœur" in text
    assert "François" in text
    assert "Personne-149" in text
    assert "SUPPRIMÉ_CONFIRME" not in text
    assert "B-01, B-02" in text
    # Each page contains the repeated heading; table headers repeat as needed.
    assert text.count("Fiches impliquées — Évènement") == pages
    assert text.count("Naissance") >= 2
    assert "Protection Civile · 1 / " in text


def test_offline_fiche_pdf_long_notes_and_local_history(offline_export_files):
    content, text, pages = read_pdf(offline_export_files / "fiche.pdf")
    assert pages >= 3
    assert b"595.28 841.89" in content
    assert "FIN_NOTES" in text.replace("\n", "")
    assert "FIN_HISTORIQUE" in text
    assert "Sortie locale" in text
    assert "Zone d’accueil" in text
    assert "Étage 2" in text
    assert "Hélène Cœur" in text
    assert "Hôpital" in text
    assert read_pdf(offline_export_files / "empty.pdf")[2] == 1


def test_offline_pdf_with_independent_reader(offline_export_files):
    pypdf = pytest.importorskip("pypdf", reason="Optional independent PDF parser")
    for name in ("event.pdf", "fiche.pdf", "empty.pdf"):
        reader = pypdf.PdfReader(offline_export_files / name, strict=True)
        pages = []
        for page in reader.pages:
            width, height = float(page.mediabox.width), float(page.mediabox.height)

            def check_text_bounds(value, _matrix, transform, font, size):
                value = value.rstrip("\n")
                if not value:
                    return
                x, y = transform[4:6]
                font_name = str(font["/BaseFont"]).lstrip("/")
                # ReportLab supplies the font's real glyph widths, independently
                # of the browser exporter's conservative wrapping estimates.
                right = x + stringWidth(value, font_name, size)
                assert x >= 27.5, (name, value, x)
                assert right <= width - 27.5, (name, value, right, width)
                assert 17.5 <= y <= height - 27.5, (name, value, y, height)

            pages.append(page.extract_text(visitor_text=check_text_bounds))
            # Borders cover the full table width, including the last column.
            stream = page.get_contents().get_data()
            for segment in re.findall(rb"([\d.]+) ([\d.]+) m ([\d.]+) ([\d.]+) l S", stream):
                x1, y1, x2, y2 = map(float, segment)
                assert 27.5 <= x1 <= x2 <= width - 27.5
                assert 27.5 <= y1 <= height - 27.5
                assert y1 == y2
        extracted = "\n".join(pages)
        assert "Évènement" in extracted
        assert "Protection Civile" in extracted
        if name != "empty.pdf":
            assert "Hélène Cœur" in extracted
            assert "François" in extracted
        if name == "fiche.pdf":
            assert "FIN_NOTES" in extracted.replace("\n", "")
            assert "FIN_HISTORIQUE" in extracted
