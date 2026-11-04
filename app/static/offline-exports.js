/* Browser-only PDF and XLSX exports. Pass the snapshot after CAIOffline.listFiches
 * has merged local creations and actions. No request, CDN, or library is needed. */
(function (global) {
  'use strict';
  const MIME_PDF = 'application/pdf';
  const MIME_EXCEL = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
  const encoder = new TextEncoder();
  const text = value => value == null ? '' : Array.isArray(value) ? value.map(text).join(', ') : String(value);
  const clean = value => text(value).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\ufffe\uffff]/g, '');
  const xml = value => clean(value).replace(/[&<>"']/g, char => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;'}[char]));
  const dateOnly = value => /^\d{4}-\d{2}-\d{2}$/.test(text(value)) ? value.slice(8, 10) + '/' + value.slice(5, 7) + '/' + value.slice(0, 4) : text(value);
  const state = fiche => fiche.deletionPending ? 'Suppression en attente' : fiche.pending ? 'En attente de synchronisation' : 'Synchronisé';
  function eventData(data, context) {
    const source = data?.evenement || data || {};
    return {...source, settings: source.settings || context?.eventSettings || {}, id: source.id || context?.eventId || '', nom: source.nom || context?.eventName || '',
      numero: source.numero || context?.eventNumber || ''};
  }
  const visible = data => (data.fiches || []).filter(fiche => !fiche.deletedConfirmed);
  const eventRows = event => [
    ['Évènement', event.nom], ['Numéro', event.numero || event.id], ['Adresse', event.adresse],
    ['Statut', event.statut], ['Type', event.type_evt], ["Date d’ouverture", event.date_ouverture],
  ];
  const ficheColumns = [
    ['Numéro', 'numero'], ['Code Sinus', 'code_sinus'], ['Nom', 'nom'], ['Prénom', 'prenom'],
    ['Date de naissance', 'date_naissance'], ['Téléphone', 'telephone'], ['Adresse', 'adresse'],
    ['Statut', 'statut'], ['Heure d’arrivée', 'heure_arrivee'], ['Heure de sortie', 'heure_sortie'],
    ['Destination', 'destination'], ['Moyen de transport', 'moyen_transport'],
    ['Recherche personne', 'recherche_personne'], ['Personne à prévenir', 'personne_a_prevenir'],
    ['Tél. à prévenir', 'tel_personne_a_prevenir'], ['Difficultés', 'difficultes'],
    ['Compétences', 'competences'], ['Bagages', 'bagages'], ['Autres informations', 'autres_informations'],
    ['Type de fiche', 'type_fiche'], ['Espèce', 'animal_espece'], ['Détails animal', 'animal_details'],
    ['Synchronisation', '_sync'],
  ];
  function valueOf(fiche, key) {
    if (key === '_sync') return state(fiche);
    if (key === 'date_naissance') return dateOnly(fiche[key]);
    if (key === 'type_fiche') return fiche.est_animal ? 'Animal' : 'Humain';
    return text(fiche[key]);
  }
  function joinBytes(parts) {
    const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.length; }
    return result;
  }

  // OOXML files use ZIP's stored method. CRCs and byte lengths are calculated
  // from UTF-8 bytes, so accented text works with standard spreadsheet readers.
  const crcTable = Array.from({length: 256}, (_, index) => {
    let crc = index;
    for (let bit = 0; bit < 8; bit++) crc = (crc & 1) ? (0xedb88320 ^ (crc >>> 1)) : crc >>> 1;
    return crc >>> 0;
  });
  function crc32(bytes) {
    let crc = 0xffffffff;
    for (const byte of bytes) crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
  }
  function zip(files) {
    const parts = [], directory = [];
    let offset = 0, directorySize = 0;
    for (const [name, content] of files) {
      const nameBytes = encoder.encode(name), bytes = encoder.encode(content), crc = crc32(bytes);
      const local = new Uint8Array(30), localView = new DataView(local.buffer);
      localView.setUint32(0, 0x04034b50, true); localView.setUint16(4, 20, true);
      localView.setUint16(6, 0x0800, true); localView.setUint16(12, 0x21, true);
      localView.setUint32(14, crc, true); localView.setUint32(18, bytes.length, true);
      localView.setUint32(22, bytes.length, true); localView.setUint16(26, nameBytes.length, true);
      const central = new Uint8Array(46), centralView = new DataView(central.buffer);
      centralView.setUint32(0, 0x02014b50, true); centralView.setUint16(4, 20, true);
      centralView.setUint16(6, 20, true); centralView.setUint16(8, 0x0800, true);
      centralView.setUint16(14, 0x21, true); centralView.setUint32(16, crc, true);
      centralView.setUint32(20, bytes.length, true); centralView.setUint32(24, bytes.length, true);
      centralView.setUint16(28, nameBytes.length, true); centralView.setUint32(42, offset, true);
      parts.push(local, nameBytes, bytes); directory.push(central, nameBytes);
      offset += local.length + nameBytes.length + bytes.length;
      directorySize += central.length + nameBytes.length;
    }
    const end = new Uint8Array(22), view = new DataView(end.buffer);
    view.setUint32(0, 0x06054b50, true); view.setUint16(8, files.length, true);
    view.setUint16(10, files.length, true); view.setUint32(12, directorySize, true);
    view.setUint32(16, offset, true);
    return joinBytes([...parts, ...directory, end]);
  }
  function columnName(index) {
    let name = '';
    for (index++; index; index = Math.floor((index - 1) / 26)) name = String.fromCharCode(65 + (index - 1) % 26) + name;
    return name;
  }
  function worksheet(rows, options) {
    const header = options.header || 1, lastColumn = columnName(Math.max(...rows.map(row => row.length), 1) - 1);
    const cells = rows.map((row, index) => '<row r="' + (index + 1) + '">' + row.map((value, column) => {
      const style = index + 1 === header ? 1 : 0;
      // Every user value is an inline string, including strings starting with
      // =, +, -, or @. No formula element is ever created.
      return '<c r="' + columnName(column) + (index + 1) + '" t="inlineStr" s="' + style + '"><is><t xml:space="preserve">' + xml(value) + '</t></is></c>';
    }).join('') + '</row>').join('');
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
      '<dimension ref="A1:' + lastColumn + rows.length + '"/><sheetViews><sheetView workbookViewId="0"><pane ySplit="' + header + '" topLeftCell="A' + (header + 1) + '" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>' +
      '<sheetFormatPr defaultRowHeight="30"/><cols><col min="1" max="' + (ficheColumns.length + 1) + '" width="22" customWidth="1"/></cols><sheetData>' + cells + '</sheetData>' +
      (options.filter ? '<autoFilter ref="A' + header + ':' + lastColumn + rows.length + '"/>' : '') + '</worksheet>';
  }
  function eventXlsx(data, context) {
    const fiches = visible(data), event = eventData(data, context);
    const customLabels = new Map((event.settings.custom_fields || []).map(field => [field.key, field.label]));
    const customKeys = [...new Set([...customLabels.keys(), ...fiches.flatMap(fiche => Object.keys(fiche.custom_values || {}))])];
    const rows = [[...ficheColumns.map(column => column[0]), ...customKeys.map(key => customLabels.get(key) || key)],
      ...fiches.map(fiche => [...ficheColumns.map(column => valueOf(fiche, column[1])), ...customKeys.map(key => text(fiche.custom_values?.[key]))])];
    const summary = [['Export des fiches impliquées', 'Protection Civile'], ...eventRows(event),
      ['Total des fiches', fiches.length], ['Présents', fiches.filter(fiche => text(fiche.statut).toLocaleLowerCase('fr') === 'présent').length],
      ['Sortis', fiches.filter(fiche => text(fiche.statut).toLocaleLowerCase('fr') === 'sorti').length],
      ['Fiches avec modifications en attente', fiches.filter(fiche => fiche.pending || fiche.deletionPending).length]];
    const ns = 'http://schemas.openxmlformats.org/';
    return zip([
      ['[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'],
      ['_rels/.rels', '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="' + ns + 'package/2006/relationships"><Relationship Id="rId1" Type="' + ns + 'officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'],
      ['xl/workbook.xml', '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="' + ns + 'spreadsheetml/2006/main" xmlns:r="' + ns + 'officeDocument/2006/relationships"><sheets><sheet name="Fiches Impliqués" sheetId="1" r:id="rId1"/><sheet name="Évènement" sheetId="2" r:id="rId2"/></sheets></workbook>'],
      ['xl/_rels/workbook.xml.rels', '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="' + ns + 'package/2006/relationships"><Relationship Id="rId1" Type="' + ns + 'officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="' + ns + 'officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="' + ns + 'officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'],
      ['xl/styles.xml', '<?xml version="1.0" encoding="UTF-8"?><styleSheet xmlns="' + ns + 'spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF002F6C"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="49" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="49" fontId="1" fillId="2" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'],
      ['xl/worksheets/sheet1.xml', worksheet(rows, {header: 1, filter: true})],
      ['xl/worksheets/sheet2.xml', worksheet(summary, {header: 1})],
    ]);
  }

  // Standard PDF fonts support French accents through WinAnsiEncoding. A
  // ToUnicode map also makes accented names searchable and copyable in readers.
  const specialCodes = {'€': 128, '‚': 130, 'ƒ': 131, '„': 132, '…': 133, '†': 134, '‡': 135, 'ˆ': 136,
    '‰': 137, 'Š': 138, '‹': 139, 'Œ': 140, 'Ž': 142, '‘': 145, '’': 146, '“': 147, '”': 148,
    '•': 149, '–': 150, '—': 151, '˜': 152, '™': 153, 'š': 154, '›': 155, 'œ': 156, 'ž': 158, 'Ÿ': 159};
  const unicodeCodes = Object.fromEntries(Object.entries(specialCodes).map(([char, code]) => [code, char.charCodeAt(0)]));
  function pdfString(value) {
    let result = '';
    for (const char of clean(value).normalize('NFC')) {
      const point = char.codePointAt(0), code = specialCodes[char] || (point <= 255 ? point : 63);
      result += '\\' + code.toString(8).padStart(3, '0');
    }
    return '(' + result + ')';
  }
  const number = value => Number(value.toFixed(2));
  // Conservative widths keep wrapped text inside a cell, including uppercase
  // names, accented letters, wide W/M glyphs, and long unbroken identifiers.
  function glyphWidth(char, size) {
    if (' ilI.,:;!\'|'.includes(char)) return size * 0.30;
    if ('WMwm@%Œœ'.includes(char)) return size * 1.0;
    return size * (char === char.toUpperCase() ? 0.75 : 0.61);
  }
  function wrap(value, width, size) {
    const output = [];
    for (const paragraph of clean(value).replace(/\r\n?/g, '\n').replace(/\t/g, '    ').split('\n')) {
      if (!paragraph) { output.push(''); continue; }
      let line = '', used = 0;
      for (const char of paragraph) {
        const measured = glyphWidth(char, size);
        if (line && used + measured > width) { output.push(line); line = ''; used = 0; }
        line += char; used += measured;
      }
      output.push(line);
    }
    return output.length ? output : [''];
  }
  function pdfDocument(width, height, title) {
    const pages = [];
    let commands, y;
    const margin = 28, lineHeight = 11;
    function drawText(value, x, top, size, bold, color) {
      commands.push((color || '0.04 0.12 0.23') + ' rg BT /' + (bold ? 'F2' : 'F1') + ' ' + size + ' Tf 1 0 0 1 ' + number(x) + ' ' + number(height - top) + ' Tm ' + pdfString(value) + ' Tj ET');
    }
    function line(x1, top, x2) { commands.push('0.8 0.84 0.88 RG 0.4 w ' + number(x1) + ' ' + number(height - top) + ' m ' + number(x2) + ' ' + number(height - top) + ' l S'); }
    function newPage() {
      commands = []; pages.push(commands); y = margin + 16;
      drawText(title, margin, y, 15, true, '0 0.18 0.42'); y += 23;
    }
    function heading(value) {
      if (y + 40 > height - 36) newPage();
      y += 7; drawText(value, margin, y, 11, true, '0.75 0.32 0'); y += 18;
    }
    function table(headers, rows, widths, size) {
      const totalWidth = widths.reduce((sum, column) => sum + column, 0), availableWidth = width - margin * 2;
      if (totalWidth > availableWidth) widths = widths.map(column => column * availableWidth / totalWidth);
      const padding = 4, step = size + 3;
      function header() {
        const lines = headers.map((value, index) => wrap(value, widths[index] - padding * 2, size));
        const headerHeight = Math.max(...lines.map(value => value.length)) * step + 8;
        let x = margin;
        for (let column = 0; column < headers.length; column++) {
          for (let row = 0; row < lines[column].length; row++) drawText(lines[column][row], x + padding, y + size + row * step, size, true);
          x += widths[column];
        }
        y += headerHeight; line(margin, y, margin + widths.reduce((a, b) => a + b, 0));
      }
      if (headers) {
        if (y + 60 > height - 36) newPage();
        header();
      }
      for (const row of rows) {
        const lines = widths.map((width, index) => wrap(row[index], width - padding * 2, size));
        const count = Math.max(...lines.map(value => value.length));
        let position = 0;
        while (position < count) {
          let available = Math.floor((height - 38 - y - 8) / step);
          if (available < 1) { newPage(); if (headers) header(); available = Math.floor((height - 38 - y - 8) / step); }
          const take = Math.min(count - position, available);
          let x = margin;
          for (let column = 0; column < widths.length; column++) {
            for (let index = 0; index < take; index++) {
              if (position + index < lines[column].length) drawText(lines[column][position + index], x + padding, y + size + index * step + 4, size, false);
            }
            x += widths[column];
          }
          y += take * step + 8; line(margin, y, x); position += take;
        }
      }
      y += 8;
    }
    function finish() {
      pages.forEach((page, index) => {
        commands = page;
        drawText('Protection Civile · ' + (index + 1) + ' / ' + pages.length, margin, height - 18, 8, false);
      });
      const map = [];
      for (let code = 32; code < 256; code++) map.push('<' + code.toString(16).padStart(2, '0') + '> <' + (unicodeCodes[code] || code).toString(16).padStart(4, '0') + '>');
      const mapping = '/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /CAIWinAnsi def\n/CMapType 2 def\n1 begincodespacerange\n<00> <ff>\nendcodespacerange\n' +
        [map.slice(0, 100), map.slice(100, 200), map.slice(200)].map(group => group.length + ' beginbfchar\n' + group.join('\n') + '\nendbfchar\n').join('') + 'endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend';
      const stream = value => '<< /Length ' + encoder.encode(value).length + ' >>\nstream\n' + value + '\nendstream';
      const objects = [null, '<< /Type /Catalog /Pages 2 0 R >>', '',
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding /ToUnicode 5 0 R >>',
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding /ToUnicode 5 0 R >>', stream(mapping)];
      const pageIds = [];
      for (const page of pages) {
        const pageId = objects.length, contentId = pageId + 1; pageIds.push(pageId);
        objects.push('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' + width + ' ' + height + '] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ' + contentId + ' 0 R >>');
        objects.push(stream(page.join('\n')));
      }
      objects[2] = '<< /Type /Pages /Count ' + pages.length + ' /Kids [' + pageIds.map(id => id + ' 0 R').join(' ') + '] >>';
      const parts = [encoder.encode('%PDF-1.4\n%CAI offline export\n')], offsets = [0];
      let length = parts[0].length;
      for (let id = 1; id < objects.length; id++) {
        offsets[id] = length;
        const bytes = encoder.encode(id + ' 0 obj\n' + objects[id] + '\nendobj\n'); parts.push(bytes); length += bytes.length;
      }
      parts.push(encoder.encode('xref\n0 ' + objects.length + '\n0000000000 65535 f \n' + offsets.slice(1).map(offset => String(offset).padStart(10, '0') + ' 00000 n \n').join('') + 'trailer\n<< /Size ' + objects.length + ' /Root 1 0 R >>\nstartxref\n' + length + '\n%%EOF\n'));
      return joinBytes(parts);
    }
    newPage();
    return {heading, table, finish, lineHeight};
  }
  function eventPdf(data, context) {
    const event = eventData(data, context), fiches = visible(data), pdf = pdfDocument(841.89, 595.28, 'Fiches impliquées — Évènement');
    pdf.table(null, eventRows(event), [110, 675], 9);
    pdf.heading('Liste des fiches impliquées (' + fiches.length + ')');
    const columns = [['Numéro', 'numero'], ['Nom', 'nom'], ['Prénom', 'prenom'], ['Naissance', 'date_naissance'],
      ['Statut', 'statut'], ['Téléphone', 'telephone'], ['Adresse', 'adresse'], ['Compétences', 'competences'],
      ['Destination', 'destination'], ['Bagages', 'bagages']];
    pdf.table(columns.map(column => column[0]), fiches.map(fiche => columns.map(column =>
      column[1] === 'statut' && (fiche.pending || fiche.deletionPending) ? valueOf(fiche, column[1]) + ' (' + state(fiche) + ')' : valueOf(fiche, column[1]))),
    [60, 70, 65, 58, 70, 66, 112, 98, 100, 86], 7);
    return pdf.finish();
  }
  function fichePdf(fiche, data, context) {
    const event = eventData(data, context), pdf = pdfDocument(595.28, 841.89, 'Fiche impliqué — ' + (fiche.numero || fiche.id || ''));
    function section(title, rows) { pdf.heading(title); pdf.table(null, rows, [156, 383], 9); }
    section('Informations personnelles', [['Numéro', fiche.numero], ['Type de fiche', fiche.est_animal ? 'Animal' : 'Humain'],
      ['Nom', fiche.nom], ['Prénom', fiche.prenom], ['Date de naissance', dateOnly(fiche.date_naissance)],
      ['Adresse', fiche.adresse], ['Téléphone', fiche.telephone]]);
    section('Coordonnées et contact', [['Personne à prévenir', fiche.personne_a_prevenir], ['Téléphone de la personne à prévenir', fiche.tel_personne_a_prevenir]]);
    section('Suivi opérationnel', [['Statut', fiche.statut], ['Synchronisation', state(fiche)], ['Heure d’arrivée', fiche.heure_arrivee],
      ['Heure de sortie', fiche.heure_sortie], ['Destination', fiche.destination], ['Moyen de transport', fiche.moyen_transport]]);
    section('Informations complémentaires', [['Code Sinus', fiche.code_sinus], ['Recherche une personne', fiche.recherche_personne],
      ['Difficultés', fiche.difficultes], ['Compétences', fiche.competences],
      ['Bagages', text(fiche.bagages) || 'Aucun'], ['Autres informations', fiche.autres_informations]]);
    if (fiche.est_animal) section('Animal', [['Espèce', fiche.animal_espece], ['Référent', fiche.referent?.label || fiche.referent_id], ['Détails', fiche.animal_details]]);
    const custom = Object.entries(fiche.custom_values || {});
    if (custom.length) {
      const labels = new Map((event.settings?.custom_fields || []).map(field => [String(field.id || field.key), field.label || field.name]));
      section('Champs complémentaires', custom.map(([key, value]) => [labels.get(key) || key, value]));
    }
    section('Évènement associé', eventRows(event));
    if (fiche.timeline?.length) section('Historique récent', fiche.timeline.map(entry => [entry.created_at || '',
      (entry.user ? entry.user + ' — ' : '') + text(entry.content) + (entry.pending ? ' (En attente de synchronisation)' : '')]));
    return pdf.finish();
  }
  function download(bytes, filename, mimetype) {
    const blob = bytes instanceof Blob ? bytes : new Blob([bytes], {type: mimetype});
    const url = URL.createObjectURL(blob), anchor = document.createElement('a');
    anchor.href = url; anchor.download = text(filename).replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_');
    document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
  global.CAIExports = {eventPdf, eventXlsx, eventExcel: eventXlsx, fichePdf, download, MIME_PDF, MIME_EXCEL};
})(globalThis);
