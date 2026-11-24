/**
 * Security-Hardened Pure-JS OpenXML `.xlsx` Workbook Builder (`xlsx-writer.mjs`).
 *
 * Guarantees:
 * 1. Valid XML 1.0 character sanitization via `escapeXmlText` (zero `\x00-\x08\x0b\x0c\x0e-\x1f` crashes in Excel or openpyxl).
 * 2. User/header string cells ALWAYS use `t="inlineStr"` (`<is><t xml:space="preserve">...</t></is>`), NEVER `<f>`,
 *    so user text beginning with `=`, `===`, `+`, `-`, `@`, or `=CMD|...` is strictly stored with `data_type == "s"`
 *    and NEVER triggers Excel workbook repair dialogs or DDE execution.
 * 3. Only DocuClean/LedgerClean's own optional summary rows (`SUM` / `AVERAGE`) emit `<f>` cells.
 */

import { cleanCellText, escapeXmlText } from './sanitize.mjs';

const CURRENCY_RE =
  /^\s*(\()?\s*([¥￥$€£]|RMB|CNY|USD|EUR|GBP)?\s*([+-])?\s*(\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)\s*(\))?\s*$/i;
const PERCENT_RE = /^\s*([+-]?\d+(?:,\d{3})*(?:\.\d+)?)\s*%\s*$/;
const CN_DATE_RE = /^\s*(\d{4})\s*[年/.-]\s*(\d{1,2})\s*[月/.-]\s*(\d{1,2})\s*日?\s*$/;
const ID_HEADER_RE =
  /(?:^id$|编号|单号|发票号|税号|序号|年份|year|code|邮编|电话|order|invoice|reference|account)/i;

const CRC_TABLE = (() => {
  const tbl = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    tbl[i] = c >>> 0;
  }
  return tbl;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function buildZipArchive(entries) {
  const enc = new TextEncoder();
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBytes = enc.encode(entry.name);
    const dataBytes =
      entry.data instanceof Uint8Array ? entry.data : enc.encode(String(entry.data));
    const crc = crc32(dataBytes);
    const size = dataBytes.length;

    const localHeader = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(localHeader.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0x0800, true);
    lv.setUint16(8, 0, true);
    lv.setUint16(10, 0, true);
    lv.setUint16(12, 0x5721, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, size, true);
    lv.setUint32(22, size, true);
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true);
    localHeader.set(nameBytes, 30);

    localParts.push(localHeader, dataBytes);

    const centralHeader = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(centralHeader.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0x0800, true);
    cv.setUint16(10, 0, true);
    cv.setUint16(12, 0, true);
    cv.setUint16(14, 0x5721, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, size, true);
    cv.setUint32(24, size, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint16(30, 0, true);
    cv.setUint16(32, 0, true);
    cv.setUint16(34, 0, true);
    cv.setUint16(36, 0, true);
    cv.setUint32(38, 0, true);
    cv.setUint32(42, offset, true);
    centralHeader.set(nameBytes, 46);
    centralParts.push(centralHeader);

    offset += localHeader.length + dataBytes.length;
  }

  const centralSize = centralParts.reduce((s, p) => s + p.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(4, 0, true);
  ev.setUint16(6, 0, true);
  ev.setUint16(8, entries.length, true);
  ev.setUint16(10, entries.length, true);
  ev.setUint32(12, centralSize, true);
  ev.setUint32(16, offset, true);
  ev.setUint16(20, 0, true);

  const totalLen = offset + centralSize + 22;
  const out = new Uint8Array(totalLen);
  let pos = 0;
  for (const p of localParts) {
    out.set(p, pos);
    pos += p.length;
  }
  for (const p of centralParts) {
    out.set(p, pos);
    pos += p.length;
  }
  out.set(eocd, pos);
  return out;
}

function colLetter(colIdx1) {
  let n = colIdx1;
  let s = '';
  while (n > 0) {
    const rem = (n - 1) % 26;
    s = String.fromCharCode(65 + rem) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

function displayWidth(str) {
  const s = String(str ?? '');
  let w = 0;
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    w += cp > 0x2e80 ? 2.1 : 1.0;
  }
  return w;
}

export function classifyCellForXlsx(raw, { forceText = false } = {}) {
  if (raw === null || raw === undefined) {
    return { value: '', kind: 'text', styleIdx: 1 };
  }
  if (!forceText && typeof raw === 'number' && Number.isFinite(raw)) {
    return {
      value: raw,
      kind: Number.isInteger(raw) ? 'integer' : 'decimal',
      styleIdx: Number.isInteger(raw) ? 2 : 3,
    };
  }
  const s = cleanCellText(raw);
  if (!s || s === '-' || s === '—' || s === 'null' || s === 'None') {
    return { value: s === 'null' || s === 'None' ? '' : s, kind: 'text', styleIdx: 1 };
  }
  // Never auto-convert leading-zero codes, 11+ digit IDs, or forced-text ID columns to numbers
  if (forceText || /^0\d+$/.test(s) || /^\d{11,}$/.test(s)) {
    return { value: s, kind: 'text', styleIdx: 1 };
  }
  // Explicitly keep any user cell starting with `=` or `@` as a plain literal string (`inlineStr`)
  if (/^[=@]/.test(s)) {
    return { value: s, kind: 'text', styleIdx: 1 };
  }

  const mPct = PERCENT_RE.exec(s);
  if (mPct) {
    const num = Number(mPct[1].replace(/,/g, ''));
    if (Number.isFinite(num)) {
      return { value: num / 100, kind: 'percent', styleIdx: 5 };
    }
  }

  const mCur = CURRENCY_RE.exec(s);
  if (mCur) {
    const hasOpen = Boolean(mCur[1]);
    const hasClose = Boolean(mCur[5]);
    if (hasOpen === hasClose) {
      const sign = mCur[3] === '-' || (hasOpen && hasClose) ? -1 : 1;
      const numStr = mCur[4].replace(/,/g, '');
      const num = Number(numStr) * sign;
      if (Number.isFinite(num)) {
        const sym = (mCur[2] || '').toUpperCase();
        if (sym) {
          return { value: num, kind: 'currency', styleIdx: 4 };
        }
        const isInt = !numStr.includes('.');
        return { value: num, kind: isInt ? 'integer' : 'decimal', styleIdx: isInt ? 2 : 3 };
      }
    }
  }

  const mDate = CN_DATE_RE.exec(s);
  if (mDate) {
    const yr = Number(mDate[1]);
    const mo = String(Number(mDate[2])).padStart(2, '0');
    const dy = String(Number(mDate[3])).padStart(2, '0');
    return { value: `${yr}-${mo}-${dy}`, kind: 'date', styleIdx: 1 };
  }

  return { value: s, kind: 'text', styleIdx: 1 };
}

/**
 * Builds a complete multi-sheet OpenXML `.xlsx` binary (`Uint8Array`).
 * Each table in `tables` has `{ name, headers, rows, forceTextCols?: Set<number>, injectFormulas?: boolean }`.
 */
export function buildWorkbookXlsxBytes(tables, { injectFormulas = true } = {}) {
  const effective =
    Array.isArray(tables) && tables.length > 0
      ? tables
      : [{ name: 'Sheet1', headers: ['Column_1'], rows: [['']] }];

  const usedNames = new Set();
  const safeSheetName = (raw, idx) => {
    const cleaned = (
      cleanCellText(raw)
        .replace(/[\[\]:*?/\\']/g, '_')
        .trim() || `Sheet${idx}`
    ).slice(0, 28);
    let cand = cleaned;
    let n = 2;
    while (usedNames.has(cand.toLowerCase())) {
      const suf = `_${n++}`;
      cand = `${cleaned.slice(0, 31 - suf.length)}${suf}`;
    }
    usedNames.add(cand.toLowerCase());
    return cand;
  };

  const stylesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <numFmts count="2">
    <numFmt numFmtId="164" formatCode="&quot;¥&quot;#,##0.00;[Red]-&quot;¥&quot;#,##0.00"/>
    <numFmt numFmtId="165" formatCode="#,##0.00"/>
  </numFmts>
  <fonts count="3">
    <font><sz val="10"/><color rgb="FF111827"/><name val="Microsoft YaHei"/></font>
    <font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Microsoft YaHei"/></font>
    <font><b/><sz val="10"/><color rgb="FF0F172A"/><name val="Microsoft YaHei"/></font>
  </fonts>
  <fills count="4">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF1E3A5F"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFE2E8F0"/></patternFill></fill>
  </fills>
  <borders count="2">
    <border><left/><right/><top/><bottom/><diagonal/></border>
    <border>
      <left style="thin"><color rgb="FFCBD5E1"/></left>
      <right style="thin"><color rgb="FFCBD5E1"/></right>
      <top style="thin"><color rgb="FFCBD5E1"/></top>
      <bottom style="thin"><color rgb="FFCBD5E1"/></bottom>
      <diagonal/>
    </border>
  </borders>
  <cellStyleXfs count="1">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>
  </cellStyleXfs>
  <cellXfs count="10">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"/>
    <xf numFmtId="3" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"/>
    <xf numFmtId="165" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"/>
    <xf numFmtId="164" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"/>
    <xf numFmtId="10" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>
    <xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
    <xf numFmtId="165" fontId="2" fillId="3" borderId="1" xfId="0" applyNumberFormat="1" applyFont="1" applyFill="1" applyBorder="1"/>
    <xf numFmtId="10" fontId="2" fillId="3" borderId="1" xfId="0" applyNumberFormat="1" applyFont="1" applyFill="1" applyBorder="1"/>
  </cellXfs>
  <cellStyles count="1">
    <cellStyle name="Normal" xfId="0" builtinId="0"/>
  </cellStyles>
</styleSheet>`;

  const sheetFiles = [];
  const sheetNames = [];

  effective.forEach((tbl, idx) => {
    const sName = safeSheetName(tbl.name, idx + 1);
    sheetNames.push(sName);
    const headers = tbl.headers?.length ? tbl.headers : ['Column_1'];
    const rows = Array.isArray(tbl.rows) ? tbl.rows : [];
    const ncols = headers.length;
    const nrows = rows.length;
    const forceTextCols = tbl.forceTextCols instanceof Set ? tbl.forceTextCols : new Set();

    const widths = headers.map((h) => Math.max(10, displayWidth(h) + 4));
    const colNumCounts = new Array(ncols).fill(0);
    const colNonEmpty = new Array(ncols).fill(0);
    const colPctCounts = new Array(ncols).fill(0);

    const rowXmlList = [];
    const hdrCells = headers.map((h, c0) => {
      const ref = `${colLetter(c0 + 1)}1`;
      return `<c r="${ref}" t="inlineStr" s="6"><is><t xml:space="preserve">${escapeXmlText(cleanCellText(h))}</t></is></c>`;
    });
    rowXmlList.push(`<row r="1" ht="25" customHeight="1">${hdrCells.join('')}</row>`);

    rows.forEach((r, r0) => {
      const rNum = r0 + 2;
      const cells = [];
      for (let c0 = 0; c0 < ncols; c0++) {
        const rawVal = r[c0] ?? '';
        const forceText = forceTextCols.has(c0) || ID_HEADER_RE.test(headers[c0] || '');
        const typed = classifyCellForXlsx(rawVal, { forceText });
        const ref = `${colLetter(c0 + 1)}${rNum}`;
        widths[c0] = Math.max(widths[c0], Math.min(56, displayWidth(String(typed.value)) + 3.5));

        if (typed.value !== '') colNonEmpty[c0]++;
        if (typeof typed.value === 'number' && Number.isFinite(typed.value)) {
          colNumCounts[c0]++;
          if (typed.kind === 'percent') colPctCounts[c0]++;
          cells.push(`<c r="${ref}" s="${typed.styleIdx}"><v>${typed.value}</v></c>`);
        } else {
          cells.push(
            `<c r="${ref}" t="inlineStr" s="1"><is><t xml:space="preserve">${escapeXmlText(typed.value)}</t></is></c>`,
          );
        }
      }
      rowXmlList.push(`<row r="${rNum}" ht="20" customHeight="1">${cells.join('')}</row>`);
    });

    const allowSheetFormulas =
      tbl.injectFormulas !== undefined ? Boolean(tbl.injectFormulas) : injectFormulas;
    const numericCols = [];
    for (let c0 = 0; c0 < ncols; c0++) {
      if (
        colNumCounts[c0] >= 2 &&
        colNumCounts[c0] >= 0.5 * Math.max(1, colNonEmpty[c0]) &&
        !ID_HEADER_RE.test(headers[c0] || '') &&
        !forceTextCols.has(c0)
      ) {
        numericCols.push(c0);
      }
    }

    if (allowSheetFormulas && nrows >= 2 && numericCols.length > 0) {
      for (const [offset, label, fnName] of [
        [2, '合计 (SUM)', 'SUM'],
        [3, '均值 (AVG)', 'AVERAGE'],
      ]) {
        const rNum = nrows + offset;
        const fCells = [];
        for (let c0 = 0; c0 < ncols; c0++) {
          const ref = `${colLetter(c0 + 1)}${rNum}`;
          if (c0 === 0 && !numericCols.includes(0)) {
            fCells.push(
              `<c r="${ref}" t="inlineStr" s="7"><is><t xml:space="preserve">${escapeXmlText(label)}</t></is></c>`,
            );
          } else if (numericCols.includes(c0)) {
            const isPct = colPctCounts[c0] > colNumCounts[c0] / 2;
            if (fnName === 'SUM' && isPct) {
              fCells.push(`<c r="${ref}" t="inlineStr" s="7"><is><t>-</t></is></c>`);
            } else {
              const colL = colLetter(c0 + 1);
              const sIdx = isPct ? 9 : 8;
              fCells.push(
                `<c r="${ref}" s="${sIdx}"><f>${fnName}(${colL}2:${colL}${nrows + 1})</f></c>`,
              );
            }
          } else {
            fCells.push(`<c r="${ref}" t="inlineStr" s="7"><is><t></t></is></c>`);
          }
        }
        rowXmlList.push(`<row r="${rNum}" ht="22" customHeight="1">${fCells.join('')}</row>`);
      }
    }

    const colsXml = widths
      .map(
        (w, c0) =>
          `<col min="${c0 + 1}" max="${c0 + 1}" width="${w.toFixed(1)}" customWidth="1"/>`,
      )
      .join('');
    const lastDataRow = Math.max(1, nrows + 1);
    const filterRef = `A1:${colLetter(ncols)}${lastDataRow}`;

    const sheetXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetViews>
    <sheetView workbookViewId="0">
      <pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>
    </sheetView>
  </sheetViews>
  <cols>${colsXml}</cols>
  <sheetData>${rowXmlList.join('')}</sheetData>
  <autoFilter ref="${filterRef}"/>
</worksheet>`;

    sheetFiles.push({ name: `xl/worksheets/sheet${idx + 1}.xml`, data: sheetXml });
  });

  const wbSheetsXml = sheetNames
    .map(
      (n, idx) =>
        `<sheet name="${escapeXmlText(n)}" sheetId="${idx + 1}" r:id="rId${idx + 1}"/>`,
    )
    .join('');

  const workbookXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>${wbSheetsXml}</sheets>
</workbook>`;

  const wbRelsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  ${sheetNames
    .map(
      (_, idx) =>
        `<Relationship Id="rId${idx + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${idx + 1}.xml"/>`,
    )
    .join('')}
  <Relationship Id="rId${sheetNames.length + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`;

  const contentTypesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  ${sheetNames
    .map(
      (_, idx) =>
        `<Override PartName="/xl/worksheets/sheet${idx + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`,
    )
    .join('')}
</Types>`;

  const rootRelsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`;

  return buildZipArchive([
    { name: '[Content_Types].xml', data: contentTypesXml },
    { name: '_rels/.rels', data: rootRelsXml },
    { name: 'xl/workbook.xml', data: workbookXml },
    { name: 'xl/_rels/workbook.xml.rels', data: wbRelsXml },
    { name: 'xl/styles.xml', data: stylesXml },
    ...sheetFiles,
  ]);
}
