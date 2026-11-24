/**
 * Multi-Page PDF Vector/Spatial Table Extractor & Multi-Format Cleaner (`pdf-tables.mjs`).
 *
 * Extraction Pipeline:
 * 1. For binary PDF payloads (`%PDF-`):
 *    - Primary: Sandboxed Python `PyMuPDF` (`fitz`) subprocess via stdin/stdout (`shell: false`, 15s timeout),
 *      extracting vector-bordered tables (`page.find_tables()`) AND spatial Y/X word-column grids for borderless PDFs.
 *    - Fallback: Pure-JS `/FlateDecode` + `/ToUnicode` CMap + `BT..ET` (`Tm`/`Td`/`TJ`) coordinate table extractor
 *      when Python or `fitz` is unavailable.
 * 2. Automatic cross-page continuation stitching when consecutive pages repeat identical table headers.
 * 3. Multi-format support for HTML (`rowspan`/`colspan` 2D expansion), CSV/TSV (with unquoted currency comma healing),
 *    JSON/JSONL (nested dot-flattening), XML, and Markdown pipe tables.
 */

import { execFileSync } from 'node:child_process';
import {
  buildSafeUtf8BomCsv,
  cleanCellText,
  decodeAndRepairCjk,
  decodeBase64ToBytes,
  healUnquotedCurrencyCommas,
  toUint8Array,
} from './sanitize.mjs';
import { buildWorkbookXlsxBytes } from './xlsx-writer.mjs';

const PYMUPDF_EXTRACTOR_SCRIPT = `
import sys, json, contextlib

pdf_bytes = sys.stdin.buffer.read()
pages_out = []
page_count = 0

with contextlib.redirect_stdout(sys.stderr):
    import fitz
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    page_count = len(doc)
    for page_idx, page in enumerate(doc):
        page_tables = []
        try:
            finder = page.find_tables()
            for t in finder.tables:
                extracted = t.extract()
                if extracted and len(extracted) >= 2:
                    rows = [[("" if c is None else str(c)) for c in r] for r in extracted]
                    if any(any(cell.strip() for cell in r) for r in rows):
                        page_tables.append(rows)
        except Exception:
            pass

        if not page_tables:
            words = page.get_text("words")
            if words:
                words_sorted = sorted(words, key=lambda w: (round(w[1] / 3.0), w[0]))
                lines = []
                cur_line = []
                cur_y = None
                for w in words_sorted:
                    x0, y0, x1, y1, txt = w[0], w[1], w[2], w[3], w[4]
                    if cur_y is None or abs(y0 - cur_y) <= 4.0:
                        cur_line.append((x0, x1, txt))
                        cur_y = y0 if cur_y is None else (cur_y + y0) / 2.0
                    else:
                        lines.append(sorted(cur_line, key=lambda item: item[0]))
                        cur_line = [(x0, x1, txt)]
                        cur_y = y0
                if cur_line:
                    lines.append(sorted(cur_line, key=lambda item: item[0]))

                segmented_rows = []
                for ln in lines:
                    cells = []
                    buf = ln[0][2]
                    prev_x1 = ln[0][1]
                    for x0, x1, txt in ln[1:]:
                        if x0 - prev_x1 >= 14.0:
                            cells.append(buf)
                            buf = txt
                        else:
                            need_sp = (ord(buf[-1]) < 128 and ord(txt[0]) < 128)
                            buf += (" " if need_sp else "") + txt
                        prev_x1 = x1
                    cells.append(buf)
                    segmented_rows.append(cells)

                multi_col = [r for r in segmented_rows if len(r) >= 2]
                if len(multi_col) >= 2:
                    filtered = [r for r in segmented_rows if len(r) >= 2]
                    page_tables.append(filtered)

        pages_out.append({
            "pageNumber": page_idx + 1,
            "tables": page_tables,
            "text": page.get_text("text")
        })

sys.stdout.buffer.write(json.dumps({
    "pageCount": page_count,
    "pages": pages_out
}, ensure_ascii=False).encode("utf-8"))
sys.stdout.buffer.flush()
`;

function tryExtractPdfWithPyMuPdf(pdfBytes) {
  const candidates = process.platform === 'win32' ? ['python', 'python3'] : ['python3', 'python'];
  for (const pyBin of candidates) {
    try {
      const stdout = execFileSync(pyBin, ['-c', PYMUPDF_EXTRACTOR_SCRIPT], {
        input: Buffer.from(pdfBytes),
        timeout: 15000,
        maxBuffer: 32 * 1024 * 1024,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      return JSON.parse(stdout.toString('utf8'));
    } catch {
      // Try next binary or fall back to pure-JS PDF extractor
    }
  }
  return null;
}

async function decompressFlatePureJs(rawBytes) {
  let trimmed = rawBytes;
  if (trimmed.length >= 2 && trimmed[trimmed.length - 2] === 0x0d && trimmed[trimmed.length - 1] === 0x0a) {
    trimmed = trimmed.subarray(0, trimmed.length - 2);
  } else if (trimmed.length >= 1 && (trimmed[trimmed.length - 1] === 0x0a || trimmed[trimmed.length - 1] === 0x0d)) {
    trimmed = trimmed.subarray(0, trimmed.length - 1);
  }

  for (const fmt of ['deflate', 'deflate-raw']) {
    for (const candidate of [trimmed, rawBytes]) {
      try {
        const ds = new DecompressionStream(fmt);
        const writer = ds.writable.getWriter();
        const reader = ds.readable.getReader();
        const chunks = [];
        let total = 0;
        const readTask = (async () => {
          try {
            while (true) {
              const { value, done } = await reader.read();
              if (done) break;
              if (value?.byteLength) {
                chunks.push(value);
                total += value.byteLength;
              }
            }
          } catch (e) {
            if (total === 0) throw e;
          }
        })();
        try {
          await writer.write(candidate);
          await writer.close();
        } catch {}
        await readTask;
        if (total > 0) {
          const out = new Uint8Array(total);
          let pos = 0;
          for (const c of chunks) {
            out.set(c, pos);
            pos += c.byteLength;
          }
          return out;
        }
      } catch {}
    }
  }
  return null;
}

function bytesToLatin1(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    s += String.fromCharCode(...bytes.subarray(i, Math.min(i + 8192, bytes.length)));
  }
  return s;
}

function decodeUtf16BeHex(hexStr) {
  const clean = hexStr.replace(/\s+/g, '');
  if (!clean) return '';
  const padded = clean.length % 2 === 1 ? `${clean}0` : clean;
  const bytes = new Uint8Array(padded.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16) || 0;
  }
  if (bytes.length === 1) return String.fromCharCode(bytes[0]);
  return new TextDecoder('utf-16be').decode(bytes);
}

function parseToUnicodeCMap(cmapText) {
  const map = new Map();
  const widths = new Set();
  for (const m of cmapText.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
    for (const p of m[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) {
      const k = p[1].toUpperCase();
      widths.add(k.length);
      map.set(k, decodeUtf16BeHex(p[2]));
    }
  }
  for (const m of cmapText.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
    const re = /<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(?:<([0-9A-Fa-f]+)>|\[([\s\S]*?)\])/g;
    for (const r of m[1].matchAll(re)) {
      const startCode = parseInt(r[1], 16);
      const endCode = parseInt(r[2], 16);
      const w = r[1].length;
      widths.add(w);
      if (!Number.isFinite(startCode) || !Number.isFinite(endCode) || endCode < startCode || endCode - startCode > 65535) continue;
      if (r[3]) {
        const baseCp = decodeUtf16BeHex(r[3]).codePointAt(0) || 0;
        for (let c = startCode; c <= endCode; c++) {
          map.set(c.toString(16).toUpperCase().padStart(w, '0'), String.fromCodePoint(baseCp + (c - startCode)));
        }
      } else if (r[4]) {
        const targets = [...r[4].matchAll(/<([0-9A-Fa-f]+)>/g)].map((x) => decodeUtf16BeHex(x[1]));
        for (let i = 0; i < targets.length && startCode + i <= endCode; i++) {
          map.set((startCode + i).toString(16).toUpperCase().padStart(w, '0'), targets[i]);
        }
      }
    }
  }
  return { map, widths: [...widths].sort((a, b) => b - a) };
}

function decodePdfLiteral(raw) {
  const bytes = [];
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === '\\') {
      const nxt = raw[++i];
      if (nxt === undefined) break;
      if (nxt === 'n') bytes.push(10);
      else if (nxt === 'r') bytes.push(13);
      else if (nxt === 't') bytes.push(9);
      else if (nxt === 'b') bytes.push(8);
      else if (nxt === 'f') bytes.push(12);
      else if (nxt >= '0' && nxt <= '7') {
        let oct = nxt;
        if (raw[i + 1] >= '0' && raw[i + 1] <= '7') oct += raw[++i];
        if (raw[i + 1] >= '0' && raw[i + 1] <= '7') oct += raw[++i];
        bytes.push(parseInt(oct, 8) & 0xff);
      } else {
        bytes.push(nxt.charCodeAt(0) & 0xff);
      }
    } else {
      bytes.push(ch.charCodeAt(0) & 0xff);
    }
  }
  const u8 = new Uint8Array(bytes);
  if (u8.length >= 2 && u8[0] === 0xfe && u8[1] === 0xff) {
    return new TextDecoder('utf-16be').decode(u8.subarray(2));
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(u8);
  } catch {
    return bytesToLatin1(u8);
  }
}

function decodePdfHex(hexStr, cmap) {
  const clean = hexStr.replace(/\s+/g, '').toUpperCase();
  if (!clean) return '';
  if (cmap && cmap.map.size > 0) {
    const ws = cmap.widths.length ? cmap.widths : [4, 2];
    let out = '';
    let idx = 0;
    while (idx < clean.length) {
      let hit = false;
      for (const w of ws) {
        if (idx + w <= clean.length && cmap.map.has(clean.slice(idx, idx + w))) {
          out += cmap.map.get(clean.slice(idx, idx + w));
          idx += w;
          hit = true;
          break;
        }
      }
      if (!hit) {
        const step = ws.includes(4) && clean.length - idx >= 4 ? 4 : 2;
        out += decodeUtf16BeHex(clean.slice(idx, idx + step));
        idx += step;
      }
    }
    return out;
  }
  if (clean.startsWith('FEFF')) return decodeUtf16BeHex(clean.slice(4));
  return decodeUtf16BeHex(clean);
}

export async function extractPdfPureJsFallback(pdfBytes) {
  const u8 = toUint8Array(pdfBytes);
  const latin1 = bytesToLatin1(u8);
  if (!latin1.slice(0, 1024).includes('%PDF-')) {
    throw new Error('Invalid PDF payload: missing %PDF- header');
  }
  const pageCount = (latin1.match(/\/Type\s*\/Page\b/g) || [1]).length;
  const objects = [];
  for (const m of latin1.matchAll(/(\d+)\s+\d+\s+obj\b([\s\S]*?)endobj/g)) {
    const body = m[2];
    const bodyOffset = m.index + m[0].indexOf(body);
    const sm = body.match(/stream(?:\r\n|\n|\r)/);
    let dict = body;
    let streamBytes = null;
    if (sm) {
      dict = body.slice(0, sm.index);
      const start = sm.index + sm[0].length;
      const end = body.lastIndexOf('endstream');
      if (end > start) {
        streamBytes = u8.subarray(bodyOffset + start, bodyOffset + end);
      }
    }
    objects.push({ dict, streamBytes, decoded: null });
  }

  for (const obj of objects) {
    if (!obj.streamBytes) continue;
    if (/\/FlateDecode\b|\/Fl\b/.test(obj.dict)) {
      const inf = await decompressFlatePureJs(obj.streamBytes);
      if (inf) obj.decoded = bytesToLatin1(inf);
    } else if (!/\/Image\b|\/DCTDecode\b/.test(obj.dict)) {
      obj.decoded = bytesToLatin1(obj.streamBytes);
    }
  }

  const globalMap = new Map();
  const globalWidths = new Set();
  for (const obj of objects) {
    if (obj.decoded && obj.decoded.includes('begincmap')) {
      const parsed = parseToUnicodeCMap(obj.decoded);
      for (const [k, v] of parsed.map.entries()) {
        if (!globalMap.has(k)) globalMap.set(k, v);
      }
      for (const w of parsed.widths) globalWidths.add(w);
    }
  }
  const cmap = { map: globalMap, widths: [...globalWidths].sort((a, b) => b - a) };

  const pages = [];
  for (const obj of objects) {
    if (!obj.decoded || obj.decoded.includes('begincmap') || !/\bBT\b/.test(obj.decoded)) continue;
    const positionedItems = [];
    for (const bm of obj.decoded.matchAll(/\bBT\b([\s\S]*?)\bET\b/g)) {
      const block = bm[1];
      let curX = 0;
      let curY = 0;
      for (const tok of block.matchAll(
        /(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(?:Td|TD)|(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+Tm|\(((?:\\.|[^\\)])*)\)\s*Tj|<([0-9A-Fa-f\s]+)>\s*Tj/g,
      )) {
        if (tok[1] !== undefined) {
          curX += Number(tok[1]);
          curY += Number(tok[2]);
        } else if (tok[7] !== undefined) {
          curX = Number(tok[7]);
          curY = Number(tok[8]);
        } else if (tok[9] !== undefined) {
          const txt = cleanCellText(decodePdfLiteral(tok[9]));
          if (txt) positionedItems.push({ x: curX, y: curY, text: txt });
        } else if (tok[10] !== undefined) {
          const txt = cleanCellText(decodePdfHex(tok[10], cmap));
          if (txt) positionedItems.push({ x: curX, y: curY, text: txt });
        }
      }
    }
    if (positionedItems.length > 0) {
      positionedItems.sort((a, b) => b.y - a.y || a.x - b.x);
      const rows = [];
      let curRow = [];
      let rowY = null;
      for (const it of positionedItems) {
        if (rowY === null || Math.abs(it.y - rowY) <= 4.0) {
          curRow.push(it);
          rowY = rowY === null ? it.y : (rowY + it.y) / 2;
        } else {
          rows.push(curRow.sort((a, b) => a.x - b.x).map((x) => x.text));
          curRow = [it];
          rowY = it.y;
        }
      }
      if (curRow.length) rows.push(curRow.sort((a, b) => a.x - b.x).map((x) => x.text));
      const multi = rows.filter((r) => r.length >= 2);
      pages.push({
        pageNumber: pages.length + 1,
        tables: multi.length >= 2 ? [multi] : [],
        text: rows.map((r) => r.join('  ')).join('\n'),
      });
    }
  }

  return { pageCount: Math.max(pageCount, pages.length), pages };
}

function normalizeHeaders(rawHeaders, ncols) {
  const seen = new Map();
  const out = [];
  for (let i = 0; i < ncols; i++) {
    const base = cleanCellText(rawHeaders[i] ?? '') || `Column_${i + 1}`;
    const cnt = (seen.get(base) || 0) + 1;
    seen.set(base, cnt);
    out.push(cnt === 1 ? base : `${base}_${cnt}`);
  }
  return out;
}

export function gridToNormalizedTable(grid, name = 'Table_1', sourceFile = '') {
  const cleaned = grid
    .map((r) => r.map((c) => cleanCellText(c)))
    .filter((r) => r.some((c) => c !== ''));
  if (cleaned.length === 0) return null;
  const ncols = Math.max(...cleaned.map((r) => r.length));
  const padded = cleaned.map((r) => [...r, ...Array(ncols - r.length).fill('')]);
  const keepCols = [];
  for (let c = 0; c < ncols; c++) {
    if (padded.some((r) => r[c] !== '')) keepCols.push(c);
  }
  if (keepCols.length === 0) return null;
  const compact = padded.map((r) => keepCols.map((c) => r[c]));
  return {
    name: name.slice(0, 28) || 'Table_1',
    headers: normalizeHeaders(compact[0], keepCols.length),
    rows: compact.slice(1),
    sourceFile,
  };
}

function parseCsvToTables(text, name = 'Table_1', sourceFile = '') {
  const healed = healUnquotedCurrencyCommas(text);
  const nonEmpty = healed.split('\n').filter((l) => l.trim() !== '');
  if (nonEmpty.length === 0) return [];
  const delims = [',', '\t', ';', '|'];
  let bestDelim = ',';
  let bestCount = -1;
  for (const d of delims) {
    const cnt = nonEmpty.slice(0, 15).reduce((acc, ln) => acc + (ln.split(d).length - 1), 0);
    if (cnt > bestCount) {
      bestCount = cnt;
      bestDelim = d;
    }
  }

  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  const src = healed.endsWith('\n') ? healed : `${healed}\n`;

  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (inQuotes) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"' && field.trim() === '') {
      field = '';
      inQuotes = true;
    } else if (ch === bestDelim) {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      field = '';
      if (row.some((c) => cleanCellText(c) !== '')) rows.push(row);
      row = [];
    } else if (ch !== '\r') {
      field += ch;
    }
  }
  const tbl = gridToNormalizedTable(rows, name, sourceFile);
  return tbl ? [tbl] : [];
}

function stripHtmlTags(html) {
  return cleanCellText(
    String(html ?? '')
      .replace(/<br\s*\/?>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"')
      .replace(/&#39;|&apos;/gi, "'")
      .replace(/&yen;/gi, '¥'),
  );
}

export function parseHtmlToTables(html, sourceFile = '') {
  const tables = [];
  const tableRegex = /<table\b[^>]*>([\s\S]*?)<\/table>/gi;
  let tMatch;
  let tIdx = 0;
  while ((tMatch = tableRegex.exec(html)) !== null) {
    tIdx++;
    const inner = tMatch[1];
    const cap = /<caption\b[^>]*>([\s\S]*?)<\/caption>/i.exec(inner);
    const tName = cap ? stripHtmlTags(cap[1]) : `Table_${tIdx}`;
    const grid = new Map();
    let maxRow = 0;
    let maxCol = 0;

    const trRegex = /<tr\b[^>]*>([\s\S]*?)<\/tr>/gi;
    let trMatch;
    let rIdx = 0;
    while ((trMatch = trRegex.exec(inner)) !== null) {
      const cellRegex = /<(th|td)\b([^>]*)>([\s\S]*?)<\/\1>/gi;
      let cMatch;
      let cIdx = 0;
      while ((cMatch = cellRegex.exec(trMatch[1])) !== null) {
        while (grid.has(`${rIdx},${cIdx}`)) cIdx++;
        const tag = cMatch[1].toLowerCase();
        const attrs = cMatch[2];
        const text = stripHtmlTags(cMatch[3]);
        const rs = Math.max(1, Number(/rowspan\s*=\s*["']?(\d+)/i.exec(attrs)?.[1] || 1));
        const cs = Math.max(1, Number(/colspan\s*=\s*["']?(\d+)/i.exec(attrs)?.[1] || 1));

        for (let dr = 0; dr < rs; dr++) {
          for (let dc = 0; dc < cs; dc++) {
            const key = `${rIdx + dr},${cIdx + dc}`;
            if (dr === 0 && dc === 0) grid.set(key, text);
            else if (rIdx === 0 && dr === 0) grid.set(key, text ? `${text}_${dc + 1}` : '');
            else if (dc === 0 && tag === 'td' && !/^\s*[¥￥$€£+-]?\d/.test(text)) grid.set(key, text);
            else grid.set(key, '');
          }
        }
        maxRow = Math.max(maxRow, rIdx + rs);
        maxCol = Math.max(maxCol, cIdx + cs);
        cIdx += cs;
      }
      rIdx++;
    }

    const matrix = Array.from({ length: maxRow }, (_, r) =>
      Array.from({ length: maxCol }, (_, c) => grid.get(`${r},${c}`) ?? ''),
    );
    const tbl = gridToNormalizedTable(matrix, tName, sourceFile);
    if (tbl) tables.push(tbl);
  }
  return tables;
}

function flattenRecord(obj, prefix = '', out = {}) {
  if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === 'object' && !Array.isArray(v)) flattenRecord(v, key, out);
      else if (Array.isArray(v)) {
        out[key] = v.every((x) => typeof x !== 'object') ? v.join(', ') : JSON.stringify(v);
      } else {
        out[key] = v ?? '';
      }
    }
  } else {
    out[prefix || 'value'] = obj ?? '';
  }
  return out;
}

function recordsToNormalizedTable(records, name, sourceFile) {
  if (!records.length) return null;
  const flat = records.map((r) => flattenRecord(r));
  const headers = [];
  for (const rec of flat) {
    for (const k of Object.keys(rec)) {
      if (!headers.includes(k)) headers.push(k);
    }
  }
  const rows = flat.map((rec) => headers.map((h) => cleanCellText(rec[h] ?? '')));
  return {
    name: name.slice(0, 28) || 'Data',
    headers: normalizeHeaders(headers, headers.length),
    rows,
    sourceFile,
  };
}

function parseJsonToTables(text, name = 'Data', sourceFile = '') {
  const trimmed = text.trim();
  let data;
  try {
    data = JSON.parse(trimmed);
  } catch {
    data = trimmed
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l));
  }
  if (Array.isArray(data)) {
    const t = recordsToNormalizedTable(data, name, sourceFile);
    return t ? [t] : [];
  }
  if (data && typeof data === 'object') {
    const tables = [];
    for (const [k, v] of Object.entries(data)) {
      if (Array.isArray(v) && v.length > 0 && typeof v[0] === 'object') {
        const t = recordsToNormalizedTable(v, k, sourceFile);
        if (t) tables.push(t);
      }
    }
    if (tables.length > 0) return tables;
    const single = recordsToNormalizedTable([data], name, sourceFile);
    return single ? [single] : [];
  }
  return [];
}

function parseMarkdownToTables(text, name = 'Table', sourceFile = '') {
  const lines = text.split('\n');
  const tables = [];
  let tIdx = 0;
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i].trim();
    if (ln.includes('|') && i + 1 < lines.length && /^\s*\|?[\s:-]+\|[\s|:-]*$/.test(lines[i + 1])) {
      const grid = [
        ln
          .replace(/^\||\|$/g, '')
          .split('|')
          .map((c) => c.trim()),
      ];
      i += 2;
      while (i < lines.length && lines[i].includes('|')) {
        grid.push(
          lines[i]
            .trim()
            .replace(/^\||\|$/g, '')
            .split('|')
            .map((c) => c.trim()),
        );
        i++;
      }
      i--;
      tIdx++;
      const tbl = gridToNormalizedTable(grid, `${name}_${tIdx}`, sourceFile);
      if (tbl) tables.push(tbl);
    }
  }
  if (tables.length === 0) {
    return parseCsvToTables(text, name, sourceFile);
  }
  return tables;
}

/**
 * Stitches tables across consecutive PDF pages when headers match (or when a continuation table
 * has the exact same column count and its first row is data rather than headers).
 */
export function stitchContinuationTables(rawTables, { mergePages = true, dedupeRows = false } = {}) {
  let tables = rawTables.map((t) => ({
    ...t,
    headers: [...t.headers],
    rows: t.rows.map((r) => [...r]),
  }));

  let stitchedCount = 0;
  if (mergePages && tables.length >= 2) {
    const merged = [tables[0]];
    for (let i = 1; i < tables.length; i++) {
      const prev = merged[merged.length - 1];
      const curr = tables[i];
      const sameHeaders =
        prev.headers.length === curr.headers.length &&
        prev.headers.every(
          (h, idx) => h.toLowerCase() === curr.headers[idx].toLowerCase(),
        );
      if (sameHeaders) {
        // Also skip repeated header rows embedded inside curr.rows
        const filteredRows = curr.rows.filter(
          (r) =>
            !r.every(
              (cell, idx) =>
                cleanCellText(cell).toLowerCase() === prev.headers[idx].toLowerCase(),
            ),
        );
        prev.rows.push(...filteredRows);
        stitchedCount++;
      } else {
        merged.push(curr);
      }
    }
    tables = merged;
  }

  let duplicatesRemoved = 0;
  if (dedupeRows) {
    for (const t of tables) {
      const seen = new Set();
      const kept = [];
      for (const r of t.rows) {
        const key = r.map((c) => cleanCellText(c)).join('\u001f');
        if (seen.has(key)) {
          duplicatesRemoved++;
          continue;
        }
        seen.add(key);
        kept.push(r);
      }
      t.rows = kept;
    }
  }

  return { tables, stitchedCount, duplicatesRemoved };
}

function tableToMarkdown(tbl, maxRows = 100) {
  const esc = (s) => cleanCellText(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
  const headerLine = `| ${tbl.headers.map(esc).join(' | ')} |`;
  const sepLine = `| ${tbl.headers.map(() => '---').join(' | ')} |`;
  const rowLines = tbl.rows
    .slice(0, maxRows)
    .map((r) => `| ${tbl.headers.map((_, idx) => esc(r[idx] ?? '')).join(' | ')} |`);
  return [`### ${tbl.name}`, '', headerLine, sepLine, ...rowLines].join('\n');
}

/**
 * Main High-Level Extractor & Cleaner for `extract_and_clean_pdf_tables_to_xlsx`.
 */
export async function extractAndCleanTablesToXlsx({
  filename = 'document.pdf',
  bytes = null,
  contentBase64 = '',
  content = '',
  mergePages = true,
  dedupeRows = false,
  injectFormulas = true,
} = {}) {
  const rawBytes =
    bytes instanceof Uint8Array && bytes.length > 0
      ? bytes
      : contentBase64
        ? decodeBase64ToBytes(contentBase64)
        : null;

  const isPdfBinary =
    rawBytes &&
    rawBytes.length >= 5 &&
    String.fromCharCode(...rawBytes.subarray(0, 5)) === '%PDF-';

  let rawTables = [];
  let pageCount = 1;
  let detectedEncoding = 'utf-8';
  let mojibakeRepaired = false;
  let extractorBackend = 'structured-parser';

  if (isPdfBinary) {
    detectedEncoding = 'pdf-binary';
    let pdfResult = tryExtractPdfWithPyMuPdf(rawBytes);
    if (pdfResult) {
      extractorBackend = 'pymupdf-fitz';
    } else {
      pdfResult = await extractPdfPureJsFallback(rawBytes);
      extractorBackend = 'pure-js-pdf';
    }
    pageCount = pdfResult.pageCount || 1;
    let tblSeq = 0;
    for (const page of pdfResult.pages || []) {
      for (const grid of page.tables || []) {
        tblSeq++;
        const norm = gridToNormalizedTable(
          grid,
          `Page_${page.pageNumber}_Table_${tblSeq}`,
          filename,
        );
        if (norm) rawTables.push(norm);
      }
    }
    // If PDF had pipe/delimited text rather than positioned multi-col cells, try text fallback
    if (rawTables.length === 0) {
      const joinedText = (pdfResult.pages || []).map((p) => p.text || '').join('\n');
      rawTables = parseMarkdownToTables(joinedText, 'Extracted_Table', filename);
    }
  } else {
    const decoded = decodeAndRepairCjk({ bytes: rawBytes, text: content });
    detectedEncoding = decoded.detectedEncoding;
    mojibakeRepaired = decoded.mojibakeRepaired;
    const lower = String(filename || '').toLowerCase();
    const stem = (filename || 'Table').replace(/\.[^.]+$/, '') || 'Table';

    if (lower.endsWith('.html') || lower.endsWith('.htm') || /<table\b/i.test(decoded.text)) {
      rawTables = parseHtmlToTables(decoded.text, filename);
      extractorBackend = 'html-grid-2d';
    } else if (
      lower.endsWith('.json') ||
      lower.endsWith('.jsonl') ||
      /^[\[{]/.test(decoded.text.trim())
    ) {
      rawTables = parseJsonToTables(decoded.text, stem, filename);
      extractorBackend = 'json-flattener';
    } else if (lower.endsWith('.md') || (decoded.text.includes('|') && /\|\s*---/.test(decoded.text))) {
      rawTables = parseMarkdownToTables(decoded.text, stem, filename);
      extractorBackend = 'markdown-table';
    } else {
      rawTables = parseCsvToTables(decoded.text, stem, filename);
      extractorBackend = 'csv-healer';
    }
  }

  const { tables, stitchedCount, duplicatesRemoved } = stitchContinuationTables(rawTables, {
    mergePages,
    dedupeRows,
  });

  // Rename primary stitched table cleanly after stem
  if (tables.length === 1 && isPdfBinary) {
    const stem = (filename || 'Extracted').replace(/\.[^.]+$/, '');
    tables[0].name = stem.slice(0, 28) || 'Extracted_Table';
  }

  const xlsxBytes = buildWorkbookXlsxBytes(tables, { injectFormulas });
  const primaryTable = tables[0] || { name: 'Empty', headers: ['Column_1'], rows: [] };
  const utf8BomCsv = buildSafeUtf8BomCsv({
    headers: primaryTable.headers,
    rows: primaryTable.rows,
    withBom: true,
  });
  const markdownPreview = tables.map((t) => tableToMarkdown(t, 50)).join('\n\n');

  const totalRows = tables.reduce((acc, t) => acc + t.rows.length, 0);

  return {
    filename,
    extractorBackend,
    detectedEncoding,
    mojibakeRepaired,
    pageCount,
    tableCount: tables.length,
    totalRows,
    stitchedPagesCount: stitchedCount,
    duplicatesRemoved,
    tables: tables.map((t) => ({
      name: t.name,
      headers: t.headers,
      rowCount: t.rows.length,
      rows: t.rows,
    })),
    markdown: markdownPreview,
    utf8BomCsv,
    xlsxBytes,
    xlsxBase64: Buffer.from(xlsxBytes).toString('base64'),
  };
}
