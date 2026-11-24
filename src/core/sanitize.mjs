/**
 * Security-Hardened Text Decoding, CJK Mojibake Repair, XML 1.0 Sanitization,
 * and OWASP CSV Formula / DDE Injection Protection (`sanitize.mjs`).
 */

const ZERO_WIDTH_RE = /[\u200b\u200c\u200d\ufeff\u2060]/g;

// Windows-1252 0x80..0x9F Unicode-to-byte reverse map (essential when UTF-8 or GBK bytes
// were mis-decoded as Windows-1252 / ISO-8859-1 by Excel, browsers, or legacy ETL scripts).
const CP1252_UNICODE_TO_BYTE = new Map([
  [0x20ac, 0x80],
  [0x201a, 0x82],
  [0x0192, 0x83],
  [0x201e, 0x84],
  [0x2026, 0x85],
  [0x2020, 0x86],
  [0x2021, 0x87],
  [0x02c6, 0x88],
  [0x2030, 0x89],
  [0x0160, 0x8a],
  [0x2039, 0x8b],
  [0x0152, 0x8c],
  [0x017d, 0x8e],
  [0x2018, 0x91],
  [0x2019, 0x92],
  [0x201c, 0x93],
  [0x201d, 0x94],
  [0x2022, 0x95],
  [0x2013, 0x96],
  [0x2014, 0x97],
  [0x02dc, 0x98],
  [0x2122, 0x99],
  [0x0161, 0x9a],
  [0x203a, 0x9b],
  [0x0153, 0x9c],
  [0x017e, 0x9e],
  [0x0178, 0x9f],
]);

/**
 * Strips all characters forbidden by XML 1.0 Fifth Edition (§2.2):
 * Allowed: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
 * Normalizes vertical tab (\x0B) and form-feed (\x0C, emitted by PDF page breaks) to spaces
 * (or newlines when `preservePageBreaksAsNewline` is true), and strips \x00-\x08, \x0E-\x1F, \x7F,
 * \uFFFE, \uFFFF, and unpaired UTF-16 surrogates so OpenXML (.xlsx / .docx) parsers never fail.
 */
export function stripIllegalXmlChars(input, { preservePageBreaksAsNewline = false } = {}) {
  if (input === null || input === undefined) return '';
  const str = String(input);
  let out = '';
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code === 0x0b || code === 0x0c) {
      out += preservePageBreaksAsNewline ? '\n' : ' ';
      continue;
    }
    if (code === 0x09 || code === 0x0a || code === 0x0d) {
      out += str[i];
      continue;
    }
    if (code < 0x20 || code === 0x7f || code === 0xfffe || code === 0xffff) {
      continue;
    }
    // UTF-16 surrogate pair validation
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = str.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += str[i] + str[i + 1];
        i++;
      }
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      continue;
    }
    out += str[i];
  }
  return out;
}

export function cleanCellText(val) {
  if (val === null || val === undefined) return '';
  return stripIllegalXmlChars(val, { preservePageBreaksAsNewline: false })
    .replace(ZERO_WIDTH_RE, '')
    .replace(/\u00a0/g, ' ')
    .replace(/\r\n?/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{2,}/g, '\n')
    .trim();
}

export function escapeXmlText(val) {
  return stripIllegalXmlChars(val, { preservePageBreaksAsNewline: false })
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function toUint8Array(input) {
  if (input instanceof Uint8Array) return input;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (typeof input === 'string') {
    return new TextEncoder().encode(input);
  }
  throw new TypeError('Unsupported binary/text input type');
}

export function decodeBase64ToBytes(b64) {
  if (!b64 || typeof b64 !== 'string') return new Uint8Array(0);
  const cleaned = b64.replace(/^data:[^;]+;base64,/i, '').replace(/\s+/g, '');
  return new Uint8Array(Buffer.from(cleaned, 'base64'));
}

// High-frequency Simplified Chinese, Traditional Chinese, and Japanese Kanji characters
// (including business, accounting, banking, tax/invoice, and logistics vocabulary).
// Used to separate genuine CJK text from GBK/3 & GBK/4 archaic-character mojibake when
// GB18030/Big5/Shift_JIS/EUC-KR byte ranges overlap.
const COMMON_CJK_SET = new Set(
  '的一是在不了有和人这中大为上个国我以要他时来用们生到作地于出就分对成会可主发年动同工也能下过子说产种面而方后多定行学法所民得经十之进着等部度家电力里如水化高自二理起小物现实加量都两体制机当使点从业本去把性好应开它合还因由其些然前外天政四日那社义事平形相全表间样与关各重新线内数正心反你明看原又么利比或但质气第向道命此变条只没结解问意建月公无系军很情者最立代想已通并提直题党程展五果料象员革位入常文总次品式活设及管特件长求老头基资边流路级少图山统接知较将组见计别她手角期根论运农指几九区强放决西被干做必战先回则任取据处队南给色光门即保治北造百规热领七海口东导器压志世金增争济阶油思术极交受联什认六共权收证改清己美再采转更单风切打白教速花带安场身车例真务具万每目至达走积示议声报斗完类离华名确才科张信马节话米整空元况今集温传土许步群广石记需段研界拉林律叫且究观越织装影算低持音众书布复容儿须际商非验连断深难近矿千周委素技备半办青省列习响约支般史感劳便团往酸历市克何除消构称太准精值号率族维划选写存候毛亲快效斯院查江型眼王按格养易置派层片始却专状育厂京识适属圆包火住调满县局照参红细引听该铁价严' +
    '订单编号客户名称实付金额交易创建时间对方商品说明收支服务费状态成功退款商户单号备注日期摘要借方贷方余额发票代码号码税率税额合计数量单价部门项目预算采购杭州深圳上海北京广州成都云栖科技有限股份工作室银行微信支付宝顺丰滴滴小桔阿里云星辰极客张三李四王五赵六陈七刘八周九吴十费用报销差旅餐饮住宿交通办公软件订阅年度季度月度明细汇总账单流水凭证审核验收通过普通专用电子数码跨境贸易设计咨询物流快递保价冷链生鲜寄件快车专车服务器域名存储带宽续费充值提现手续费折扣优惠实收应付应收净额毛利成本利润税前税后个人企业组织机构统一社会信用纳税识别开户地址电话账号币种人民币美元欧元日元港币英镑' +
    '訂單編號客戶名稱實付金額台灣臺灣雲端開發國際企業帳號匯款轉帳發票統編稅額總計數量單價備註狀態處理完成退貨運費優惠折扣購買銷售應收應付餘額銀行郵局專戶明細報表會計傳票審核確認聯絡電話地址頁碼項目部門採購合約幣別新台幣港幣美金日圓歐元資訊網路數位媒體顧問設計製造貿易物流貨運台北新北台中高雄桃園台南新竹' +
    '注文番号取引先名金額東京大阪名古屋福岡北海道札幌横浜京都神戸株式会社有限合同商事物産工業電機情報通信銀行口座振込請求書領収書納品書見積書消費税合計小計単価数量備考日付年月日担当者部署電話番号住所郵便商品代金送料手数料割引返品返金決済完了未払入金出金残高勘定科目摘要借方貸方伝票承認確認顧客氏名様御中税込税抜円田中佐藤鈴木高橋渡辺伊藤山本中村小林加藤吉田山田佐々木山口松本井上木村斎藤清水',
);

/**
 * Linguistic quality score favoring coherent CJK (high-frequency Hanzi/Kanji, Fullwidth Kana,
 * pure Hangul, CJK punctuation) and clean printable ASCII while heavily penalizing U+FFFD
 * replacement chars, Private Use Area (U+E000..U+F8FF), halfwidth Katakana mojibake, mixed
 * Hangul+Hanja word corruption, C1/Latin-1 mojibake clusters, and control characters.
 */
export function scoreTextCoherence(text) {
  if (!text) return -1e9;
  let commonHanzi = 0;
  let rareHanzi = 0;
  let kana = 0;
  let hangul = 0;
  let cjkPunct = 0;
  let halfwidthKana = 0;
  let pua = 0;
  let ascii = 0;
  let latinMojibake = 0;
  let replacement = 0;
  let control = 0;

  for (let i = 0; i < text.length; i++) {
    const cp = text.charCodeAt(i);
    if (cp === 0xfffd) {
      replacement++;
    } else if (cp >= 0xe000 && cp <= 0xf8ff) {
      pua++;
    } else if (cp >= 0xff61 && cp <= 0xff9f) {
      halfwidthKana++;
    } else if (cp === 9 || cp === 10 || cp === 13 || (cp >= 0x20 && cp <= 0x7e)) {
      ascii++;
    } else if (cp >= 0x3040 && cp <= 0x30ff) {
      kana++;
    } else if (cp >= 0xac00 && cp <= 0xd7a3) {
      hangul++;
    } else if ((cp >= 0x4e00 && cp <= 0x9fff) || (cp >= 0x3400 && cp <= 0x4dbf)) {
      if (COMMON_CJK_SET.has(text[i])) {
        commonHanzi++;
      } else {
        rareHanzi++;
      }
    } else if (
      (cp >= 0x3000 && cp <= 0x303f) || // CJK Symbols & Punctuation
      (cp >= 0xff01 && cp <= 0xff60) || // Fullwidth ASCII variants (￥, ，, ：)
      (cp >= 0xffe0 && cp <= 0xffee) || // Fullwidth Currency/Symbols
      cp === 0x00a5 // Yen/Yuan sign ¥
    ) {
      cjkPunct++;
    } else if ((cp >= 0x0080 && cp <= 0x00ff) || CP1252_UNICODE_TO_BYTE.has(cp)) {
      latinMojibake++;
    } else if (cp < 0x20 && cp !== 0x0b && cp !== 0x0c) {
      control++;
    }
  }

  const totalHanzi = commonHanzi + rareHanzi;
  // When GB2312 Chinese bytes are mis-decoded as EUC-KR, ~35-50% of byte pairs fall into
  // EUC-KR's Hanja range (0xCA..0xFD) interleaved with Hangul inside the same tokens.
  const mixedHangulHanjaPenalty =
    hangul > 0 && totalHanzi > 0 && totalHanzi >= hangul * 0.15
      ? Math.min(hangul, totalHanzi) * 3.0
      : 0;

  const rawScore =
    commonHanzi * 4.2 +
    rareHanzi * 1.4 +
    kana * 4.1 +
    hangul * 3.7 +
    cjkPunct * 3.3 +
    ascii * 1.0 -
    mixedHangulHanjaPenalty -
    halfwidthKana * 4.5 -
    pua * 18.0 -
    latinMojibake * 2.4 -
    replacement * 35.0 -
    control * 20.0;

  return rawScore / Math.max(text.length, 1);
}

function stringToSingleByteStream(str) {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    const cp = str.charCodeAt(i);
    if (cp <= 0xff) {
      bytes[i] = cp;
    } else if (CP1252_UNICODE_TO_BYTE.has(cp)) {
      bytes[i] = CP1252_UNICODE_TO_BYTE.get(cp);
    } else {
      return null;
    }
  }
  return bytes;
}

/**
 * Repairs double-encoded mojibake strings (e.g., UTF-8 or GB18030 bytes misread as Latin-1 / Windows-1252).
 */
export function repairStringMojibake(text) {
  if (!text) return { text: '', repaired: false, originalEncoding: 'utf-8' };

  let highByteChars = 0;
  for (let i = 0; i < text.length; i++) {
    const cp = text.charCodeAt(i);
    if ((cp >= 0x80 && cp <= 0xff) || CP1252_UNICODE_TO_BYTE.has(cp)) {
      highByteChars++;
    }
  }

  if (highByteChars >= 2) {
    const rawBytes = stringToSingleByteStream(text);
    if (rawBytes) {
      const baseScore = scoreTextCoherence(text);

      // 1. Strict UTF-8 check first: valid multi-byte UTF-8 sequences have strong structural
      // redundancy, whereas GB18030 accepts nearly arbitrary byte pairs as rare Hanzi (e.g. '寮犱笁').
      try {
        const utf8Decoded = new TextDecoder('utf-8', { fatal: true }).decode(rawBytes);
        if (scoreTextCoherence(utf8Decoded) > baseScore + 0.3) {
          return {
            text: utf8Decoded,
            repaired: true,
            originalEncoding: 'mojibake(latin1->utf-8)',
          };
        }
      } catch {
        // Not valid UTF-8 -> fall through to legacy CJK encodings
      }

      let best = { text, score: baseScore + 0.3, repaired: false, originalEncoding: 'utf-8' };
      for (const candidateEnc of ['gb18030', 'big5', 'shift_jis', 'euc-kr']) {
        try {
          const decoded = new TextDecoder(candidateEnc, { fatal: true }).decode(rawBytes);
          const sc = scoreTextCoherence(decoded);
          if (sc > best.score) {
            best = {
              text: decoded,
              score: sc,
              repaired: true,
              originalEncoding: `mojibake(latin1->${candidateEnc})`,
            };
          }
        } catch {
          // Not valid in candidateEnc
        }
      }

      if (best.repaired) {
        return {
          text: best.text,
          repaired: true,
          originalEncoding: best.originalEncoding,
        };
      }
    }
  }

  return { text, repaired: false, originalEncoding: 'utf-8' };
}

/**
 * Decodes raw bytes OR repairs already-garbled strings across UTF-8, UTF-16LE/BE, GB18030/GBK, Big5, Shift_JIS, EUC-KR.
 */
export function decodeAndRepairCjk({ bytes, text } = {}) {
  if (bytes && bytes.length > 0) {
    const u8 = toUint8Array(bytes);

    // 1. UTF-8 BOM
    if (u8.length >= 3 && u8[0] === 0xef && u8[1] === 0xbb && u8[2] === 0xbf) {
      const raw = new TextDecoder('utf-8').decode(u8.subarray(3));
      const rep = repairStringMojibake(raw);
      const sanitized = stripIllegalXmlChars(rep.text, { preservePageBreaksAsNewline: true })
        .replace(ZERO_WIDTH_RE, '')
        .replace(/\r\n?/g, '\n');
      return {
        text: sanitized,
        detectedEncoding: rep.repaired ? `utf-8-bom+${rep.originalEncoding}` : 'utf-8-bom',
        mojibakeRepaired: rep.repaired,
        confidence: 0.99,
      };
    }

    // 2. UTF-16LE / UTF-16BE BOM
    if (u8.length >= 2 && u8[0] === 0xff && u8[1] === 0xfe) {
      const raw = new TextDecoder('utf-16le').decode(u8.subarray(2));
      return {
        text: stripIllegalXmlChars(raw, { preservePageBreaksAsNewline: true })
          .replace(ZERO_WIDTH_RE, '')
          .replace(/\r\n?/g, '\n'),
        detectedEncoding: 'utf-16le',
        mojibakeRepaired: true,
        confidence: 0.99,
      };
    }
    if (u8.length >= 2 && u8[0] === 0xfe && u8[1] === 0xff) {
      const raw = new TextDecoder('utf-16be').decode(u8.subarray(2));
      return {
        text: stripIllegalXmlChars(raw, { preservePageBreaksAsNewline: true })
          .replace(ZERO_WIDTH_RE, '')
          .replace(/\r\n?/g, '\n'),
        detectedEncoding: 'utf-16be',
        mojibakeRepaired: true,
        confidence: 0.99,
      };
    }

    // 3. Un-BOM'd UTF-16LE heuristic
    if (u8.length >= 16) {
      let oddZeros = 0;
      const sampleLen = Math.min(u8.length, 64);
      for (let i = 1; i < sampleLen; i += 2) {
        if (u8[i] === 0x00) oddZeros++;
      }
      if (oddZeros >= sampleLen / 4) {
        const raw = new TextDecoder('utf-16le').decode(u8);
        return {
          text: stripIllegalXmlChars(raw, { preservePageBreaksAsNewline: true })
            .replace(ZERO_WIDTH_RE, '')
            .replace(/\r\n?/g, '\n'),
          detectedEncoding: 'utf-16le-nobom',
          mojibakeRepaired: true,
          confidence: 0.94,
        };
      }
    }

    // 4. Strict UTF-8 check (+ double-mojibake check)
    try {
      const utf8 = new TextDecoder('utf-8', { fatal: true }).decode(u8);
      const rep = repairStringMojibake(utf8);
      const cleaned = stripIllegalXmlChars(rep.text, { preservePageBreaksAsNewline: true })
        .replace(ZERO_WIDTH_RE, '')
        .replace(/\r\n?/g, '\n');
      return {
        text: cleaned,
        detectedEncoding: rep.repaired ? rep.originalEncoding : 'utf-8',
        mojibakeRepaired: rep.repaired,
        confidence: rep.repaired ? 0.96 : 0.99,
      };
    } catch {
      // Non-UTF-8 legacy CJK byte stream -> evaluate CJK encodings by coherence score
    }

    let bestCandidate = null;
    for (const enc of ['gb18030', 'big5', 'shift_jis', 'euc-kr', 'windows-1252']) {
      try {
        const dec = new TextDecoder(enc, { fatal: enc !== 'windows-1252' }).decode(u8);
        const sc = scoreTextCoherence(dec);
        const adjusted = enc === 'gb18030' ? sc + 0.01 : sc;
        if (!bestCandidate || adjusted > bestCandidate.adjusted) {
          bestCandidate = { text: dec, enc, sc, adjusted };
        }
      } catch {
        // Unsupported or invalid byte sequence for this encoding
      }
    }

    if (bestCandidate) {
      return {
        text: stripIllegalXmlChars(bestCandidate.text, { preservePageBreaksAsNewline: true })
          .replace(ZERO_WIDTH_RE, '')
          .replace(/\r\n?/g, '\n'),
        detectedEncoding: bestCandidate.enc,
        mojibakeRepaired: bestCandidate.enc !== 'utf-8',
        confidence: Number(Math.min(0.98, Math.max(0.55, 0.7 + bestCandidate.sc * 0.1)).toFixed(2)),
      };
    }
  }

  const rawText = typeof text === 'string' ? text : '';
  const rep = repairStringMojibake(rawText);
  const cleaned = stripIllegalXmlChars(rep.text, { preservePageBreaksAsNewline: true })
    .replace(ZERO_WIDTH_RE, '')
    .replace(/\r\n?/g, '\n');
  return {
    text: cleaned,
    detectedEncoding: rep.originalEncoding,
    mojibakeRepaired: rep.repaired,
    confidence: rep.repaired ? 0.95 : 0.99,
  };
}

/**
 * Heals unquoted currency values containing thousands commas (e.g. `¥1,250.00`, `(¥1,100.00)`, `$12,400.50`)
 * before comma-delimited CSV parsing so columns do not split mid-amount.
 */
export function healUnquotedCurrencyCommas(csvLineOrText) {
  return String(csvLineOrText ?? '').replace(
    /(^|[,\t;])(\s*(?:\()?\s*(?:[¥￥$€£]|RMB|CNY|USD)\s*[+-]?\d{1,3}(?:,\d{3})+(?:\.\d+)?\s*(?:\))?\s*)(?=[,\t;\r\n]|$)/gm,
    (_m, sep, amt) => `${sep}"${amt.trim()}"`,
  );
}

const FORMULA_DANGEROUS_START_RE = /^[=+\-@]/;
const CONTROL_DANGEROUS_START_RE = /^[\t\r\n]/;
const PURE_SIGNED_NUMBER_RE = /^[+-]?\d+(?:\.\d+)?$/;

/**
 * Formats a single CSV cell with strict OWASP CSV / DDE Formula Injection neutralization
 * and 15+ digit numeric ID protection against Excel IEEE-754 truncation.
 */
export function formatSafeCsvCell(
  value,
  { isNumeric = false, isId = false, idArmor = 'apostrophe' } = {},
) {
  if (value === null || value === undefined) return '';
  let str = stripIllegalXmlChars(String(value), { preservePageBreaksAsNewline: false }).replace(
    ZERO_WIDTH_RE,
    '',
  );

  if (isNumeric && PURE_SIGNED_NUMBER_RE.test(str.trim())) {
    return str.trim();
  }

  const trimmed = str.trim();
  if ((isId || /^\d{15,}$/.test(trimmed) || /^0\d+$/.test(trimmed)) && /^\d+$/.test(trimmed)) {
    if (idArmor === 'tab') {
      str = `${trimmed}\t`;
    } else if (idArmor === 'apostrophe') {
      str = `'${trimmed}`;
    } else {
      str = trimmed;
    }
  } else {
    const trimmedLeft = str.replace(/^ +/, '');
    if (
      (FORMULA_DANGEROUS_START_RE.test(trimmedLeft) && !PURE_SIGNED_NUMBER_RE.test(trimmedLeft)) ||
      CONTROL_DANGEROUS_START_RE.test(str)
    ) {
      str = `'${str}`;
    }
  }

  if (/[",\r\n\t]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Serializes `{ headers: string[], rows: any[][] }` or `{ columns, records }` to UTF-8 BOM CSV
 * with full DDE/formula-injection protection.
 */
export function buildSafeUtf8BomCsv({ headers, rows, numericColSet = new Set(), idColSet = new Set(), withBom = true }) {
  const hdrLine = headers
    .map((h) => formatSafeCsvCell(h, { isNumeric: false, isId: false }))
    .join(',');

  const bodyLines = rows.map((row) =>
    headers
      .map((_, colIdx) => {
        const val = row[colIdx] ?? '';
        const isNum =
          numericColSet.has(colIdx) &&
          (typeof val === 'number' || PURE_SIGNED_NUMBER_RE.test(String(val).trim()));
        return formatSafeCsvCell(val, {
          isNumeric: isNum,
          isId: idColSet.has(colIdx),
          idArmor: 'apostrophe',
        });
      })
      .join(','),
  );

  const csv = [hdrLine, ...bodyLines].join('\r\n') + '\r\n';
  return withBom ? `\uFEFF${csv}` : csv;
}
