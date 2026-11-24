/**
 * Commercial Tool & Endpoint Catalog (`catalog.mjs`) for the Direct 0%-Fee x402 Gateway.
 *
 * Single source of truth for:
 * - Paid REST endpoints (`/api/v1/*`)
 * - Paid MCP `tools/call` tools (`/mcp`)
 * - x402 v1/v2 `outputSchema` (`input.bodyFields` + `output`) for `x402scan` / `x402lint` / Bazaar
 * - Pre-settlement input validation (`InputValidationError` -> HTTP 400 BEFORE `/settle`!)
 */

import { extractAndCleanTablesToXlsx, gridToNormalizedTable } from './core/pdf-tables.mjs';
import { reconcileStatementsAndInvoices } from './core/reconcile-engine.mjs';
import {
  buildSafeUtf8BomCsv,
  cleanCellText,
  decodeAndRepairCjk,
  decodeBase64ToBytes,
  healUnquotedCurrencyCommas,
} from './core/sanitize.mjs';
import { auditEip712SignaturePayload } from './web3/eip712-audit.mjs';
import { decodeAndAuditEvmCalldata } from './web3/evm-calldata.mjs';
import { validateMultichainAddress } from './web3/multichain-address.mjs';

export class InputValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InputValidationError';
    this.statusCode = 400;
  }
}

function parseSimpleCsvGrid(text) {
  const healed = healUnquotedCurrencyCommas(text);
  const nonEmpty = healed.split('\n').filter((l) => l.trim() !== '');
  if (nonEmpty.length === 0) return { delimiter: ',', headers: [], rows: [] };

  const delims = [',', '\t', ';'];
  let bestDelim = ',';
  let bestScore = -1;
  for (const d of delims) {
    const score = nonEmpty.slice(0, 15).reduce((acc, l) => acc + (l.split(d).length - 1), 0);
    if (score > bestScore) {
      bestScore = score;
      bestDelim = d;
    }
  }

  const rawRows = [];
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
      row.push(cleanCellText(field));
      field = '';
    } else if (ch === '\n') {
      row.push(cleanCellText(field));
      field = '';
      if (row.some((c) => c !== '')) rawRows.push(row);
      row = [];
    } else if (ch !== '\r') {
      field += ch;
    }
  }

  const norm = gridToNormalizedTable(rawRows, 'Repaired_CSV');
  if (!norm) return { delimiter: bestDelim, headers: [], rows: [] };
  return { delimiter: bestDelim, headers: norm.headers, rows: norm.rows };
}

export const PAID_ENDPOINTS = [
  {
    id: 'validate-address',
    restPath: '/api/v1/validate-address',
    mcpName: 'validate_multichain_address',
    title: 'Validate & Normalize Multichain Wallet Address',
    category: 'web3-security',
    priceUsd: '0.01',
    amountAtomic: '10000',
    description:
      'Cryptographically validates and normalizes wallet/contract addresses across 8 ecosystems: EVM (Keccak-256 EIP-55 checksum + typo/burn detection), Tron (T... SHA-256d Base58Check + 0x41/EVM conversion), Bitcoin (BIP-173 Bech32 bc1q, BIP-350 Bech32m bc1p Taproot, Base58Check), Solana (Ed25519 curve vs off-curve PDA detector), TON (EQ/UQ CRC16-XMODEM + bounceable trap alert), XRPL (classic r... + XLS-5d X-address tag decoder), Cosmos Bech32, and Stacks c32check.',
    inputSchema: {
      type: 'object',
      properties: {
        address: {
          type: 'string',
          description: 'Wallet or contract address string to validate and normalize.',
        },
        chain: {
          type: 'string',
          description: 'Optional chain constraint: auto, evm, tron, bitcoin, solana, ton, xrpl, cosmos, or stacks.',
          default: 'auto',
        },
        expectedNetwork: {
          type: 'string',
          enum: ['any', 'mainnet', 'testnet'],
          description: 'Expected network environment (any, mainnet, or testnet).',
          default: 'any',
        },
      },
      required: ['address'],
    },
    bodyFields: {
      address: {
        type: 'string',
        required: true,
        description: 'Wallet or contract address string to validate and normalize',
      },
      chain: {
        type: 'string',
        required: false,
        description: 'Optional chain constraint: auto, evm, tron, bitcoin, solana, ton, xrpl, cosmos, or stacks',
      },
      expectedNetwork: {
        type: 'string',
        required: false,
        description: 'Expected network environment: any, mainnet, or testnet',
      },
    },
    outputSchemaShape: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        tool: { type: 'string' },
        summary: {
          type: 'object',
          properties: {
            valid: { type: 'boolean' },
            safeToTransact: { type: 'boolean' },
            riskLevel: { type: 'string' },
            chain: { type: 'string' },
            network: { type: 'string' },
            canonicalAddress: { type: 'string' },
          },
        },
        analysis: { type: 'object' },
      },
    },
    sampleRequest: {
      address: '0xfEbDbB880C7f323c145d61683874a45540208a68',
      chain: 'evm',
      expectedNetwork: 'mainnet',
    },
    validateArgs(args) {
      if (!args || typeof args !== 'object' || Array.isArray(args)) {
        throw new InputValidationError('Request body must be a JSON object.');
      }
      if (typeof args.address !== 'string' || !args.address.trim()) {
        throw new InputValidationError('Field `address` is required and must be a non-empty string.');
      }
      if (args.address.length > 512) {
        throw new InputValidationError('Field `address` exceeds maximum length of 512 characters.');
      }
    },
    async execute(args) {
      const analysis = validateMultichainAddress({
        address: args.address,
        chain: args.chain || 'auto',
        expectedNetwork: args.expectedNetwork || 'any',
      });
      return {
        status: 'ok',
        tool: 'validate_multichain_address',
        summary: {
          valid: analysis.valid,
          safeToTransact: analysis.safeToTransact,
          riskLevel: analysis.riskLevel,
          chain: analysis.chain,
          network: analysis.network,
          canonicalAddress: analysis.canonicalAddress,
        },
        analysis,
      };
    },
  },
  {
    id: 'audit-calldata',
    restPath: '/api/v1/audit-calldata',
    mcpName: 'decode_and_audit_evm_calldata',
    title: 'Decode & Audit Raw EVM Transaction Calldata',
    category: 'web3-security',
    priceUsd: '0.01',
    amountAtomic: '10000',
    description:
      'Deterministically decodes raw hex EVM transaction payloads (`to`, `value`, `data`, `chainId`) across ERC-20 (`transfer`, `approve`, `transferFrom`, `increaseAllowance`), ERC-721/1155 (`setApprovalForAll`, `safeTransferFrom`), Permit2, Uniswap V2/V3/UniversalRouter, 1inch, Multicall (recursive inner-call decoding), and Gnosis Safe `execTransaction`. Flags CRITICAL unlimited approvals, setApprovalForAll(true), zero-minOut MEV sandwich exposure, non-zero ETH sent with approvals, and DELEGATECALL takeovers.',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Target 0x contract or recipient address.' },
        value: { type: 'string', description: 'Native ETH/gas token value in wei (decimal or 0x hex).', default: '0' },
        data: { type: 'string', description: '0x-prefixed hex calldata string.', default: '0x' },
        chainId: { type: 'number', description: 'EVM Chain ID (default: 8453 Base).', default: 8453 },
        sender: { type: 'string', description: 'Optional sender 0x address for swap output-diversion checks.' },
        referenceTimestamp: { type: 'number', description: 'Optional Unix timestamp in seconds.' },
      },
      required: ['data'],
    },
    bodyFields: {
      data: {
        type: 'string',
        required: true,
        description: '0x-prefixed hex calldata string (e.g. 0x095ea7b3...)',
      },
      to: {
        type: 'string',
        required: false,
        description: 'Target 0x contract or recipient address',
      },
      value: {
        type: 'string',
        required: false,
        description: 'Native ETH/gas token value in wei (decimal or 0x hex)',
      },
      chainId: {
        type: 'number',
        required: false,
        description: 'EVM Chain ID (default: 8453 Base)',
      },
      sender: {
        type: 'string',
        required: false,
        description: 'Optional sender 0x address for swap output-diversion checks',
      },
    },
    outputSchemaShape: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        tool: { type: 'string' },
        summary: {
          type: 'object',
          properties: {
            safeToExecute: { type: 'boolean' },
            recommendation: { type: 'string' },
            riskLevel: { type: 'string' },
            riskScore: { type: 'number' },
            standard: { type: 'string' },
            functionName: { type: 'string' },
            findingCount: { type: 'number' },
          },
        },
        audit: { type: 'object' },
      },
    },
    sampleRequest: {
      to: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      value: '0',
      data: '0x095ea7b30000000000000000000000001111111254eeb25477b68fb85ed929f73a960582ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      chainId: 8453,
    },
    validateArgs(args) {
      if (!args || typeof args !== 'object' || Array.isArray(args)) {
        throw new InputValidationError('Request body must be a JSON object.');
      }
      if (args.data === undefined && args.to === undefined) {
        throw new InputValidationError('Field `data` (0x hex calldata) or `to` (0x address) is required.');
      }
      if (args.data !== undefined) {
        if (typeof args.data !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(args.data.trim())) {
          throw new InputValidationError('Field `data` must be an even-length 0x-prefixed hex string.');
        }
      }
    },
    async execute(args) {
      const audit = decodeAndAuditEvmCalldata({
        to: args.to || '',
        value: args.value ?? '0',
        data: args.data ?? '0x',
        chainId: args.chainId ?? 8453,
        sender: args.sender || '',
        referenceTimestamp: args.referenceTimestamp ?? null,
      });
      return {
        status: 'ok',
        tool: 'decode_and_audit_evm_calldata',
        summary: {
          safeToExecute: audit.safeToExecute,
          recommendation: audit.recommendation,
          riskLevel: audit.riskLevel,
          riskScore: audit.riskScore,
          standard: audit.standard,
          functionName: audit.functionName,
          findingCount: audit.findings.length,
        },
        audit,
      };
    },
  },
  {
    id: 'audit-eip712',
    restPath: '/api/v1/audit-eip712',
    mcpName: 'audit_eip712_signature_payload',
    title: 'Audit Off-Chain EIP-712 Typed-Data Signature Payload',
    category: 'web3-security',
    priceUsd: '0.01',
    amountAtomic: '10000',
    description:
      'Audits off-chain `eth_signTypedData_v4` JSON objects or strings (`Permit`, DAI `Permit`, `PermitSingle`, `PermitBatch`, `PermitTransferFrom`, Seaport `OrderComponents`, Circle USDC EIP-3009 `TransferWithAuthorization` / `x402`, `ForwardRequest`, `SafeTx`) before signing. Computes EIP-712 `domainSeparator` and flags unlimited allowances, Seaport zero-consideration drains, DELEGATECALL meta-txs, multi-month expirations, and chainId/contract spoofing.',
    inputSchema: {
      type: 'object',
      properties: {
        typedData: {
          description: 'eth_signTypedData_v4 JSON object or serialized JSON string.',
        },
        expectedChainId: { type: 'number', description: 'Optional expected EVM chainId.' },
        expectedVerifyingContract: { type: 'string', description: 'Optional expected 0x verifyingContract.' },
        expectedRecipient: { type: 'string', description: 'Optional expected 0x recipient for x402 / EIP-3009.' },
        expectedMaxAmount: { type: 'string', description: 'Optional maximum expected raw token amount.' },
        referenceTimestamp: { type: 'number', description: 'Optional Unix timestamp in seconds.' },
      },
      required: ['typedData'],
    },
    bodyFields: {
      typedData: {
        type: 'object',
        required: true,
        description: 'eth_signTypedData_v4 typed data JSON object (with domain, types, primaryType, message)',
      },
      expectedChainId: {
        type: 'number',
        required: false,
        description: 'Optional expected EVM chainId (e.g. 8453)',
      },
      expectedVerifyingContract: {
        type: 'string',
        required: false,
        description: 'Optional expected 0x verifyingContract address',
      },
      expectedRecipient: {
        type: 'string',
        required: false,
        description: 'Optional expected 0x recipient for x402 / EIP-3009 authorization',
      },
      expectedMaxAmount: {
        type: 'string',
        required: false,
        description: 'Optional maximum expected raw atomic token amount',
      },
    },
    outputSchemaShape: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        tool: { type: 'string' },
        summary: {
          type: 'object',
          properties: {
            safeToSign: { type: 'boolean' },
            recommendation: { type: 'string' },
            riskLevel: { type: 'string' },
            riskScore: { type: 'number' },
            schemaCategory: { type: 'string' },
            primaryType: { type: 'string' },
            findingCount: { type: 'number' },
          },
        },
        audit: { type: 'object' },
      },
    },
    sampleRequest: {
      typedData: {
        domain: {
          name: 'USD Coin',
          version: '2',
          chainId: 8453,
          verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        },
        primaryType: 'TransferWithAuthorization',
        types: {
          TransferWithAuthorization: [
            { name: 'from', type: 'address' },
            { name: 'to', type: 'address' },
            { name: 'value', type: 'uint256' },
            { name: 'validAfter', type: 'uint256' },
            { name: 'validBefore', type: 'uint256' },
            { name: 'nonce', type: 'bytes32' },
          ],
        },
        message: {
          from: '0x1111111111111111111111111111111111111111',
          to: '0xfEbDbB880C7f323c145d61683874a45540208a68',
          value: '10000',
          validAfter: '0',
          validBefore: '1893456000',
          nonce: '0x0000000000000000000000000000000000000000000000000000000000000001',
        },
      },
      expectedChainId: 8453,
    },
    validateArgs(args) {
      if (!args || typeof args !== 'object' || Array.isArray(args)) {
        throw new InputValidationError('Request body must be a JSON object.');
      }
      if (args.typedData === undefined || args.typedData === null || args.typedData === '') {
        throw new InputValidationError('Field `typedData` is required (JSON object or serialized JSON string).');
      }
      let parsed = args.typedData;
      if (typeof parsed === 'string') {
        try {
          parsed = JSON.parse(parsed);
        } catch {
          throw new InputValidationError('Field `typedData` string is not valid JSON.');
        }
      }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || !parsed.message) {
        throw new InputValidationError('Field `typedData` must contain an EIP-712 `message` object.');
      }
    },
    async execute(args) {
      const audit = auditEip712SignaturePayload({
        typedData: args.typedData,
        expectedChainId: args.expectedChainId ?? null,
        expectedVerifyingContract: args.expectedVerifyingContract || '',
        expectedRecipient: args.expectedRecipient || '',
        expectedMaxAmount: args.expectedMaxAmount ?? null,
        referenceTimestamp: args.referenceTimestamp ?? null,
      });
      return {
        status: 'ok',
        tool: 'audit_eip712_signature_payload',
        summary: {
          safeToSign: audit.safeToSign,
          recommendation: audit.recommendation,
          riskLevel: audit.riskLevel,
          riskScore: audit.riskScore,
          schemaCategory: audit.schemaCategory,
          primaryType: audit.primaryType,
          findingCount: audit.findings.length,
        },
        audit,
      };
    },
  },
  {
    id: 'repair-cjk-csv',
    restPath: '/api/v1/repair-cjk-csv',
    mcpName: 'repair_cjk_csv_mojibake',
    title: 'Repair CJK CSV Mojibake & Neutralize Formula Injection',
    category: 'financial-data',
    priceUsd: '0.01',
    amountAtomic: '10000',
    description:
      'Detects and repairs garbled Chinese/Japanese/Korean CSV/TSV exports from GB18030, GBK, Big5, Shift-JIS, EUC-KR, UTF-16LE/BE, and double-encoded UTF-8-as-Latin1/CP1252; heals unquoted currency thousands commas; strips dangerous control bytes; armors 15+ digit IDs; and neutralizes OWASP CSV/DDE formula injection (=, +, -, @) into Excel-ready UTF-8 BOM CSV + structured JSON rows.',
    inputSchema: {
      type: 'object',
      properties: {
        filename: {
          type: 'string',
          description: 'Optional source filename (e.g. alipay_export.csv)',
          default: 'export.csv',
        },
        contentBase64: {
          type: 'string',
          description: 'Base64-encoded raw CSV bytes (GBK/GB18030/Big5/Shift-JIS/EUC-KR/UTF-16)',
        },
        content: {
          type: 'string',
          description: 'Garbled or raw CSV text (e.g. UTF-8 bytes mis-decoded as Latin-1/Windows-1252)',
        },
      },
    },
    bodyFields: {
      content: {
        type: 'string',
        required: false,
        description: 'Garbled or raw CSV text string (provide either content or contentBase64)',
      },
      contentBase64: {
        type: 'string',
        required: false,
        description: 'Base64-encoded raw legacy CSV bytes (GB18030/GBK/Big5/Shift-JIS/EUC-KR/UTF-16)',
      },
      filename: {
        type: 'string',
        required: false,
        description: 'Optional source filename (default: export.csv)',
      },
    },
    outputSchemaShape: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        tool: { type: 'string' },
        summary: { type: 'object' },
        headers: { type: 'array' },
        rows: { type: 'array' },
        utf8BomCsv: { type: 'string' },
      },
    },
    sampleRequest: {
      filename: 'alipay_export.csv',
      content: '订单号,商户名称,金额\n202611240001,阿里云计算,¥1,250.00\n',
    },
    validateArgs(args) {
      if (!args || typeof args !== 'object' || Array.isArray(args)) {
        throw new InputValidationError('Request body must be a JSON object.');
      }
      if (!args.contentBase64 && (typeof args.content !== 'string' || !args.content.trim())) {
        throw new InputValidationError(
          'Either `contentBase64` (raw CSV bytes) or non-empty `content` (CSV string) is required.',
        );
      }
    },
    async execute(args) {
      const rawBytes = args.contentBase64 ? decodeBase64ToBytes(args.contentBase64) : null;
      const decoded = decodeAndRepairCjk({ bytes: rawBytes, text: args.content || '' });
      const parsedGrid = parseSimpleCsvGrid(decoded.text);
      const safeUtf8BomCsv =
        parsedGrid.headers.length > 0
          ? buildSafeUtf8BomCsv({
              headers: parsedGrid.headers,
              rows: parsedGrid.rows,
              withBom: true,
            })
          : `\uFEFF${decoded.text}`;

      return {
        status: 'ok',
        tool: 'repair_cjk_csv_mojibake',
        summary: {
          filename: args.filename || 'export.csv',
          detectedEncoding: decoded.detectedEncoding,
          mojibakeRepaired: decoded.mojibakeRepaired,
          confidence: decoded.confidence,
          delimiter: parsedGrid.delimiter,
          columnCount: parsedGrid.headers.length,
          rowCount: parsedGrid.rows.length,
        },
        headers: parsedGrid.headers,
        rows: parsedGrid.rows,
        utf8BomCsv: safeUtf8BomCsv,
      };
    },
  },
  {
    id: 'extract-tables',
    restPath: '/api/v1/extract-tables',
    mcpName: 'extract_and_clean_pdf_tables_to_xlsx',
    title: 'Extract & Clean Multi-Page PDF / HTML / Messy Tables to OpenXML XLSX',
    category: 'financial-data',
    priceUsd: '0.02',
    amountAtomic: '20000',
    description:
      'Extracts tables from multi-page PDF binaries (Base64), HTML (with 2D rowspan/colspan expansion), Markdown, JSON/JSONL, or messy CSVs; stitches repeating headers across page breaks, repairs CJK mojibake, neutralizes Excel formula/DDE injection on user cells while generating live =SUM() and =AVERAGE() summary rows, and outputs Base64 OpenXML .xlsx, Markdown, and UTF-8 BOM CSV.',
    inputSchema: {
      type: 'object',
      properties: {
        filename: {
          type: 'string',
          description: 'Input filename with extension hint (e.g. report.pdf, table.html)',
          default: 'document.html',
        },
        contentBase64: {
          type: 'string',
          description: 'Base64-encoded PDF or legacy-encoded file bytes',
        },
        content: {
          type: 'string',
          description: 'Direct HTML, Markdown, CSV, or JSON string payload',
        },
        mergePages: {
          type: 'boolean',
          description: 'Stitch multi-page continuation tables sharing identical headers (default: true)',
          default: true,
        },
        dedupeRows: {
          type: 'boolean',
          description: 'Remove exact duplicate rows across pages (default: false)',
          default: false,
        },
        injectFormulas: {
          type: 'boolean',
          description: 'Append live =SUM() and =AVERAGE() summary rows to numeric columns (default: true)',
          default: true,
        },
      },
    },
    bodyFields: {
      content: {
        type: 'string',
        required: false,
        description: 'HTML, Markdown, CSV, or JSON table content (provide content or contentBase64)',
      },
      contentBase64: {
        type: 'string',
        required: false,
        description: 'Base64-encoded PDF or binary document bytes',
      },
      filename: {
        type: 'string',
        required: false,
        description: 'Filename with extension hint (e.g. report.pdf, statement.html)',
      },
    },
    outputSchemaShape: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        tool: { type: 'string' },
        summary: { type: 'object' },
        tables: { type: 'array' },
        markdown: { type: 'string' },
        utf8BomCsv: { type: 'string' },
        xlsxBase64: { type: 'string' },
      },
    },
    sampleRequest: {
      filename: 'quarterly.html',
      content: '<table><tr><th>Item</th><th>Amount</th></tr><tr><td>Cloud Compute</td><td>120.50</td></tr></table>',
    },
    validateArgs(args) {
      if (!args || typeof args !== 'object' || Array.isArray(args)) {
        throw new InputValidationError('Request body must be a JSON object.');
      }
      if (!args.contentBase64 && (typeof args.content !== 'string' || !args.content.trim())) {
        throw new InputValidationError(
          'Either `contentBase64` (PDF/binary bytes) or non-empty `content` (HTML/Markdown/CSV/JSON string) is required.',
        );
      }
    },
    async execute(args) {
      const result = await extractAndCleanTablesToXlsx({
        filename: args.filename || 'document.html',
        contentBase64: args.contentBase64 || '',
        content: args.content || '',
        mergePages: args.mergePages !== false,
        dedupeRows: Boolean(args.dedupeRows),
        injectFormulas: args.injectFormulas !== false,
      });
      return {
        status: 'ok',
        tool: 'extract_and_clean_pdf_tables_to_xlsx',
        summary: {
          filename: result.filename,
          extractorBackend: result.extractorBackend,
          detectedEncoding: result.detectedEncoding,
          mojibakeRepaired: result.mojibakeRepaired,
          pageCount: result.pageCount,
          tableCount: result.tableCount,
          totalRows: result.totalRows,
          stitchedPagesCount: result.stitchedPagesCount,
          duplicatesRemoved: result.duplicatesRemoved,
          xlsxByteLength: result.xlsxBytes.length,
        },
        tables: result.tables,
        markdown: result.markdown,
        utf8BomCsv: result.utf8BomCsv,
        xlsxBase64: result.xlsxBase64,
      };
    },
  },
  {
    id: 'reconcile-statements',
    restPath: '/api/v1/reconcile-statements',
    mcpName: 'reconcile_statements_and_invoices',
    title: 'Reconcile Bank / Payment Statements & Electronic Invoices',
    category: 'financial-data',
    priceUsd: '0.02',
    amountAtomic: '20000',
    description:
      'Deterministically reconciles Alipay, WeChat Pay, Stripe, PayPal, or bank CSV/JSON statements against electronic invoices (CN Digital e-Invoice XML/PDF, UBL 2.1 XML, CSV, JSON) using exact BigInt micro-unit math: 1:1 order-ID matching, vendor+amount+date matching, cross-currency FX spread matching, and N-to-1 subset-sum combined invoice matching. Outputs structured JSON summary, anomaly alerts, UTF-8 BOM CSV, and Base64 3-sheet OpenXML .xlsx workbook.',
    inputSchema: {
      type: 'object',
      properties: {
        statements: {
          type: 'array',
          description:
            'List of payment statement files ({ filename, content? | contentBase64? }) from Alipay, WeChat Pay, Stripe, or bank CSV/JSON exports.',
          items: {
            type: 'object',
            properties: {
              filename: { type: 'string' },
              content: { type: 'string' },
              contentBase64: { type: 'string' },
            },
            required: ['filename'],
          },
        },
        invoices: {
          type: 'array',
          description: 'List of electronic invoice files ({ filename, content? | contentBase64? }).',
          items: {
            type: 'object',
            properties: {
              filename: { type: 'string' },
              content: { type: 'string' },
              contentBase64: { type: 'string' },
            },
            required: ['filename'],
          },
        },
        baseCurrency: { type: 'string', default: 'CNY' },
        expectedBuyerName: { type: 'string' },
        expectedBuyerTaxId: { type: 'string' },
        dateWindowDays: { type: 'number', default: 45 },
        includeXlsxBase64: { type: 'boolean', default: true },
      },
      required: ['statements'],
    },
    bodyFields: {
      statements: {
        type: 'array',
        required: true,
        description: 'Non-empty array of statement objects ({ filename, content | contentBase64 })',
      },
      invoices: {
        type: 'array',
        required: false,
        description: 'Array of electronic invoice objects ({ filename, content | contentBase64 })',
      },
      baseCurrency: {
        type: 'string',
        required: false,
        description: '3-letter ISO base currency (default: CNY)',
      },
    },
    outputSchemaShape: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        tool: { type: 'string' },
        summary: { type: 'object' },
        transactions: { type: 'array' },
        invoices: { type: 'array' },
        anomalies: { type: 'array' },
        utf8BomCsv: { type: 'string' },
        xlsxBase64: { type: 'string' },
      },
    },
    sampleRequest: {
      statements: [
        {
          filename: 'stripe_nov.csv',
          content: 'id,date,merchant,amount,currency\nord_1001,2026-11-20,AWS Cloud,99.00,USD\n',
        },
      ],
      invoices: [
        {
          filename: 'inv_aws.json',
          content: '{"invoiceNumber":"INV-9001","orderId":"ord_1001","sellerName":"AWS Cloud","issueDate":"2026-11-21","totalAmount":99.00,"currency":"USD"}',
        },
      ],
      baseCurrency: 'USD',
    },
    validateArgs(args) {
      if (!args || typeof args !== 'object' || Array.isArray(args)) {
        throw new InputValidationError('Request body must be a JSON object.');
      }
      if (!Array.isArray(args.statements) || args.statements.length === 0) {
        throw new InputValidationError('Field `statements` must be a non-empty array of statement objects.');
      }
      for (const s of args.statements) {
        if (!s || typeof s !== 'object' || (!s.content && !s.contentBase64)) {
          throw new InputValidationError(
            'Each item in `statements` must provide either `content` or `contentBase64`.',
          );
        }
      }
    },
    async execute(args) {
      const result = await reconcileStatementsAndInvoices({
        statements: args.statements,
        invoices: Array.isArray(args.invoices) ? args.invoices : [],
        baseCurrency: args.baseCurrency || 'CNY',
        expectedBuyerName: args.expectedBuyerName || '',
        expectedBuyerTaxId: args.expectedBuyerTaxId || '',
        dateWindowDays: Number(args.dateWindowDays ?? 45),
      });
      const includeXlsx = args.includeXlsxBase64 !== false;
      return {
        status: 'ok',
        tool: 'reconcile_statements_and_invoices',
        summary: result.summary,
        transactions: result.transactions,
        invoices: result.invoices,
        anomalies: result.anomalies,
        utf8BomCsv: result.utf8BomCsv,
        ...(includeXlsx ? { xlsxBase64: result.xlsxBase64, xlsxByteLength: result.xlsxBytes.length } : {}),
      };
    },
  },
];

export const ENDPOINTS_BY_PATH = new Map(PAID_ENDPOINTS.map((e) => [e.restPath, e]));
export const ENDPOINTS_BY_MCP_NAME = new Map(PAID_ENDPOINTS.map((e) => [e.mcpName, e]));
