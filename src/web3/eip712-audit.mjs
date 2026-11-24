/**
 * Off-Chain EIP-712 (`eth_signTypedData_v4`) Pre-Signature Security Auditor (`eip712-audit.mjs`).
 *
 * Audits EIP-2612 `Permit`, DAI `Permit`, Uniswap `Permit2` (`PermitSingle`, `PermitBatch`,
 * `PermitTransferFrom`, `PermitBatchTransferFrom`), OpenSea `Seaport` (`OrderComponents`),
 * Circle USDC EIP-3009 (`TransferWithAuthorization` / `ReceiveWithAuthorization` used by `x402`),
 * ERC-2771 `ForwardRequest`, and Gnosis `SafeTx` payloads BEFORE an AI agent or wallet signs.
 */

import { keccak256Bytes, keccak256Hex, toEip55Address } from './crypto-primitives.mjs';
import { decodeAndAuditEvmCalldata } from './evm-calldata.mjs';
import { validateMultichainAddress } from './multichain-address.mjs';

const HALF_UINT256 = 1n << 255n;
const HALF_UINT160 = 1n << 159n;
const MAX_UINT48 = (1n << 48n) - 1n;

const CANONICAL_PERMIT2_ADDRESS = '0x000000000022D473030F116dDEE9F6B43aC78BA3';

function parseBigIntSafe(val) {
  if (val === undefined || val === null || val === '') return null;
  if (typeof val === 'bigint') return val;
  if (typeof val === 'number') {
    if (!Number.isFinite(val) || val < 0) return null;
    return BigInt(Math.trunc(val));
  }
  const s = String(val).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^\d+$/.test(s)) return BigInt(s);
  return null;
}

function pad32Hex(hexNoPrefix) {
  return hexNoPrefix.padStart(64, '0');
}

function computeDomainSeparatorHex(domain = {}) {
  try {
    const fields = [];
    const encodedWords = [];
    if (domain.name !== undefined) {
      fields.push('string name');
      encodedWords.push(keccak256Hex(String(domain.name)));
    }
    if (domain.version !== undefined) {
      fields.push('string version');
      encodedWords.push(keccak256Hex(String(domain.version)));
    }
    if (domain.chainId !== undefined) {
      const cid = parseBigIntSafe(domain.chainId);
      if (cid === null) return null;
      fields.push('uint256 chainId');
      encodedWords.push(pad32Hex(cid.toString(16)));
    }
    if (domain.verifyingContract !== undefined) {
      const clean = String(domain.verifyingContract).replace(/^0x/i, '').toLowerCase();
      if (!/^[0-9a-f]{40}$/.test(clean)) return null;
      fields.push('address verifyingContract');
      encodedWords.push(pad32Hex(clean));
    }
    if (domain.salt !== undefined) {
      const cleanSalt = String(domain.salt).replace(/^0x/i, '').toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(cleanSalt)) return null;
      fields.push('bytes32 salt');
      encodedWords.push(cleanSalt);
    }
    const typeStr = `EIP712Domain(${fields.join(',')})`;
    const typeHash = keccak256Hex(typeStr);
    const fullHex = typeHash + encodedWords.join('');
    return `0x${Buffer.from(keccak256Bytes(Buffer.from(fullHex, 'hex'))).toString('hex')}`;
  } catch {
    return null;
  }
}

function checkExpiryField(val, label, nowSec, findings) {
  const big = parseBigIntSafe(val);
  if (big === null) return;
  if (big === 0n) {
    findings.push({
      code: 'INFINITE_ZERO_EXPIRY',
      severity: 'CRITICAL',
      points: 85,
      message: `Signature field "${label}" is 0 (never expires on DAI-style / Seaport / EIP-3009 contracts), enabling permanent signature replay until nonce revocation.`,
    });
    return;
  }
  const num = Number(big);
  if (num < nowSec) {
    findings.push({
      code: 'EXPIRED_SIGNATURE_DEADLINE',
      severity: 'HIGH',
      points: 40,
      message: `Signature "${label}" (${big.toString()}) has already expired relative to ${nowSec}.`,
    });
  } else if (big >= MAX_UINT48 || num > nowSec + 86400 * 30) {
    findings.push({
      code: 'MULTI_MONTH_OR_INFINITE_SIGNATURE_DEADLINE',
      severity: 'HIGH',
      points: 55,
      message: `Signature "${label}" (${big.toString()}) stays valid > 30 days (or MAX_UINT), allowing attackers to warehouse your off-chain signature and drain funds months later!`,
    });
  }
}

function checkAddressRole(addr, label, findings, { flagZeroAsBurn = true } = {}) {
  if (!addr || typeof addr !== 'string') return null;
  const v = validateMultichainAddress({ address: addr, chain: 'evm' });
  if (!v.valid) {
    findings.push({
      code: 'INVALID_EIP712_ADDRESS',
      severity: 'CRITICAL',
      points: 90,
      message: `Field "${label}" contains invalid or checksum-corrupted EVM address "${addr}".`,
    });
    return addr;
  }
  if (flagZeroAsBurn && v.isBurnOrSystemTrap) {
    findings.push({
      code: 'ZERO_OR_BURN_SPENDER_OR_RECIPIENT',
      severity: 'HIGH',
      points: 60,
      message: `Field "${label}" points to zero/burn address (${v.canonicalAddress}).`,
    });
  }
  return v.canonicalAddress;
}

export function auditEip712SignaturePayload({
  typedData,
  expectedChainId = null,
  expectedVerifyingContract = '',
  expectedRecipient = '',
  expectedMaxAmount = null,
  referenceTimestamp = null,
} = {}) {
  let payload = typedData;
  if (typeof payload === 'string') {
    try {
      payload = JSON.parse(payload);
    } catch (err) {
      throw new Error(`Invalid JSON string in \`typedData\`: ${err.message}`);
    }
  }
  if (!payload || typeof payload !== 'object') {
    throw new Error('`audit_eip712_signature_payload` requires a `typedData` JSON object or string.');
  }

  const nowSec =
    referenceTimestamp !== null && referenceTimestamp !== undefined
      ? Number(referenceTimestamp)
      : Math.floor(Date.now() / 1000);

  const domain = payload.domain && typeof payload.domain === 'object' ? payload.domain : {};
  const types = payload.types && typeof payload.types === 'object' ? payload.types : {};
  const message = payload.message && typeof payload.message === 'object' ? payload.message : null;
  let primaryType = payload.primaryType || '';

  if (!primaryType && types) {
    const nonDomainKeys = Object.keys(types).filter((k) => k !== 'EIP712Domain');
    if (nonDomainKeys.length === 1) primaryType = nonDomainKeys[0];
  }

  if (!message || !primaryType) {
    throw new Error('EIP-712 payload must contain `primaryType` and `message` objects.');
  }

  const findings = [];
  let summaryKind = 'CUSTOM_TYPED_DATA';
  const extractedSummary = { primaryType };

  // ==========================================================================
  // 1. Domain Integrity & Replay Protection Audit
  // ==========================================================================
  const domainChainIdBig = parseBigIntSafe(domain.chainId);
  if (domainChainIdBig === null) {
    findings.push({
      code: 'MISSING_DOMAIN_CHAIN_ID',
      severity: 'HIGH',
      points: 55,
      message:
        'EIP-712 domain omits `chainId` — signature can be replayed across EVERY EVM chain where a matching contract exists!',
    });
  } else if (expectedChainId !== null && expectedChainId !== undefined) {
    const expCid = parseBigIntSafe(expectedChainId);
    if (expCid !== null && domainChainIdBig !== expCid) {
      findings.push({
        code: 'DOMAIN_CHAIN_ID_MISMATCH',
        severity: 'CRITICAL',
        points: 95,
        message: `Domain chainId (${domainChainIdBig.toString()}) does NOT match expected chainId (${expCid.toString()}) — cross-chain phishing trap!`,
      });
    }
  }

  let normalizedVerifyingContract = null;
  if (!domain.verifyingContract) {
    findings.push({
      code: 'MISSING_VERIFYING_CONTRACT',
      severity: 'HIGH',
      points: 60,
      message:
        'EIP-712 domain omits `verifyingContract` — signature is not bound to a specific on-chain contract address!',
    });
  } else {
    normalizedVerifyingContract = checkAddressRole(
      String(domain.verifyingContract),
      'domain.verifyingContract',
      findings,
      { flagZeroAsBurn: true },
    );
    if (expectedVerifyingContract && String(expectedVerifyingContract).trim()) {
      const expVc = toEip55Address(String(expectedVerifyingContract).trim());
      if (normalizedVerifyingContract && normalizedVerifyingContract !== expVc) {
        findings.push({
          code: 'DOMAIN_CONTRACT_SPOOFING',
          severity: 'CRITICAL',
          points: 95,
          message: `Domain verifyingContract (${normalizedVerifyingContract}) does NOT match expected contract (${expVc})!`,
        });
      }
    }
  }

  const domainSeparator = computeDomainSeparatorHex(domain);

  // ==========================================================================
  // 2. Primary Type Specific Security Audits
  // ==========================================================================
  const pTypeLower = primaryType.toLowerCase();

  // 2A. EIP-2612 & DAI-style `Permit`
  if (pTypeLower === 'permit') {
    summaryKind = 'ERC20_PERMIT';
    const spender = checkAddressRole(message.spender, 'message.spender', findings);
    extractedSummary.spender = spender;
    if (message.allowed !== undefined) {
      // DAI boolean permit
      const allowed = Boolean(message.allowed);
      extractedSummary.allowed = allowed;
      if (allowed) {
        findings.push({
          code: 'UNLIMITED_DAI_PERMIT_ALLOWANCE',
          severity: 'CRITICAL',
          points: 90,
          message: `DAI-style off-chain Permit grants UNLIMITED gasless spending authority over your token balance to ${spender}!`,
        });
      }
      checkExpiryField(message.expiry, 'message.expiry', nowSec, findings);
    } else {
      const valBig = parseBigIntSafe(message.value ?? message.amount);
      extractedSummary.value = valBig !== null ? valBig.toString() : String(message.value ?? '');
      if (valBig !== null && valBig >= HALF_UINT256) {
        findings.push({
          code: 'UNLIMITED_PERMIT_ALLOWANCE',
          severity: 'CRITICAL',
          points: 90,
          message: `Off-chain EIP-2612 Permit grants UNLIMITED spending allowance to ${spender} (zero gas required by attacker to submit \`permit\` + \`transferFrom\`)!`,
        });
      }
      if (expectedMaxAmount !== null && expectedMaxAmount !== undefined && valBig !== null) {
        const cap = parseBigIntSafe(expectedMaxAmount);
        if (cap !== null && valBig > cap) {
          findings.push({
            code: 'AMOUNT_EXCEEDS_EXPECTED_CAP',
            severity: 'CRITICAL',
            points: 90,
            message: `Permit value (${valBig.toString()}) exceeds caller's expectedMaxAmount (${cap.toString()})!`,
          });
        }
      }
      checkExpiryField(message.deadline, 'message.deadline', nowSec, findings);
    }
  }

  // 2B. Uniswap Permit2 (`PermitSingle`, `PermitBatch`, `PermitTransferFrom`, `PermitBatchTransferFrom`)
  else if (
    pTypeLower === 'permitsingle' ||
    pTypeLower === 'permitbatch' ||
    pTypeLower === 'permittransferfrom' ||
    pTypeLower === 'permitbatchtransferfrom'
  ) {
    summaryKind = 'UNISWAP_PERMIT2';
    if (
      normalizedVerifyingContract &&
      normalizedVerifyingContract !== CANONICAL_PERMIT2_ADDRESS &&
      !expectedVerifyingContract
    ) {
      findings.push({
        code: 'NON_CANONICAL_PERMIT2_CONTRACT',
        severity: 'HIGH',
        points: 55,
        message: `Permit2 payload uses non-canonical verifyingContract ${normalizedVerifyingContract} (official Permit2 is ${CANONICAL_PERMIT2_ADDRESS}).`,
      });
    }

    const spender = checkAddressRole(message.spender, 'message.spender', findings);
    extractedSummary.spender = spender;
    checkExpiryField(message.sigDeadline ?? message.deadline, 'sigDeadline', nowSec, findings);

    const detailItems = Array.isArray(message.details)
      ? message.details
      : message.details
        ? [message.details]
        : Array.isArray(message.permitted)
          ? message.permitted
          : message.permitted
            ? [message.permitted]
            : [];

    extractedSummary.tokenCount = detailItems.length;
    detailItems.forEach((item, idx) => {
      const token = checkAddressRole(item.token, `details[${idx}].token`, findings);
      const amt = parseBigIntSafe(item.amount);
      if (amt !== null && (amt >= HALF_UINT160 || amt >= HALF_UINT256)) {
        findings.push({
          code: 'UNLIMITED_PERMIT2_ALLOWANCE',
          severity: 'CRITICAL',
          points: 90,
          message: `Permit2 item #${idx} (${token}) grants MAX_UINT160/MAX_UINT256 allowance to spender ${spender}!`,
        });
      }
      if (item.expiration !== undefined) {
        checkExpiryField(item.expiration, `details[${idx}].expiration`, nowSec, findings);
      }
    });
  }

  // 2C. OpenSea Seaport (`OrderComponents` / `Order`)
  else if (pTypeLower === 'ordercomponents' || pTypeLower === 'order') {
    summaryKind = 'SEAPORT_ORDER';
    const offerer = checkAddressRole(message.offerer, 'message.offerer', findings, {
      flagZeroAsBurn: false,
    });
    const offer = Array.isArray(message.offer) ? message.offer : [];
    const consideration = Array.isArray(message.consideration) ? message.consideration : [];
    extractedSummary.offerer = offerer;
    extractedSummary.offerCount = offer.length;
    extractedSummary.considerationCount = consideration.length;

    const offererReceipts = consideration.filter((c) => {
      if (!c?.recipient || !offerer) return false;
      try {
        return toEip55Address(c.recipient) === offerer;
      } catch {
        return false;
      }
    });

    if (offer.length > 0 && offererReceipts.length === 0) {
      findings.push({
        code: 'SEAPORT_ZERO_CONSIDERATION_DRAIN',
        severity: 'CRITICAL',
        points: 98,
        message: `Seaport listing offers ${offer.length} asset(s) while returning ZERO consideration items to offerer ${offerer} — classic NFT/ERC-20 zero-price signature drain!`,
      });
    }
    if (message.endTime !== undefined) {
      checkExpiryField(message.endTime, 'message.endTime', nowSec, findings);
    }
  }

  // 2D. EIP-3009 USDC / `x402` (`TransferWithAuthorization` / `ReceiveWithAuthorization`)
  else if (
    pTypeLower === 'transferwithauthorization' ||
    pTypeLower === 'receivewithauthorization'
  ) {
    summaryKind = 'EIP3009_X402_AUTHORIZATION';
    const from = checkAddressRole(message.from, 'message.from', findings);
    const to = checkAddressRole(message.to, 'message.to', findings);
    const valBig = parseBigIntSafe(message.value);
    extractedSummary.from = from;
    extractedSummary.to = to;
    extractedSummary.value = valBig !== null ? valBig.toString() : String(message.value ?? '');

    if (expectedRecipient && String(expectedRecipient).trim() && to) {
      const expRec = toEip55Address(String(expectedRecipient).trim());
      if (to !== expRec) {
        findings.push({
          code: 'X402_RECIPIENT_MISMATCH',
          severity: 'CRITICAL',
          points: 95,
          message: `EIP-3009 authorization recipient (${to}) does NOT match expected payment recipient (${expRec})!`,
        });
      }
    }
    if (expectedMaxAmount !== null && expectedMaxAmount !== undefined && valBig !== null) {
      const cap = parseBigIntSafe(expectedMaxAmount);
      if (cap !== null && valBig > cap) {
        findings.push({
          code: 'AMOUNT_EXCEEDS_EXPECTED_CAP',
          severity: 'CRITICAL',
          points: 95,
          message: `EIP-3009 authorization value (${valBig.toString()}) exceeds expectedMaxAmount (${cap.toString()})!`,
        });
      }
    }
    checkExpiryField(message.validBefore, 'message.validBefore', nowSec, findings);
  }

  // 2E. Meta-Transactions & Safe Multisig (`ForwardRequest`, `SafeTx`)
  else if (pTypeLower === 'forwardrequest' || pTypeLower === 'safetx') {
    summaryKind = pTypeLower === 'safetx' ? 'GNOSIS_SAFE_TX' : 'ERC2771_FORWARD_REQUEST';
    const innerTo = checkAddressRole(message.to, 'message.to', findings);
    const operation = Number(message.operation ?? 0);
    extractedSummary.to = innerTo;
    extractedSummary.operation = operation === 1 ? 'DELEGATECALL (1)' : 'CALL (0)';

    if (operation === 1) {
      findings.push({
        code: 'TYPED_DATA_DELEGATECALL',
        severity: 'CRITICAL',
        points: 95,
        message: `${primaryType} specifies operation=1 (DELEGATECALL) into ${innerTo}, risking complete account/owner takeover!`,
      });
    }
    if (typeof message.data === 'string' && message.data.startsWith('0x') && message.data.length >= 10) {
      const innerAudit = decodeAndAuditEvmCalldata({
        to: innerTo || '',
        value: String(message.value ?? '0'),
        data: message.data,
        chainId: Number(domainChainIdBig ?? 8453n),
        referenceTimestamp: nowSec,
      });
      extractedSummary.decodedInnerCall = {
        functionName: innerAudit.functionName,
        riskLevel: innerAudit.riskLevel,
        decodedArgs: innerAudit.decodedArgs,
      };
      for (const f of innerAudit.findings) {
        findings.push({
          ...f,
          points: f.severity === 'CRITICAL' ? 90 : f.severity === 'HIGH' ? 55 : 25,
          message: `[Embedded Calldata -> ${innerAudit.functionName}] ${f.message}`,
        });
      }
    }
  }

  // 2F. Generic fallback heuristic scan on arbitrary custom EIP-712 structs
  else {
    for (const [k, v] of Object.entries(message)) {
      if (/spender|operator/i.test(k) && typeof v === 'string' && v.startsWith('0x')) {
        checkAddressRole(v, `message.${k}`, findings);
      }
      if (/amount|value|allowance/i.test(k)) {
        const b = parseBigIntSafe(v);
        if (b !== null && b >= HALF_UINT256) {
          findings.push({
            code: 'CUSTOM_TYPED_DATA_MAX_ALLOWANCE',
            severity: 'CRITICAL',
            points: 85,
            message: `Custom EIP-712 field "message.${k}" contains MAX_UINT256 / >= 2^255 value.`,
          });
        }
      }
      if (/deadline|expir/i.test(k)) {
        checkExpiryField(v, `message.${k}`, nowSec, findings);
      }
    }
  }

  const rawScore = findings.reduce((acc, f) => acc + (f.points || 15), 0);
  const riskScore = Math.min(100, rawScore);

  let riskLevel = 'SAFE';
  if (findings.some((f) => f.severity === 'CRITICAL') || riskScore >= 80) {
    riskLevel = 'CRITICAL';
  } else if (findings.some((f) => f.severity === 'HIGH') || riskScore >= 45) {
    riskLevel = 'HIGH';
  } else if (findings.some((f) => f.severity === 'MEDIUM') || riskScore >= 20) {
    riskLevel = 'MEDIUM';
  } else if (findings.length > 0) {
    riskLevel = 'LOW';
  }

  const recommendation =
    riskLevel === 'CRITICAL'
      ? 'DO_NOT_SIGN'
      : riskLevel === 'HIGH'
        ? 'REQUIRE_HUMAN_REVIEW'
        : riskLevel === 'MEDIUM'
          ? 'SIGN_WITH_CAUTION'
          : 'SAFE_TO_SIGN';

  return {
    safeToSign: recommendation === 'SAFE_TO_SIGN' || recommendation === 'SIGN_WITH_CAUTION',
    recommendation,
    riskLevel,
    riskScore,
    schemaCategory: summaryKind,
    primaryType,
    domain: {
      name: domain.name ?? null,
      version: domain.version ?? null,
      chainId: domainChainIdBig !== null ? Number(domainChainIdBig) : null,
      verifyingContract: normalizedVerifyingContract,
      domainSeparator,
    },
    extractedSummary,
    findings: findings.map(({ points: _p, ...rest }) => rest),
  };
}
