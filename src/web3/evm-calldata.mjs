/**
 * Deterministic EVM Transaction Calldata Pre-Flight Decoder & Risk Scorer (`evm-calldata.mjs`).
 *
 * Decodes ERC-20, ERC-721/1155, Permit2, Uniswap V2/V3/UniversalRouter, 1inch, Multicall,
 * and Safe `execTransaction` payloads directly from raw ABI hex (`0` external RPC calls)
 * and flags unlimited approvals, `setApprovalForAll(true)`, `amountOutMin == 0` MEV sandwich
 * exposure, expired/excessive deadlines, non-zero native ETH sent with approvals, and `DELEGATECALL`.
 */

import { keccak256Hex, toEip55Address } from './crypto-primitives.mjs';
import { validateMultichainAddress } from './multichain-address.mjs';

export const CHAIN_NAMES = {
  1: 'Ethereum Mainnet',
  10: 'OP Mainnet',
  56: 'BNB Smart Chain',
  100: 'Gnosis Chain',
  137: 'Polygon PoS',
  324: 'zkSync Era',
  8453: 'Base Mainnet',
  42161: 'Arbitrum One',
  43114: 'Avalanche C-Chain',
  59144: 'Linea',
  84532: 'Base Sepolia',
  11155111: 'Ethereum Sepolia',
};

const MAX_UINT256 = (1n << 256n) - 1n;
const HALF_UINT256 = 1n << 255n;
const MAX_UINT160 = (1n << 160n) - 1n;
const HALF_UINT160 = 1n << 159n;
const MAX_UINT48 = (1n << 48n) - 1n;

export function selectorOf(sig) {
  return `0x${keccak256Hex(sig).slice(0, 8)}`;
}

function parseBigIntAmount(val, fieldName = 'value') {
  if (val === undefined || val === null || val === '') return 0n;
  if (typeof val === 'bigint') return val;
  if (typeof val === 'number') {
    if (!Number.isFinite(val) || val < 0 || !Number.isSafeInteger(val)) {
      throw new Error(`Invalid numeric ${fieldName}: pass decimal or 0x hex string for large wei values`);
    }
    return BigInt(val);
  }
  const s = String(val).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^\d+$/.test(s)) return BigInt(s);
  throw new Error(`Invalid ${fieldName} "${val}" (expected decimal integer or 0x hex string)`);
}

function readWordHex(bodyHex, wordIdx) {
  const start = wordIdx * 64;
  if (start + 64 > bodyHex.length) {
    throw new Error(`Truncated ABI calldata at 32-byte word #${wordIdx}`);
  }
  return bodyHex.slice(start, start + 64);
}

function readUint256(bodyHex, wordIdx) {
  return BigInt(`0x${readWordHex(bodyHex, wordIdx)}`);
}

function readAddress(bodyHex, wordIdx) {
  const word = readWordHex(bodyHex, wordIdx);
  return toEip55Address(word.slice(24));
}

function readBool(bodyHex, wordIdx) {
  return readUint256(bodyHex, wordIdx) !== 0n;
}

function readDynamicBytes(bodyHex, byteOffset) {
  const startHex = Number(byteOffset) * 2;
  if (!Number.isSafeInteger(startHex) || startHex < 0 || startHex + 64 > bodyHex.length) {
    throw new Error('Out-of-bounds ABI dynamic bytes offset');
  }
  const lenBytes = Number(BigInt(`0x${bodyHex.slice(startHex, startHex + 64)}`));
  const dataStart = startHex + 64;
  const dataEnd = dataStart + lenBytes * 2;
  if (!Number.isSafeInteger(dataEnd) || dataEnd > bodyHex.length) {
    throw new Error('Out-of-bounds ABI dynamic bytes length');
  }
  return `0x${bodyHex.slice(dataStart, dataEnd)}`;
}

function readAddressArray(bodyHex, byteOffset) {
  const startHex = Number(byteOffset) * 2;
  if (!Number.isSafeInteger(startHex) || startHex < 0 || startHex + 64 > bodyHex.length) {
    throw new Error('Out-of-bounds ABI address[] offset');
  }
  const count = Number(BigInt(`0x${bodyHex.slice(startHex, startHex + 64)}`));
  if (count > 64) throw new Error(`Excessive address[] length (${count})`);
  const out = [];
  for (let i = 0; i < count; i++) {
    const itemStart = startHex + 64 + i * 64;
    if (itemStart + 64 > bodyHex.length) throw new Error('Truncated ABI address[] element');
    out.push(toEip55Address(bodyHex.slice(itemStart + 24, itemStart + 64)));
  }
  return out;
}

function readBytesArray(bodyHex, byteOffset) {
  const startHex = Number(byteOffset) * 2;
  if (!Number.isSafeInteger(startHex) || startHex < 0 || startHex + 64 > bodyHex.length) {
    throw new Error('Out-of-bounds ABI bytes[] offset');
  }
  const count = Number(BigInt(`0x${bodyHex.slice(startHex, startHex + 64)}`));
  if (count > 32) throw new Error(`Excessive bytes[] batch length (${count})`);
  const headBase = startHex + 64;
  const out = [];
  for (let i = 0; i < count; i++) {
    const relOffsetPos = headBase + i * 64;
    if (relOffsetPos + 64 > bodyHex.length) throw new Error('Truncated ABI bytes[] element offset');
    const relBytes = Number(BigInt(`0x${bodyHex.slice(relOffsetPos, relOffsetPos + 64)}`));
    out.push(readDynamicBytes(bodyHex, headBase / 2 + relBytes));
  }
  return out;
}

const UNIVERSAL_ROUTER_COMMANDS = {
  0x00: 'V3_SWAP_EXACT_IN',
  0x01: 'V3_SWAP_EXACT_OUT',
  0x04: 'SWEEP',
  0x05: 'TRANSFER',
  0x06: 'PAY_PORTION',
  0x08: 'V2_SWAP_EXACT_IN',
  0x09: 'V2_SWAP_EXACT_OUT',
  0x0a: 'PERMIT2_PERMIT',
  0x0b: 'WRAP_ETH',
  0x0c: 'UNWRAP_WETH',
  0x0d: 'PERMIT2_TRANSFER_FROM_BATCH',
};

const SELECTOR_TABLE = new Map([
  [selectorOf('transfer(address,uint256)'), 'erc20_transfer'],
  [selectorOf('approve(address,uint256)'), 'erc20_approve'],
  [selectorOf('transferFrom(address,address,uint256)'), 'erc20_transferFrom'],
  [selectorOf('increaseAllowance(address,uint256)'), 'erc20_increaseAllowance'],
  [selectorOf('decreaseAllowance(address,uint256)'), 'erc20_decreaseAllowance'],
  [selectorOf('permit(address,address,uint256,uint256,uint8,bytes32,bytes32)'), 'eip2612_permit'],
  [selectorOf('setApprovalForAll(address,bool)'), 'nft_setApprovalForAll'],
  [selectorOf('safeTransferFrom(address,address,uint256)'), 'erc721_safeTransferFrom'],
  [selectorOf('safeTransferFrom(address,address,uint256,bytes)'), 'erc721_safeTransferFromBytes'],
  [selectorOf('safeTransferFrom(address,address,uint256,uint256,bytes)'), 'erc1155_safeTransferFrom'],
  [selectorOf('approve(address,address,uint160,uint48)'), 'permit2_approve'],
  [selectorOf('permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)'), 'permit2_permitSingle'],
  [selectorOf('swapExactTokensForTokens(uint256,uint256,address[],address,uint256)'), 'univ2_swapExactTokensForTokens'],
  [selectorOf('swapExactETHForTokens(uint256,address[],address,uint256)'), 'univ2_swapExactETHForTokens'],
  [selectorOf('swapExactTokensForETH(uint256,uint256,address[],address,uint256)'), 'univ2_swapExactTokensForETH'],
  [selectorOf('exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))'), 'univ3_exactInputSingle_v1'],
  [selectorOf('exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))'), 'univ3_exactInputSingle_v2'],
  [selectorOf('execute(bytes,bytes[],uint256)'), 'universalRouter_execute_deadline'],
  [selectorOf('execute(bytes,bytes[])'), 'universalRouter_execute'],
  [selectorOf('swap(address,(address,address,address,address,uint256,uint256,uint256),bytes,bytes)'), 'oneinch_swap'],
  [selectorOf('multicall(bytes[])'), 'multicall_bytes'],
  [selectorOf('multicall(uint256,bytes[])'), 'multicall_deadline_bytes'],
  [selectorOf('execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)'), 'safe_execTransaction'],
]);

function checkDeadlineFindings(deadlineBig, nowSec, findings, label = 'deadline') {
  const dl = Number(deadlineBig);
  if (deadlineBig === 0n || dl < nowSec) {
    findings.push({
      code: 'EXPIRED_DEADLINE',
      severity: 'HIGH',
      points: 35,
      message: `Transaction ${label} (${deadlineBig.toString()}) is already in the past relative to ${nowSec} — call will revert or waste gas.`,
    });
  } else if (deadlineBig >= MAX_UINT48 || dl > nowSec + 86400 * 30) {
    findings.push({
      code: 'EXCESSIVE_DEADLINE_WINDOW',
      severity: 'MEDIUM',
      points: 20,
      message: `Transaction ${label} (${deadlineBig.toString()}) remains valid > 30 days (or near-infinite), leaving long-lived mempool/execution exposure.`,
    });
  }
}

function checkBurnRecipient(addr, findings, role = 'recipient') {
  const v = validateMultichainAddress({ address: addr, chain: 'evm' });
  if (v.isBurnOrSystemTrap) {
    findings.push({
      code: 'BURN_ADDRESS_TARGET',
      severity: 'CRITICAL',
      points: 90,
      message: `Decoded ${role} (${addr}) is a burn/precompile blackhole address.`,
    });
  }
}

export function decodeAndAuditEvmCalldata({
  to = '',
  value = '0',
  data = '0x',
  chainId = 8453,
  sender = '',
  referenceTimestamp = null,
  _depth = 0,
} = {}) {
  const nowSec =
    referenceTimestamp !== null && referenceTimestamp !== undefined
      ? Number(referenceTimestamp)
      : Math.floor(Date.now() / 1000);

  const findings = [];
  const weiValue = parseBigIntAmount(value, 'value');
  const rawData = String(data || '0x').trim();

  if (!/^0x([0-9a-fA-F]{2})*$/.test(rawData)) {
    throw new Error('`data` must be a valid 0x-prefixed even-length hexadecimal string.');
  }

  let normalizedTo = null;
  const trimmedTo = String(to || '').trim();
  if (!trimmedTo) {
    findings.push({
      code: 'CONTRACT_DEPLOYMENT_NO_TO',
      severity: rawData.length > 2 ? 'MEDIUM' : 'HIGH',
      points: 30,
      message: 'Transaction has empty `to` address, which deploys arbitrary bytecode on-chain.',
    });
  } else {
    const toCheck = validateMultichainAddress({ address: trimmedTo, chain: 'evm' });
    if (!toCheck.valid) {
      findings.push({
        code: 'INVALID_TARGET_ADDRESS_CHECKSUM',
        severity: 'CRITICAL',
        points: 95,
        message: toCheck.errors[0]?.message || `Invalid target EVM address "${trimmedTo}".`,
      });
      normalizedTo = toCheck.canonicalAddress || trimmedTo;
    } else {
      normalizedTo = toCheck.canonicalAddress;
      if (toCheck.isBurnOrSystemTrap) {
        findings.push({
          code: 'TARGET_IS_BURN_OR_PRECOMPILE',
          severity: 'CRITICAL',
          points: 95,
          message: `Transaction target ${normalizedTo} is a burn or precompile address.`,
        });
      } else if (toCheck.checksumStatus === 'unchecksummed_normalized') {
        findings.push({
          code: 'TARGET_UNCHECKSUMMED',
          severity: 'LOW',
          points: 5,
          message: `Target address lacked EIP-55 mixed-case checksum; normalized to ${normalizedTo}.`,
        });
      }
    }
  }

  let normalizedSender = null;
  if (sender && String(sender).trim()) {
    const sCheck = validateMultichainAddress({ address: String(sender).trim(), chain: 'evm' });
    if (sCheck.valid) normalizedSender = sCheck.canonicalAddress;
  }

  // Case 1: Empty calldata (native ETH / gas-token transfer)
  if (rawData === '0x' || rawData.length === 2) {
    if (weiValue === 0n && trimmedTo) {
      findings.push({
        code: 'ZERO_VALUE_EMPTY_CALLDATA',
        severity: 'LOW',
        points: 5,
        message: 'Zero-value transaction with empty calldata (no-op / self-nonce cancel).',
      });
    }
    return buildCalldataVerdict({
      chainId,
      to: normalizedTo,
      weiValue,
      selector: null,
      standard: 'NATIVE_TRANSFER',
      functionName: 'nativeTransfer',
      decodedArgs: { to: normalizedTo, valueWei: weiValue.toString() },
      subCalls: [],
      findings,
    });
  }

  if (rawData.length < 10) {
    findings.push({
      code: 'SHORT_SELECTOR_CALLDATA',
      severity: 'HIGH',
      points: 60,
      message: `Calldata (${(rawData.length - 2) / 2} bytes) is shorter than a 4-byte function selector and will trigger fallback.`,
    });
    return buildCalldataVerdict({
      chainId,
      to: normalizedTo,
      weiValue,
      selector: rawData.toLowerCase(),
      standard: 'FALLBACK_RAW',
      functionName: 'fallback',
      decodedArgs: { rawHex: rawData },
      subCalls: [],
      findings,
    });
  }

  const selector = rawData.slice(0, 10).toLowerCase();
  const bodyHex = rawData.slice(10);
  const kind = SELECTOR_TABLE.get(selector) || 'unknown_selector';

  let standard = 'UNKNOWN_CONTRACT_CALL';
  let functionName = `unknown_${selector}`;
  let decodedArgs = { rawBodyBytes: bodyHex.length / 2 };
  const subCalls = [];

  try {
    switch (kind) {
      case 'erc20_transfer': {
        standard = 'ERC-20';
        functionName = 'transfer(address,uint256)';
        const recipient = readAddress(bodyHex, 0);
        const amount = readUint256(bodyHex, 1);
        decodedArgs = { to: recipient, amount: amount.toString() };
        checkBurnRecipient(recipient, findings, 'transfer recipient');
        if (weiValue > 0n) {
          findings.push({
            code: 'NONZERO_ETH_ON_ERC20_CALL',
            severity: 'HIGH',
            points: 55,
            message: `Non-zero native ETH value (${weiValue} wei) attached to ERC-20 transfer — standard tokens revert or trap ETH.`,
          });
        }
        break;
      }

      case 'erc20_approve':
      case 'erc20_increaseAllowance': {
        standard = 'ERC-20';
        functionName =
          kind === 'erc20_approve' ? 'approve(address,uint256)' : 'increaseAllowance(address,uint256)';
        const spender = readAddress(bodyHex, 0);
        const amount = readUint256(bodyHex, 1);
        const isUnlimited = amount >= HALF_UINT256;
        decodedArgs = {
          spender,
          amount: amount.toString(),
          isMaxUint256: amount === MAX_UINT256,
          isUnlimited,
        };
        if (isUnlimited) {
          findings.push({
            code: 'UNLIMITED_ERC20_APPROVAL',
            severity: 'CRITICAL',
            points: 85,
            message: `Grants UNLIMITED token spending allowance (${amount === MAX_UINT256 ? 'MAX_UINT256' : '>= 2^255'}) to spender ${spender}. Scope approval to exact transfer amount instead.`,
          });
        }
        if (weiValue > 0n) {
          findings.push({
            code: 'NONZERO_ETH_ON_APPROVAL',
            severity: 'CRITICAL',
            points: 85,
            message: `Non-zero native ETH value (${weiValue} wei) sent alongside token approval — classic phishing drain pattern!`,
          });
        }
        break;
      }

      case 'erc20_decreaseAllowance': {
        standard = 'ERC-20';
        functionName = 'decreaseAllowance(address,uint256)';
        decodedArgs = {
          spender: readAddress(bodyHex, 0),
          subtractedValue: readUint256(bodyHex, 1).toString(),
        };
        break;
      }

      case 'erc20_transferFrom': {
        standard = 'ERC-20';
        functionName = 'transferFrom(address,address,uint256)';
        const from = readAddress(bodyHex, 0);
        const recipient = readAddress(bodyHex, 1);
        const amount = readUint256(bodyHex, 2);
        decodedArgs = { from, to: recipient, amount: amount.toString() };
        checkBurnRecipient(recipient, findings, 'transferFrom recipient');
        break;
      }

      case 'eip2612_permit': {
        standard = 'EIP-2612';
        functionName = 'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)';
        const owner = readAddress(bodyHex, 0);
        const spender = readAddress(bodyHex, 1);
        const amount = readUint256(bodyHex, 2);
        const deadline = readUint256(bodyHex, 3);
        decodedArgs = { owner, spender, value: amount.toString(), deadline: deadline.toString() };
        if (amount >= HALF_UINT256) {
          findings.push({
            code: 'UNLIMITED_PERMIT_CALLDATA',
            severity: 'CRITICAL',
            points: 85,
            message: `On-chain EIP-2612 permit grants unlimited allowance to ${spender}.`,
          });
        }
        checkDeadlineFindings(deadline, nowSec, findings, 'permit deadline');
        break;
      }

      case 'nft_setApprovalForAll': {
        standard = 'ERC-721 / ERC-1155';
        functionName = 'setApprovalForAll(address,bool)';
        const operator = readAddress(bodyHex, 0);
        const approved = readBool(bodyHex, 1);
        decodedArgs = { operator, approved };
        if (approved) {
          findings.push({
            code: 'NFT_APPROVAL_FOR_ALL_ENABLED',
            severity: 'CRITICAL',
            points: 85,
            message: `setApprovalForAll(true) grants operator ${operator} unrestricted custody over EVERY NFT/token in this collection.`,
          });
        }
        if (weiValue > 0n) {
          findings.push({
            code: 'NONZERO_ETH_ON_APPROVAL',
            severity: 'CRITICAL',
            points: 85,
            message: `Non-zero native ETH (${weiValue} wei) sent with setApprovalForAll.`,
          });
        }
        break;
      }

      case 'erc721_safeTransferFrom':
      case 'erc721_safeTransferFromBytes': {
        standard = 'ERC-721';
        functionName = 'safeTransferFrom';
        const from = readAddress(bodyHex, 0);
        const recipient = readAddress(bodyHex, 1);
        const tokenId = readUint256(bodyHex, 2);
        decodedArgs = { from, to: recipient, tokenId: tokenId.toString() };
        checkBurnRecipient(recipient, findings, 'NFT recipient');
        break;
      }

      case 'erc1155_safeTransferFrom': {
        standard = 'ERC-1155';
        functionName = 'safeTransferFrom(address,address,uint256,uint256,bytes)';
        const from = readAddress(bodyHex, 0);
        const recipient = readAddress(bodyHex, 1);
        const id = readUint256(bodyHex, 2);
        const amount = readUint256(bodyHex, 3);
        decodedArgs = { from, to: recipient, tokenId: id.toString(), amount: amount.toString() };
        checkBurnRecipient(recipient, findings, 'ERC-1155 recipient');
        break;
      }

      case 'permit2_approve': {
        standard = 'Permit2';
        functionName = 'approve(address,address,uint160,uint48)';
        const token = readAddress(bodyHex, 0);
        const spender = readAddress(bodyHex, 1);
        const amount = readUint256(bodyHex, 2);
        const expiration = readUint256(bodyHex, 3);
        decodedArgs = {
          token,
          spender,
          amount: amount.toString(),
          expiration: expiration.toString(),
        };
        if (amount >= HALF_UINT160) {
          findings.push({
            code: 'UNLIMITED_PERMIT2_APPROVAL',
            severity: 'CRITICAL',
            points: 85,
            message: `Permit2 approve grants MAX_UINT160 / near-unlimited sub-allowance of token ${token} to spender ${spender}.`,
          });
        }
        checkDeadlineFindings(expiration, nowSec, findings, 'Permit2 expiration');
        break;
      }

      case 'permit2_permitSingle': {
        standard = 'Permit2';
        functionName = 'permit(address,PermitSingle,bytes)';
        const owner = readAddress(bodyHex, 0);
        const token = readAddress(bodyHex, 1);
        const amount = readUint256(bodyHex, 2);
        const expiration = readUint256(bodyHex, 3);
        const nonce = readUint256(bodyHex, 4);
        const spender = readAddress(bodyHex, 5);
        const sigDeadline = readUint256(bodyHex, 6);
        decodedArgs = {
          owner,
          token,
          spender,
          amount: amount.toString(),
          expiration: expiration.toString(),
          nonce: nonce.toString(),
          sigDeadline: sigDeadline.toString(),
        };
        if (amount >= HALF_UINT160) {
          findings.push({
            code: 'UNLIMITED_PERMIT2_APPROVAL',
            severity: 'CRITICAL',
            points: 85,
            message: `Permit2 PermitSingle grants unlimited uint160 allowance of ${token} to ${spender}.`,
          });
        }
        checkDeadlineFindings(expiration, nowSec, findings, 'Permit2 expiration');
        checkDeadlineFindings(sigDeadline, nowSec, findings, 'Permit2 sigDeadline');
        break;
      }

      case 'univ2_swapExactTokensForTokens':
      case 'univ2_swapExactTokensForETH': {
        standard = 'Uniswap V2 Router';
        functionName =
          kind === 'univ2_swapExactTokensForTokens'
            ? 'swapExactTokensForTokens'
            : 'swapExactTokensForETH';
        const amountIn = readUint256(bodyHex, 0);
        const amountOutMin = readUint256(bodyHex, 1);
        const pathOffset = readUint256(bodyHex, 2);
        const recipient = readAddress(bodyHex, 3);
        const deadline = readUint256(bodyHex, 4);
        const path = readAddressArray(bodyHex, pathOffset);
        decodedArgs = {
          amountIn: amountIn.toString(),
          amountOutMin: amountOutMin.toString(),
          path,
          to: recipient,
          deadline: deadline.toString(),
        };
        if (amountOutMin === 0n) {
          findings.push({
            code: 'ZERO_SLIPPAGE_MIN_OUT_MEV_RISK',
            severity: 'CRITICAL',
            points: 90,
            message:
              'Swap specifies `amountOutMin == 0` (100% slippage tolerance) — MEV sandwich bots can drain virtually the entire swap value!',
          });
        }
        checkBurnRecipient(recipient, findings, 'swap output recipient');
        if (normalizedSender && recipient !== normalizedSender) {
          findings.push({
            code: 'SWAP_OUTPUT_DIVERTED_TO_THIRD_PARTY',
            severity: 'HIGH',
            points: 50,
            message: `Swap output recipient (${recipient}) differs from transaction sender (${normalizedSender}).`,
          });
        }
        checkDeadlineFindings(deadline, nowSec, findings, 'swap deadline');
        break;
      }

      case 'univ2_swapExactETHForTokens': {
        standard = 'Uniswap V2 Router';
        functionName = 'swapExactETHForTokens';
        const amountOutMin = readUint256(bodyHex, 0);
        const pathOffset = readUint256(bodyHex, 1);
        const recipient = readAddress(bodyHex, 2);
        const deadline = readUint256(bodyHex, 3);
        const path = readAddressArray(bodyHex, pathOffset);
        decodedArgs = {
          ethInWei: weiValue.toString(),
          amountOutMin: amountOutMin.toString(),
          path,
          to: recipient,
          deadline: deadline.toString(),
        };
        if (amountOutMin === 0n) {
          findings.push({
            code: 'ZERO_SLIPPAGE_MIN_OUT_MEV_RISK',
            severity: 'CRITICAL',
            points: 90,
            message: 'Swap specifies `amountOutMin == 0` — exposed to 100% MEV sandwich extraction!',
          });
        }
        checkBurnRecipient(recipient, findings, 'swap output recipient');
        if (normalizedSender && recipient !== normalizedSender) {
          findings.push({
            code: 'SWAP_OUTPUT_DIVERTED_TO_THIRD_PARTY',
            severity: 'HIGH',
            points: 50,
            message: `Swap output recipient (${recipient}) differs from transaction sender (${normalizedSender}).`,
          });
        }
        checkDeadlineFindings(deadline, nowSec, findings, 'swap deadline');
        break;
      }

      case 'univ3_exactInputSingle_v1':
      case 'univ3_exactInputSingle_v2': {
        standard = 'Uniswap V3 SwapRouter';
        functionName = 'exactInputSingle';
        const tokenIn = readAddress(bodyHex, 0);
        const tokenOut = readAddress(bodyHex, 1);
        const fee = Number(readUint256(bodyHex, 2));
        const recipient = readAddress(bodyHex, 3);
        let deadline = null;
        let amountIn;
        let amountOutMinimum;
        let sqrtPriceLimitX96;
        if (kind === 'univ3_exactInputSingle_v1') {
          deadline = readUint256(bodyHex, 4);
          amountIn = readUint256(bodyHex, 5);
          amountOutMinimum = readUint256(bodyHex, 6);
          sqrtPriceLimitX96 = readUint256(bodyHex, 7);
          checkDeadlineFindings(deadline, nowSec, findings, 'V3 swap deadline');
        } else {
          amountIn = readUint256(bodyHex, 4);
          amountOutMinimum = readUint256(bodyHex, 5);
          sqrtPriceLimitX96 = readUint256(bodyHex, 6);
        }
        decodedArgs = {
          tokenIn,
          tokenOut,
          feeBps: fee,
          recipient,
          ...(deadline !== null ? { deadline: deadline.toString() } : {}),
          amountIn: amountIn.toString(),
          amountOutMinimum: amountOutMinimum.toString(),
          sqrtPriceLimitX96: sqrtPriceLimitX96.toString(),
        };
        if (amountOutMinimum === 0n && sqrtPriceLimitX96 === 0n) {
          findings.push({
            code: 'ZERO_SLIPPAGE_MIN_OUT_MEV_RISK',
            severity: 'CRITICAL',
            points: 90,
            message:
              'Uniswap V3 exactInputSingle sets both `amountOutMinimum == 0` and `sqrtPriceLimitX96 == 0` — unprotected against MEV sandwich attacks!',
          });
        }
        checkBurnRecipient(recipient, findings, 'V3 swap recipient');
        if (normalizedSender && recipient !== normalizedSender) {
          findings.push({
            code: 'SWAP_OUTPUT_DIVERTED_TO_THIRD_PARTY',
            severity: 'HIGH',
            points: 50,
            message: `Swap output recipient (${recipient}) differs from sender (${normalizedSender}).`,
          });
        }
        break;
      }

      case 'universalRouter_execute_deadline':
      case 'universalRouter_execute': {
        standard = 'Uniswap UniversalRouter';
        functionName = kind === 'universalRouter_execute_deadline' ? 'execute(bytes,bytes[],uint256)' : 'execute(bytes,bytes[])';
        const commandsOffset = readUint256(bodyHex, 0);
        const inputsOffset = readUint256(bodyHex, 1);
        const commandsHex = readDynamicBytes(bodyHex, commandsOffset).slice(2);
        const inputs = readBytesArray(bodyHex, inputsOffset);
        const commandNames = [];
        for (let i = 0; i < commandsHex.length; i += 2) {
          const byte = parseInt(commandsHex.slice(i, i + 2), 16) & 0x3f;
          commandNames.push(UNIVERSAL_ROUTER_COMMANDS[byte] || `CMD_0x${byte.toString(16)}`);
        }
        decodedArgs = {
          commands: commandNames,
          inputCount: inputs.length,
        };
        if (kind === 'universalRouter_execute_deadline') {
          const deadline = readUint256(bodyHex, 2);
          decodedArgs.deadline = deadline.toString();
          checkDeadlineFindings(deadline, nowSec, findings, 'UniversalRouter deadline');
        }
        commandNames.forEach((cmdName, idx) => {
          const inpHex = inputs[idx] ? inputs[idx].slice(2) : '';
          if ((cmdName === 'V3_SWAP_EXACT_IN' || cmdName === 'V2_SWAP_EXACT_IN') && inpHex.length >= 192) {
            const amtOutMin = BigInt(`0x${inpHex.slice(128, 192)}`);
            if (amtOutMin === 0n) {
              findings.push({
                code: 'ZERO_SLIPPAGE_MIN_OUT_MEV_RISK',
                severity: 'CRITICAL',
                points: 90,
                message: `UniversalRouter command #${idx} (${cmdName}) has amountOutMin == 0 — severe MEV sandwich vulnerability.`,
              });
            }
          }
        });
        break;
      }

      case 'oneinch_swap': {
        standard = '1inch AggregationRouter';
        functionName = 'swap(address,SwapDescription,bytes,bytes)';
        const executor = readAddress(bodyHex, 0);
        const descOffsetWords = Number(readUint256(bodyHex, 1)) / 32;
        const srcToken = readAddress(bodyHex, descOffsetWords + 0);
        const dstToken = readAddress(bodyHex, descOffsetWords + 1);
        const srcReceiver = readAddress(bodyHex, descOffsetWords + 2);
        const dstReceiver = readAddress(bodyHex, descOffsetWords + 3);
        const amount = readUint256(bodyHex, descOffsetWords + 4);
        const minReturnAmount = readUint256(bodyHex, descOffsetWords + 5);
        decodedArgs = {
          executor,
          srcToken,
          dstToken,
          srcReceiver,
          dstReceiver,
          amount: amount.toString(),
          minReturnAmount: minReturnAmount.toString(),
        };
        if (minReturnAmount === 0n) {
          findings.push({
            code: 'ZERO_SLIPPAGE_MIN_OUT_MEV_RISK',
            severity: 'CRITICAL',
            points: 90,
            message: '1inch swap sets `minReturnAmount == 0` — 100% exposed to MEV sandwiching.',
          });
        }
        checkBurnRecipient(dstReceiver, findings, '1inch dstReceiver');
        break;
      }

      case 'multicall_bytes':
      case 'multicall_deadline_bytes': {
        standard = 'Multicall';
        functionName = kind === 'multicall_deadline_bytes' ? 'multicall(uint256,bytes[])' : 'multicall(bytes[])';
        let arrOffset;
        if (kind === 'multicall_deadline_bytes') {
          const deadline = readUint256(bodyHex, 0);
          arrOffset = readUint256(bodyHex, 1);
          decodedArgs.deadline = deadline.toString();
          checkDeadlineFindings(deadline, nowSec, findings, 'multicall deadline');
        } else {
          arrOffset = readUint256(bodyHex, 0);
        }
        const innerPayloads = readBytesArray(bodyHex, arrOffset);
        decodedArgs.callCount = innerPayloads.length;
        if (_depth < 3) {
          innerPayloads.forEach((innerHex, idx) => {
            const sub = decodeAndAuditEvmCalldata({
              to: normalizedTo || trimmedTo,
              value: '0',
              data: innerHex,
              chainId,
              sender,
              referenceTimestamp: nowSec,
              _depth: _depth + 1,
            });
            subCalls.push({ index: idx, functionName: sub.functionName, riskLevel: sub.riskLevel, decodedArgs: sub.decodedArgs });
            for (const f of sub.findings) {
              if (f.code !== 'TARGET_UNCHECKSUMMED') {
                findings.push({
                  ...f,
                  message: `[Multicall #${idx}: ${sub.functionName}] ${f.message}`,
                });
              }
            }
          });
        }
        break;
      }

      case 'safe_execTransaction': {
        standard = 'Safe Smart Account';
        functionName = 'execTransaction';
        const innerTo = readAddress(bodyHex, 0);
        const innerValue = readUint256(bodyHex, 1);
        const dataOffset = readUint256(bodyHex, 2);
        const operation = Number(readUint256(bodyHex, 3));
        const innerData = readDynamicBytes(bodyHex, dataOffset);
        decodedArgs = {
          to: innerTo,
          valueWei: innerValue.toString(),
          operation: operation === 1 ? 'DELEGATECALL (1)' : 'CALL (0)',
          innerDataBytes: (innerData.length - 2) / 2,
        };
        if (operation === 1) {
          findings.push({
            code: 'SAFE_DELEGATECALL_EXECUTION',
            severity: 'CRITICAL',
            points: 95,
            message: `Safe execTransaction uses operation=1 (DELEGATECALL) into ${innerTo}, allowing full storage & owner takeover if target is not a canonical Safe migration/MultiSend library!`,
          });
        }
        if (_depth < 3) {
          const sub = decodeAndAuditEvmCalldata({
            to: innerTo,
            value: innerValue.toString(),
            data: innerData,
            chainId,
            sender: normalizedTo || sender,
            referenceTimestamp: nowSec,
            _depth: _depth + 1,
          });
          subCalls.push({ index: 0, functionName: sub.functionName, riskLevel: sub.riskLevel, decodedArgs: sub.decodedArgs });
          for (const f of sub.findings) {
            findings.push({
              ...f,
              message: `[Safe Inner Tx -> ${sub.functionName}] ${f.message}`,
            });
          }
        }
        break;
      }

      default: {
        findings.push({
          code: 'RAW_SELECTOR_UNVERIFIED',
          severity: weiValue > 0n ? 'HIGH' : 'MEDIUM',
          points: weiValue > 0n ? 45 : 25,
          message: `Unrecognized 4-byte selector ${selector}${weiValue > 0n ? ` with ${weiValue} wei native value attached` : ''}. Verify target contract ABI before signing.`,
        });
      }
    }
  } catch (decodeErr) {
    findings.push({
      code: 'MALFORMED_ABI_CALLDATA',
      severity: 'HIGH',
      points: 65,
      message: `ABI decoding failed for selector ${selector}: ${decodeErr.message}`,
    });
  }

  return buildCalldataVerdict({
    chainId,
    to: normalizedTo,
    weiValue,
    selector,
    standard,
    functionName,
    decodedArgs,
    subCalls,
    findings,
  });
}

function buildCalldataVerdict({
  chainId,
  to,
  weiValue,
  selector,
  standard,
  functionName,
  decodedArgs,
  subCalls,
  findings,
}) {
  const rawScore = findings.reduce((acc, f) => acc + (f.points || 10), 0);
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
      ? 'BLOCK_TRANSACTION'
      : riskLevel === 'HIGH'
        ? 'REQUIRE_HUMAN_REVIEW'
        : riskLevel === 'MEDIUM'
          ? 'PROCEED_WITH_CAUTION'
          : 'ALLOW';

  return {
    safeToExecute: recommendation === 'ALLOW' || recommendation === 'PROCEED_WITH_CAUTION',
    recommendation,
    riskLevel,
    riskScore,
    chainId: Number(chainId),
    chainName: CHAIN_NAMES[Number(chainId)] || `EVM Chain ${chainId}`,
    target: to,
    valueWei: weiValue.toString(),
    selector,
    standard,
    functionName,
    decodedArgs,
    ...(subCalls.length > 0 ? { subCalls } : {}),
    findings: findings.map(({ points: _p, ...rest }) => rest),
  };
}
