/**
 * 8-Chain Deterministic Address Validator & Burn/Trap Guard (`multichain-address.mjs`).
 *
 * Supported ecosystems:
 * 1. `evm` (Ethereum, Base, Arbitrum, Polygon, Optimism, BNB, Avalanche, etc. — EIP-55 Keccak-256)
 * 2. `tron` (`T...` SHA-256d Base58Check, 0x41 mainnet / 0xa0 Shasta testnet)
 * 3. `bitcoin` (BIP-173 Bech32 `bc1q` SegWit v0, BIP-350 Bech32m `bc1p` Taproot v1+, P2PKH/P2SH Base58Check)
 * 4. `solana` (Base58 32-byte Ed25519 + mathematical on-curve wallet vs off-curve PDA check)
 * 5. `ton` (`EQ...` / `UQ...` / `kQ...` / `0Q...` CRC16-XMODEM + bounceable uninit-wallet trap warning + raw `0:hex`)
 * 6. `xrpl` (`r...` Ripple Base58Check + XLS-5d `X...`/`T...` X-Address destination-tag decoder)
 * 7. `cosmos` (Bech32 `cosmos1`, `noble1`, `osmo1`, `celestia1`, `inj1`, `sei1`, `dydx1`, `thor1`, etc.)
 * 8. `stacks` (`SP`/`SM`/`ST`/`SN` c32check)
 */

import {
  BASE58_BTC_ALPHABET,
  BASE58_XRPL_ALPHABET,
  base58CheckDecode,
  base58CheckEncode,
  base58Decode,
  base58Encode,
  bech32Decode,
  c32CheckDecode,
  convertBits,
  crc16Xmodem,
  isOnEd25519Curve,
  toEip55Address,
} from './crypto-primitives.mjs';

const EVM_BURN_ADDRESSES = new Set([
  '0x0000000000000000000000000000000000000000',
  '0x000000000000000000000000000000000000dead',
  '0xdead000000000000000042069420694206942069',
  '0xffffffffffffffffffffffffffffffffffffffff',
]);

const SOLANA_SYSTEM_PROGRAMS = new Map([
  ['11111111111111111111111111111111', 'Solana System Program (all-zero burn/program ID)'],
  ['TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 'SPL Token Program executable'],
  ['TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb', 'SPL Token-2022 Program executable'],
  ['ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL', 'Associated Token Account Program'],
  ['1nc1nerator11111111111111111111111111111111', 'Solana Incinerator burn address'],
]);

const XRPL_BLACKHOLE_ADDRESSES = new Set([
  'rrrrrrrrrrrrrrrrrrrrrhoLvTp', // Account Zero
  'rrrrrrrrrrrrrrrrrrrrBZbvji', // Account One
  'rrrrrrrrrrrrrrrrrNAMEtxvNvQ', // Ripple Name blackhole
  'rrrrrrrrrrrrrrrrrrrn5RM1rHd', // NaN blackhole
]);

const COSMOS_HRPS = new Set([
  'cosmos',
  'noble',
  'osmo',
  'celestia',
  'inj',
  'sei',
  'dydx',
  'thor',
  'akash',
  'stride',
  'neutron',
  'kava',
  'evmos',
  'juno',
  'stars',
  'axelar',
  'secret',
  'terra',
]);

function finalizeResult({
  input,
  valid,
  chain,
  network = 'mainnet',
  addressType = 'unknown',
  canonicalAddress = null,
  alternateFormats = {},
  checksumStatus = 'none',
  isBurnOrSystemTrap = false,
  metadata = {},
  warnings = [],
  errors = [],
  expectedNetwork = 'any',
}) {
  const allWarnings = [...warnings];
  const allErrors = [...errors];

  if (
    valid &&
    expectedNetwork &&
    expectedNetwork !== 'any' &&
    network !== 'any' &&
    network !== expectedNetwork
  ) {
    allWarnings.push({
      code: 'NETWORK_ENVIRONMENT_MISMATCH',
      severity: 'CRITICAL',
      message: `Address belongs to "${network}", but caller expected "${expectedNetwork}". Sending mainnet assets to testnet (or vice versa) causes permanent loss.`,
    });
  }

  let riskLevel = 'SAFE';
  if (!valid || allErrors.length > 0) {
    riskLevel = 'CRITICAL';
  } else if (allWarnings.some((w) => w.severity === 'CRITICAL')) {
    riskLevel = 'CRITICAL';
  } else if (allWarnings.some((w) => w.severity === 'HIGH')) {
    riskLevel = 'HIGH';
  } else if (allWarnings.some((w) => w.severity === 'MEDIUM')) {
    riskLevel = 'MEDIUM';
  } else if (allWarnings.length > 0) {
    riskLevel = 'LOW';
  }

  const safeToTransact =
    valid &&
    allErrors.length === 0 &&
    !isBurnOrSystemTrap &&
    riskLevel !== 'CRITICAL';

  return {
    valid,
    safeToTransact,
    riskLevel,
    input,
    chain,
    network,
    addressType,
    canonicalAddress,
    alternateFormats,
    checksumStatus,
    isBurnOrSystemTrap,
    metadata,
    warnings: allWarnings,
    errors: allErrors,
  };
}

function validateEvm(addr, expectedNetwork) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'evm',
      errors: [{ code: 'INVALID_EVM_HEX_LENGTH', message: 'EVM address must be 0x followed by 40 hex characters.' }],
      expectedNetwork,
    });
  }

  const hexBody = addr.slice(2);
  const lower = `0x${hexBody.toLowerCase()}`;
  const eip55 = toEip55Address(hexBody);
  const isAllLower = hexBody === hexBody.toLowerCase();
  const isAllUpper = hexBody === hexBody.toUpperCase();
  const matchesEip55 = addr === eip55;

  if (!isAllLower && !isAllUpper && !matchesEip55) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'evm',
      network: 'mainnet',
      addressType: 'eoa_or_contract',
      canonicalAddress: eip55,
      checksumStatus: 'failed_eip55',
      errors: [
        {
          code: 'EIP55_CHECKSUM_MISMATCH',
          message: `Mixed-case EVM address failed Keccak-256 EIP-55 checksum (likely character typo). Expected "${eip55}".`,
        },
      ],
      expectedNetwork,
    });
  }

  const warnings = [];
  let isBurn = false;
  if (EVM_BURN_ADDRESSES.has(lower)) {
    isBurn = true;
    warnings.push({
      code: 'EVM_BURN_ADDRESS',
      severity: 'CRITICAL',
      message: `Address ${eip55} is a known EVM burn/blackhole address; transferred funds are permanently irrecoverable.`,
    });
  } else if (/^0x0{38}0[1-9a-f]$/.test(lower)) {
    isBurn = true;
    warnings.push({
      code: 'EVM_PRECOMPILE_ADDRESS',
      severity: 'CRITICAL',
      message: `Address ${eip55} is a reserved EVM precompile contract (0x01..0x0f); sending tokens here burns them.`,
    });
  }

  if ((isAllLower || isAllUpper) && /[a-f]/i.test(hexBody) && !matchesEip55) {
    warnings.push({
      code: 'UNCHECKSUMMED_EVM_ADDRESS',
      severity: 'LOW',
      message: `Input lacked EIP-55 mixed-case checksum protection. Normalized to canonical EIP-55 "${eip55}".`,
    });
  }

  return finalizeResult({
    input: addr,
    valid: true,
    chain: 'evm',
    network: expectedNetwork === 'testnet' ? 'testnet' : 'mainnet',
    addressType: 'eoa_or_contract',
    canonicalAddress: eip55,
    alternateFormats: { lowercase: lower },
    checksumStatus: matchesEip55 ? 'valid_eip55' : 'unchecksummed_normalized',
    isBurnOrSystemTrap: isBurn,
    warnings,
    expectedNetwork,
  });
}

function validateTron(addr, expectedNetwork) {
  try {
    const payload = base58CheckDecode(addr, BASE58_BTC_ALPHABET);
    if (payload.length !== 21 || (payload[0] !== 0x41 && payload[0] !== 0xa0)) {
      return finalizeResult({
        input: addr,
        valid: false,
        chain: 'tron',
        errors: [
          {
            code: 'INVALID_TRON_VERSION_OR_LENGTH',
            message: 'Tron Base58Check payload must be 21 bytes starting with 0x41 (mainnet) or 0xa0 (testnet).',
          },
        ],
        expectedNetwork,
      });
    }
    const network = payload[0] === 0x41 ? 'mainnet' : 'testnet';
    const bodyHex = Buffer.from(payload.subarray(1)).toString('hex');
    const evmEquivalent = toEip55Address(bodyHex);
    const warnings = [];
    let isBurn = false;
    if (/^0{40}$/.test(bodyHex) || addr === 'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb') {
      isBurn = true;
      warnings.push({
        code: 'TRON_ZERO_BURN_ADDRESS',
        severity: 'CRITICAL',
        message: 'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb is the Tron zero/blackhole burn address.',
      });
    }
    return finalizeResult({
      input: addr,
      valid: true,
      chain: 'tron',
      network,
      addressType: 'tron_account_or_trc20',
      canonicalAddress: addr,
      alternateFormats: {
        tronHex: Buffer.from(payload).toString('hex'),
        evmHexEquivalent: evmEquivalent,
      },
      checksumStatus: 'valid_base58check',
      isBurnOrSystemTrap: isBurn,
      warnings,
      expectedNetwork,
    });
  } catch (err) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'tron',
      checksumStatus: 'failed_base58check',
      errors: [{ code: 'TRON_CHECKSUM_OR_ENCODING_ERROR', message: err.message }],
      expectedNetwork,
    });
  }
}

function validateBitcoin(addr, expectedNetwork) {
  // 1. SegWit / Taproot Bech32 & Bech32m
  if (/^(bc1|tb1|bcrt1)/i.test(addr)) {
    try {
      const dec = bech32Decode(addr, 90);
      if (dec.words.length < 1) {
        throw new Error('Empty SegWit witness data');
      }
      const witnessVersion = dec.words[0];
      if (witnessVersion > 16) {
        throw new Error(`Invalid SegWit witness version ${witnessVersion}`);
      }
      if (witnessVersion === 0 && dec.encoding !== 'bech32') {
        throw new Error('BIP-173/350 violation: SegWit v0 (bc1q/tb1q) MUST use Bech32, not Bech32m');
      }
      if (witnessVersion >= 1 && dec.encoding !== 'bech32m') {
        throw new Error('BIP-350 violation: SegWit v1+ Taproot (bc1p/tb1p) MUST use Bech32m, not Bech32');
      }
      const prog = convertBits(dec.words.slice(1), 5, 8, false);
      if (prog.length < 2 || prog.length > 40) {
        throw new Error(`Invalid witness program byte length (${prog.length})`);
      }
      if (witnessVersion === 0 && prog.length !== 20 && prog.length !== 32) {
        throw new Error(`SegWit v0 program must be 20 bytes (P2WPKH) or 32 bytes (P2WSH), got ${prog.length}`);
      }
      if (witnessVersion === 1 && prog.length !== 32) {
        throw new Error(`Taproot v1 program must be 32 bytes (P2TR), got ${prog.length}`);
      }

      const network = dec.hrp === 'bc' ? 'mainnet' : 'testnet';
      const addressType =
        witnessVersion === 0
          ? prog.length === 20
            ? 'p2wpkh_segwit_v0'
            : 'p2wsh_segwit_v0'
          : witnessVersion === 1
            ? 'p2tr_taproot_v1'
            : `segwit_v${witnessVersion}`;
      const warnings = [];
      if (dec.wasUppercase) {
        warnings.push({
          code: 'UPPERCASE_BECH32_NORMALIZED',
          severity: 'LOW',
          message: `Normalized uppercase Bech32 address to canonical lowercase "${dec.canonical}".`,
        });
      }
      return finalizeResult({
        input: addr,
        valid: true,
        chain: 'bitcoin',
        network,
        addressType,
        canonicalAddress: dec.canonical,
        checksumStatus: `valid_${dec.encoding}`,
        metadata: { witnessVersion, witnessProgramBytes: prog.length },
        warnings,
        expectedNetwork,
      });
    } catch (err) {
      return finalizeResult({
        input: addr,
        valid: false,
        chain: 'bitcoin',
        checksumStatus: 'failed_bech32',
        errors: [{ code: 'BITCOIN_SEGWIT_INVALID', message: err.message }],
        expectedNetwork,
      });
    }
  }

  // 2. Legacy P2PKH / P2SH Base58Check
  try {
    const payload = base58CheckDecode(addr, BASE58_BTC_ALPHABET);
    if (payload.length !== 21) {
      throw new Error(`Expected 21-byte Bitcoin Base58Check payload, got ${payload.length}`);
    }
    const ver = payload[0];
    let network = null;
    let addressType = null;
    if (ver === 0x00) {
      network = 'mainnet';
      addressType = 'p2pkh_legacy';
    } else if (ver === 0x05) {
      network = 'mainnet';
      addressType = 'p2sh';
    } else if (ver === 0x6f) {
      network = 'testnet';
      addressType = 'p2pkh_testnet';
    } else if (ver === 0xc4) {
      network = 'testnet';
      addressType = 'p2sh_testnet';
    } else {
      throw new Error(`Unrecognized Bitcoin Base58Check version byte 0x${ver.toString(16)}`);
    }

    const hash160Hex = Buffer.from(payload.subarray(1)).toString('hex');
    const warnings = [];
    let isBurn = false;
    if (/^0{40}$/.test(hash160Hex) || addr === '1BitcoinEaterAddressDontSendf59kuE') {
      isBurn = true;
      warnings.push({
        code: 'BITCOIN_BURN_ADDRESS',
        severity: 'CRITICAL',
        message: `${addr} is a provably unspendable Bitcoin burn address.`,
      });
    }
    return finalizeResult({
      input: addr,
      valid: true,
      chain: 'bitcoin',
      network,
      addressType,
      canonicalAddress: addr,
      checksumStatus: 'valid_base58check',
      isBurnOrSystemTrap: isBurn,
      metadata: { hash160Hex },
      warnings,
      expectedNetwork,
    });
  } catch (err) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'bitcoin',
      checksumStatus: 'failed_base58check',
      errors: [{ code: 'BITCOIN_LEGACY_INVALID', message: err.message }],
      expectedNetwork,
    });
  }
}

function validateSolana(addr, expectedNetwork) {
  try {
    const raw = base58Decode(addr, BASE58_BTC_ALPHABET);
    if (raw.length !== 32) {
      return finalizeResult({
        input: addr,
        valid: false,
        chain: 'solana',
        errors: [
          {
            code: 'INVALID_SOLANA_PUBKEY_LENGTH',
            message: `Solana Base58 public key must decode to exactly 32 bytes (got ${raw.length}).`,
          },
        ],
        expectedNetwork,
      });
    }

    const onCurve = isOnEd25519Curve(raw);
    const warnings = [];
    let isBurn = false;
    if (SOLANA_SYSTEM_PROGRAMS.has(addr)) {
      isBurn = true;
      warnings.push({
        code: 'SOLANA_SYSTEM_OR_BURN_PROGRAM',
        severity: 'CRITICAL',
        message: `${addr} is ${SOLANA_SYSTEM_PROGRAMS.get(addr)} — do NOT send user transfers directly here.`,
      });
    } else if (!onCurve) {
      warnings.push({
        code: 'SOLANA_OFF_CURVE_PDA',
        severity: 'MEDIUM',
        message:
          '32-byte key lies OFF the Ed25519 curve (Program Derived Address / PDA, e.g. vault or Associated Token Account). Verify whether recipient expects a user wallet owner pubkey vs token account PDA.',
      });
    }

    // Solana raw pubkeys have no embedded checksum — note this explicitly in metadata
    return finalizeResult({
      input: addr,
      valid: true,
      chain: 'solana',
      network: expectedNetwork === 'testnet' ? 'testnet' : 'mainnet',
      addressType: onCurve ? 'ed25519_wallet_pubkey' : 'program_derived_address_pda',
      canonicalAddress: base58Encode(raw, BASE58_BTC_ALPHABET),
      checksumStatus: 'structural_32byte_ed25519',
      isBurnOrSystemTrap: isBurn,
      metadata: { isOnEd25519Curve: onCurve, hex: Buffer.from(raw).toString('hex') },
      warnings,
      expectedNetwork,
    });
  } catch (err) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'solana',
      errors: [{ code: 'SOLANA_BASE58_DECODE_ERROR', message: err.message }],
      expectedNetwork,
    });
  }
}

function encodeTonFriendly(tagByte, workchainInt8, accountBytes32) {
  const payload34 = new Uint8Array(34);
  payload34[0] = tagByte;
  payload34[1] = workchainInt8 & 0xff;
  payload34.set(accountBytes32, 2);
  const crc = crc16Xmodem(payload34);
  const full36 = new Uint8Array(36);
  full36.set(payload34, 0);
  full36.set(crc, 34);
  return Buffer.from(full36)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function validateTon(addr, expectedNetwork) {
  // 1. Raw TON format `workchain:64hex`
  const rawMatch = addr.match(/^(-1|0):([0-9a-fA-F]{64})$/);
  if (rawMatch) {
    const wc = Number(rawMatch[1]);
    const acct = Uint8Array.from(Buffer.from(rawMatch[2].toLowerCase(), 'hex'));
    const uq = encodeTonFriendly(0x51, wc, acct);
    const eq = encodeTonFriendly(0x11, wc, acct);
    return finalizeResult({
      input: addr,
      valid: true,
      chain: 'ton',
      network: expectedNetwork === 'testnet' ? 'testnet' : 'mainnet',
      addressType: 'ton_raw_address',
      canonicalAddress: uq,
      alternateFormats: {
        nonBounceableUQ: uq,
        bounceableEQ: eq,
        raw: `${wc}:${rawMatch[2].toLowerCase()}`,
      },
      checksumStatus: 'raw_unchecksummed_converted_to_crc16',
      metadata: { workchain: wc },
      warnings: [
        {
          code: 'TON_RAW_ADDRESS_NO_CHECKSUM',
          severity: 'LOW',
          message: `Raw TON address lacks CRC16 checksum protection. Prefer non-bounceable friendly form "${uq}" for wallet transfers.`,
        },
      ],
      expectedNetwork,
    });
  }

  // 2. Friendly 48-char Base64 / Base64url (`EQ`, `UQ`, `kQ`, `0Q`)
  if (!/^[A-Za-z0-9+/_-]{48}$/.test(addr)) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'ton',
      errors: [{ code: 'INVALID_TON_ADDRESS_LENGTH', message: 'TON friendly address must be 48 Base64/Base64url characters.' }],
      expectedNetwork,
    });
  }

  const stdB64 = addr.replace(/-/g, '+').replace(/_/g, '/');
  const raw = new Uint8Array(Buffer.from(stdB64, 'base64'));
  if (raw.length !== 36) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'ton',
      errors: [{ code: 'INVALID_TON_BYTE_LENGTH', message: `Decoded TON address must be 36 bytes (got ${raw.length}).` }],
      expectedNetwork,
    });
  }

  const expectedCrc = crc16Xmodem(raw.subarray(0, 34));
  if (raw[34] !== expectedCrc[0] || raw[35] !== expectedCrc[1]) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'ton',
      checksumStatus: 'failed_crc16_xmodem',
      errors: [{ code: 'TON_CRC16_CHECKSUM_MISMATCH', message: 'TON friendly address failed 16-bit CRC16-XMODEM checksum verification.' }],
      expectedNetwork,
    });
  }

  const tag = raw[0];
  const isTestnet = (tag & 0x80) !== 0;
  const cleanTag = tag & 0x7f;
  if (cleanTag !== 0x11 && cleanTag !== 0x51) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'ton',
      errors: [{ code: 'INVALID_TON_TAG_BYTE', message: `Invalid TON address flag byte 0x${tag.toString(16)}.` }],
      expectedNetwork,
    });
  }

  const isBounceable = cleanTag === 0x11;
  const wc = raw[1] === 0xff ? -1 : raw[1];
  if (wc !== 0 && wc !== -1) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'ton',
      errors: [{ code: 'UNSUPPORTED_TON_WORKCHAIN', message: `Unsupported TON workchain ${wc} (expected 0 or -1).` }],
      expectedNetwork,
    });
  }

  const acct = raw.subarray(2, 34);
  const acctHex = Buffer.from(acct).toString('hex');
  const uqMainnet = encodeTonFriendly(isTestnet ? 0xd1 : 0x51, wc, acct);
  const eqMainnet = encodeTonFriendly(isTestnet ? 0x91 : 0x11, wc, acct);
  const canonicalCurrent = isBounceable ? eqMainnet : uqMainnet;

  const warnings = [];
  let isBurn = false;
  if (/^0{64}$/.test(acctHex)) {
    isBurn = true;
    warnings.push({
      code: 'TON_ZERO_BURN_ADDRESS',
      severity: 'CRITICAL',
      message: 'TON all-zero account ID is a blackhole burn address.',
    });
  }
  if (isBounceable) {
    warnings.push({
      code: 'TON_BOUNCEABLE_UNINIT_WALLET_TRAP',
      severity: 'MEDIUM',
      message: `Address uses bounceable flag (EQ...). If the recipient wallet contract is not yet deployed on-chain, TON transfers to EQ... bounce back minus gas fees. Use non-bounceable "${uqMainnet}" for EOA wallet payouts.`,
    });
  }

  return finalizeResult({
    input: addr,
    valid: true,
    chain: 'ton',
    network: isTestnet ? 'testnet' : 'mainnet',
    addressType: isBounceable ? 'ton_friendly_bounceable' : 'ton_friendly_non_bounceable',
    canonicalAddress: canonicalCurrent,
    alternateFormats: {
      nonBounceable: uqMainnet,
      bounceable: eqMainnet,
      raw: `${wc}:${acctHex}`,
    },
    checksumStatus: 'valid_crc16_xmodem',
    isBurnOrSystemTrap: isBurn,
    metadata: { workchain: wc, bounceable: isBounceable, testnetFlag: isTestnet },
    warnings,
    expectedNetwork,
  });
}

function validateXrpl(addr, expectedNetwork) {
  try {
    const payload = base58CheckDecode(addr, BASE58_XRPL_ALPHABET);

    // 1. Classic r-address (version 0x00 + 20-byte AccountID)
    if (payload.length === 21 && payload[0] === 0x00) {
      const warnings = [];
      let isBurn = false;
      if (XRPL_BLACKHOLE_ADDRESSES.has(addr)) {
        isBurn = true;
        warnings.push({
          code: 'XRPL_BLACKHOLE_ADDRESS',
          severity: 'CRITICAL',
          message: `${addr} is a well-known XRP Ledger blackhole/burn account.`,
        });
      } else {
        warnings.push({
          code: 'XRPL_CHECK_DESTINATION_TAG',
          severity: 'LOW',
          message:
            'Classic XRPL r-address encodes no Destination Tag. Confirm whether recipient is an exchange/custodial account requiring a Destination Tag (or X-Address).',
        });
      }
      return finalizeResult({
        input: addr,
        valid: true,
        chain: 'xrpl',
        network: expectedNetwork === 'testnet' ? 'testnet' : 'mainnet',
        addressType: 'xrpl_classic_r_address',
        canonicalAddress: addr,
        checksumStatus: 'valid_xrpl_base58check',
        isBurnOrSystemTrap: isBurn,
        metadata: {
          accountIdHex: Buffer.from(payload.subarray(1)).toString('hex'),
          destinationTag: null,
        },
        warnings,
        expectedNetwork,
      });
    }

    // 2. XLS-5d X-Address (31 bytes: 2B prefix + 20B AccountID + 1B flags + 8B LE tag)
    if (payload.length === 31) {
      let network = null;
      if (payload[0] === 0x05 && payload[1] === 0x44) network = 'mainnet';
      else if (payload[0] === 0x04 && payload[1] === 0x93) network = 'testnet';
      else throw new Error('Unrecognized XRPL X-Address network prefix');

      const accountId = payload.subarray(2, 22);
      const flags = payload[22];
      if (flags !== 0x00 && flags !== 0x01) {
        throw new Error(`Unsupported XRPL X-Address tag flag 0x${flags.toString(16)}`);
      }
      // Upper 4 bytes of 64-bit tag slot must be zero per XLS-5d
      if (payload[27] !== 0 || payload[28] !== 0 || payload[29] !== 0 || payload[30] !== 0) {
        throw new Error('Invalid non-zero upper 32 bits in XRPL X-Address tag');
      }
      const tag =
        flags === 0x01
          ? (payload[23] | (payload[24] << 8) | (payload[25] << 16) | (payload[26] * 0x1000000)) >>> 0
          : null;

      const classicPayload = new Uint8Array(21);
      classicPayload[0] = 0x00;
      classicPayload.set(accountId, 1);
      const classicAddress = base58CheckEncode(classicPayload, BASE58_XRPL_ALPHABET);

      return finalizeResult({
        input: addr,
        valid: true,
        chain: 'xrpl',
        network,
        addressType: 'xrpl_x_address',
        canonicalAddress: addr,
        alternateFormats: { classicAddress, destinationTag: tag },
        checksumStatus: 'valid_xrpl_base58check',
        isBurnOrSystemTrap: XRPL_BLACKHOLE_ADDRESSES.has(classicAddress),
        metadata: {
          classicAddress,
          destinationTag: tag,
          accountIdHex: Buffer.from(accountId).toString('hex'),
        },
        expectedNetwork,
      });
    }

    throw new Error(`Unexpected XRPL Base58Check payload length (${payload.length})`);
  } catch (err) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'xrpl',
      checksumStatus: 'failed_xrpl_base58check',
      errors: [{ code: 'XRPL_INVALID_ADDRESS', message: err.message }],
      expectedNetwork,
    });
  }
}

function validateCosmos(addr, expectedNetwork) {
  try {
    const dec = bech32Decode(addr, 120);
    if (dec.encoding !== 'bech32') {
      throw new Error(`Cosmos SDK addresses use standard Bech32 (got ${dec.encoding})`);
    }
    const bytes = convertBits(dec.words, 5, 8, false);
    if (bytes.length !== 20 && bytes.length !== 32) {
      throw new Error(`Cosmos address byte length must be 20 (account) or 32 (contract/module), got ${bytes.length}`);
    }
    const hex = Buffer.from(bytes).toString('hex');
    const isBurn = /^0+$/.test(hex);
    const warnings = [];
    if (isBurn) {
      warnings.push({
        code: 'COSMOS_ZERO_ADDRESS',
        severity: 'CRITICAL',
        message: 'All-zero Cosmos Bech32 address is unspendable.',
      });
    }
    return finalizeResult({
      input: addr,
      valid: true,
      chain: 'cosmos',
      network: 'mainnet',
      addressType: bytes.length === 20 ? `${dec.hrp}_account` : `${dec.hrp}_contract_32b`,
      canonicalAddress: dec.canonical,
      checksumStatus: 'valid_bech32',
      isBurnOrSystemTrap: isBurn,
      metadata: { hrp: dec.hrp, byteLength: bytes.length, hex },
      warnings,
      expectedNetwork,
    });
  } catch (err) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'cosmos',
      checksumStatus: 'failed_bech32',
      errors: [{ code: 'COSMOS_BECH32_INVALID', message: err.message }],
      expectedNetwork,
    });
  }
}

function validateStacks(addr, expectedNetwork) {
  const [principal, contractName] = String(addr).split('.');
  try {
    const dec = c32CheckDecode(principal);
    const network = dec.versionChar === 'P' || dec.versionChar === 'M' ? 'mainnet' : 'testnet';
    if (contractName !== undefined && !/^[a-zA-Z][a-zA-Z0-9_-]{0,127}$/.test(contractName)) {
      throw new Error(`Invalid Stacks contract name "${contractName}"`);
    }
    const canonical = contractName ? `${dec.canonical}.${contractName}` : dec.canonical;
    const isBurn = /^0{40}$/.test(dec.hash160Hex);
    const warnings = [];
    if (isBurn) {
      warnings.push({
        code: 'STACKS_BURN_ADDRESS',
        severity: 'CRITICAL',
        message: `${dec.canonical} is the Stacks all-zero burn address.`,
      });
    }
    return finalizeResult({
      input: addr,
      valid: true,
      chain: 'stacks',
      network,
      addressType: contractName ? 'stacks_contract_principal' : 'stacks_standard_principal',
      canonicalAddress: canonical,
      checksumStatus: 'valid_c32check',
      isBurnOrSystemTrap: isBurn,
      metadata: { hash160Hex: dec.hash160Hex, contractName: contractName || null },
      warnings,
      expectedNetwork,
    });
  } catch (err) {
    return finalizeResult({
      input: addr,
      valid: false,
      chain: 'stacks',
      checksumStatus: 'failed_c32check',
      errors: [{ code: 'STACKS_C32CHECK_INVALID', message: err.message }],
      expectedNetwork,
    });
  }
}

function inferChain(addr) {
  if (/^0x[0-9a-fA-F]*$/i.test(addr)) return 'evm';
  if (/^(bc1|tb1|bcrt1)/i.test(addr)) return 'bitcoin';
  if (/^(-1|0):[0-9a-fA-F]{64}$/.test(addr) || /^(EQ|UQ|kQ|0Q)[A-Za-z0-9+/_-]{46}$/.test(addr)) {
    return 'ton';
  }
  if (/^S[PMTN][0-9A-Za-z]{30,45}(\.[a-zA-Z][a-zA-Z0-9_-]*)?$/.test(addr)) return 'stacks';
  const lower = addr.toLowerCase();
  const oneIdx = lower.lastIndexOf('1');
  if (oneIdx >= 2 && COSMOS_HRPS.has(lower.slice(0, oneIdx))) return 'cosmos';
  if (/^r[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{24,34}$/.test(addr)) {
    return 'xrpl';
  }
  if (/^[XT][rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{45,47}$/.test(addr)) {
    try {
      const p = base58CheckDecode(addr, BASE58_XRPL_ALPHABET);
      if (p.length === 31) return 'xrpl';
    } catch {
      // Fall through to Tron check if starts with T
    }
  }
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(addr)) return 'tron';
  if (/^[13mn2][1-9A-HJ-NP-Za-km-z]{25,34}$/.test(addr)) {
    try {
      const p = base58CheckDecode(addr, BASE58_BTC_ALPHABET);
      if (p.length === 21) return 'bitcoin';
    } catch {
      // If 25..34 chars starting with 1/3/m/n/2 failed Base58Check, check if 32-byte Solana or typo'd BTC
      try {
        const raw = base58Decode(addr, BASE58_BTC_ALPHABET);
        if (raw.length === 32) return 'solana';
      } catch {
        // Invalid Base58
      }
      return 'bitcoin';
    }
  }
  return 'solana';
}

export function validateMultichainAddress({
  address,
  chain = 'auto',
  expectedNetwork = 'any',
} = {}) {
  const rawInput = String(address ?? '').trim();
  if (!rawInput) {
    throw new Error('`validate_multichain_address` requires a non-empty `address` string.');
  }

  const normalizedChain = String(chain || 'auto').trim().toLowerCase();
  const targetChain =
    normalizedChain === 'auto' || normalizedChain === '' ? inferChain(rawInput) : normalizedChain;

  const aliases = {
    ethereum: 'evm',
    eth: 'evm',
    base: 'evm',
    arbitrum: 'evm',
    polygon: 'evm',
    bsc: 'evm',
    optimism: 'evm',
    avalanche: 'evm',
    trx: 'tron',
    trc20: 'tron',
    btc: 'bitcoin',
    sol: 'solana',
    xrp: 'xrpl',
    ripple: 'xrpl',
    stx: 'stacks',
  };
  const canonicalChain = aliases[targetChain] || targetChain;

  switch (canonicalChain) {
    case 'evm':
      return validateEvm(rawInput, expectedNetwork);
    case 'tron':
      return validateTron(rawInput, expectedNetwork);
    case 'bitcoin':
      return validateBitcoin(rawInput, expectedNetwork);
    case 'solana':
      return validateSolana(rawInput, expectedNetwork);
    case 'ton':
      return validateTon(rawInput, expectedNetwork);
    case 'xrpl':
      return validateXrpl(rawInput, expectedNetwork);
    case 'cosmos':
      return validateCosmos(rawInput, expectedNetwork);
    case 'stacks':
      return validateStacks(rawInput, expectedNetwork);
    default:
      throw new Error(
        `Unsupported chain "${chain}". Supported chains: auto, evm, tron, bitcoin, solana, ton, xrpl, cosmos, stacks.`,
      );
  }
}
