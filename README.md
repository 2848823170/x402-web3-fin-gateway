# x402 Web3 Security & Financial Audit Gateway (`0%` Middleman Fee • Base Mainnet USDC)

Direct, zero-custody **HTTP 402 Payment Required (`x402` v1 & v2)** REST API + **Model Context Protocol (`MCP` `2025-06-18`)** Gateway built with **zero external npm dependencies** (pure Node.js `>= 20`).

Every paid tool call settles **`0.01 USDC` – `0.02 USDC`** on **Base Mainnet (`chainId: 8453`, USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)** directly to **`0xfEbDbB880C7f323c145d61683874a45540208a68`** with **`0%` middleman fee**.

## Live Public Endpoints

- **Gateway Root**: `https://nick-ebony-forth-sic.trycloudflare.com`
- **`x402` Discovery Manifest (`200 OK`)**: `https://nick-ebony-forth-sic.trycloudflare.com/.well-known/x402.json`
- **Machine-Readable Catalog (`200 OK`)**: `https://nick-ebony-forth-sic.trycloudflare.com/api/catalog`
- **OpenAPI `3.1.0` Spec (`200 OK`)**: `https://nick-ebony-forth-sic.trycloudflare.com/openapi.json`
- **MCP Streamable HTTP**: `https://nick-ebony-forth-sic.trycloudflare.com/mcp` (`initialize` & `tools/list` free; `tools/call` gated by `x402`)

## Paid Endpoints & MCP Tools (Base Mainnet USDC)

| REST Endpoint (`POST`) | MCP Tool Name | Price (USDC) | Atomic (`6` dec) | Capability |
| --- | --- | --- | --- | --- |
| `/api/v1/validate-address` | `validate_multichain_address` | **`$0.01`** | `10000` | Cryptographic wallet/contract validation across 8 chains (EVM EIP-55, Tron, Bitcoin Bech32/Bech32m/Base58Check, Solana Ed25519 curve vs PDA, TON CRC16, XRPL X-address, Cosmos, Stacks) |
| `/api/v1/scan-token-risk` | `scan_token_rug_risk` | **`$0.01`** | `10000` | Live `<400ms` on-chain Base Mainnet ERC-20 & Solana SPL / Token-2022 honeypot, mint/freeze authority, EIP-1967 proxy, Uniswap/Aerodrome liquidity & LP burn %, and whale concentration oracle |
| `/api/v1/audit-calldata` | `decode_and_audit_evm_calldata` | **`$0.01`** | `10000` | Raw EVM calldata decoder & risk auditor (ERC-20/721/1155, Permit2, Uniswap V2/V3/UniversalRouter, 1inch, recursive Multicall, Gnosis Safe `DELEGATECALL`) |
| `/api/v1/audit-eip712` | `audit_eip712_signature_payload` | **`$0.01`** | `10000` | Off-chain `eth_signTypedData_v4` auditor (`Permit`, `Permit2`, Seaport zero-consideration drains, Circle USDC EIP-3009 `TransferWithAuthorization` / `x402`, `SafeTx`) |
| `/api/v1/repair-cjk-csv` | `repair_cjk_csv_mojibake` | **`$0.01`** | `10000` | Repairs GB18030/GBK/Big5/Shift-JIS/EUC-KR/UTF-16/double-UTF8 CSV mojibake and neutralizes OWASP CSV/DDE formula injection |
| `/api/v1/extract-tables` | `extract_and_clean_pdf_tables_to_xlsx` | **`$0.02`** | `20000` | Extracts & stitches multi-page PDF/HTML/Markdown/CSV tables into formula-safe OpenXML `.xlsx` + UTF-8 BOM CSV |
| `/api/v1/reconcile-statements` | `reconcile_statements_and_invoices` | **`$0.02`** | `20000` | Exact `BigInt` payment statement vs electronic invoice reconciliation (1:1, vendor+date, FX spread, N-to-1 subset-sum) + 3-sheet `.xlsx` audit workbook |

## Protocol & Security Guarantees

1. **Dual `x402` v1 + v2 Compatibility**:
   - Returns canonical `x402Version: 1` JSON body (`network: "base"`, `maxAmountRequired`, `outputSchema.input.bodyFields`) AND Base64 `PAYMENT-REQUIRED` v2 header (`network: "eip155:8453"`).
   - Accepts `X-PAYMENT` (v1), `PAYMENT-SIGNATURE` (v2), MCP `params._meta["x402/payment"]`, OR `X-TX-HASH` (direct Base Mainnet `USDC` transfer receipt verified via `eth_getTransactionReceipt`).
2. **Zero Charge on Invalid Input (`x402lint` Compliant)**:
   - Validates all request arguments **before** calling facilitator `/settle` (`HTTP 400` on malformed input -> `$0` charged).
   - Executes deterministic pure-JS computation **before** calling `/settle` so internal errors never settle buyer funds.
3. **Anti-Replay & Recipient Pinning**:
   - Enforces `authorization.to === 0xfEbDbB880C7f323c145d61683874a45540208a68`, `value >= requiredAtomic`, active EIP-3009 validity window, and persistent nonce + tx-hash replay locks.

## Quickstart (`x402-fetch`)

```ts
import { wrapFetchWithPayment } from 'x402-fetch';
import { privateKeyToAccount } from 'viem/accounts';

const account = privateKeyToAccount(process.env.EVM_PRIVATE_KEY as `0x${string}`);
const fetchWithPay = wrapFetchWithPayment(fetch, account);

const res = await fetchWithPay(
  'https://nick-ebony-forth-sic.trycloudflare.com/api/v1/validate-address',
  {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      address: '0xfEbDbB880C7f323c145d61683874a45540208a68',
      chain: 'evm',
    }),
  },
);
console.log(await res.json());
```

## Self-Hosting & Testing

```bash
node --test tests/x402_gateway.test.mjs
HOST=127.0.0.1 PORT=9102 node src/server.mjs
```
