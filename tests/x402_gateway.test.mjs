import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createGatewayServer } from '../src/server.mjs';
import { scanEvmBytecodeCapabilities } from '../src/web3/token-rug-scanner.mjs';
import {
  BASE_USDC_ASSET,
  ERC20_TRANSFER_TOPIC0,
  PAY_TO,
} from '../src/x402.mjs';

function encodeB64(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64');
}

function decodeB64(str) {
  return JSON.parse(Buffer.from(str, 'base64').toString('utf8'));
}

function makeSamplePaymentHeader({
  version = 1,
  from = '0x1111111111111111111111111111111111111111',
  to = PAY_TO,
  value = '10000',
  validAfter = '0',
  validBefore = '1999999999',
  nonce = '0x0000000000000000000000000000000000000000000000000000000000000001',
} = {}) {
  const payloadObj =
    version === 2
      ? {
          x402Version: 2,
          accepted: {
            scheme: 'exact',
            network: 'eip155:8453',
            amount: value,
            asset: BASE_USDC_ASSET,
            payTo: to,
          },
          payload: {
            signature: `0x${'ab'.repeat(65)}`,
            authorization: { from, to, value, validAfter, validBefore, nonce },
          },
        }
      : {
          x402Version: 1,
          scheme: 'exact',
          network: 'base',
          payload: {
            signature: `0x${'cd'.repeat(65)}`,
            authorization: { from, to, value, validAfter, validBefore, nonce },
          },
        };
  return encodeB64(payloadObj);
}

test('x402 Direct 0%-Fee Base Mainnet USDC Gateway — full discovery, security & settlement suite', async (t) => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'x402-gw-test-'));
  const ledgerPath = join(tmpDir, 'settled_ledger.jsonl');

  let verifyCalls = 0;
  let settleCalls = 0;
  let rpcCalls = 0;

  const validTxHash = `0x${'77'.repeat(32)}`;
  const wrongRecipientTxHash = `0x${'88'.repeat(32)}`;

  const mockFetch = async (url, init) => {
    const body = JSON.parse(init.body);
    if (url === 'https://mock-facilitator.test/verify') {
      verifyCalls += 1;
      return new Response(
        JSON.stringify({
          isValid: true,
          payer: body.paymentPayload.payload.authorization.from,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }
    if (url === 'https://mock-facilitator.test/settle') {
      settleCalls += 1;
      return new Response(
        JSON.stringify({
          success: true,
          transaction: `0x${String(settleCalls).padStart(64, '0')}`,
          network: body.x402Version === 2 ? 'eip155:8453' : 'base',
          payer: body.paymentPayload.payload.authorization.from,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }
    if (url === 'https://mock-base-rpc.test') {
      rpcCalls += 1;
      const [txHash] = body.params;
      if (txHash === validTxHash) {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            result: {
              status: '0x1',
              from: '0x2222222222222222222222222222222222222222',
              logs: [
                {
                  address: BASE_USDC_ASSET,
                  topics: [
                    ERC20_TRANSFER_TOPIC0,
                    '0x0000000000000000000000002222222222222222222222222222222222222222',
                    `0x000000000000000000000000${PAY_TO.slice(2).toLowerCase()}`,
                  ],
                  data: `0x${(20000n).toString(16).padStart(64, '0')}`,
                },
              ],
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (txHash === wrongRecipientTxHash) {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            result: {
              status: '0x1',
              from: '0x2222222222222222222222222222222222222222',
              logs: [
                {
                  address: BASE_USDC_ASSET,
                  topics: [
                    ERC20_TRANSFER_TOPIC0,
                    '0x0000000000000000000000002222222222222222222222222222222222222222',
                    '0x000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead',
                  ],
                  data: `0x${(50000n).toString(16).padStart(64, '0')}`,
                },
              ],
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: null }), { status: 200 });
    }
    if (url === 'https://api.mainnet-beta.solana.com') {
      if (body.method === 'getAccountInfo') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: {
                owner: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
                data: {
                  parsed: {
                    info: {
                      decimals: 6,
                      supply: '1000000000000',
                      mintAuthority: 'RugAuth111111111111111111111111111111111111',
                      freezeAuthority: 'FreezeAuth111111111111111111111111111111111',
                      extensions: [
                        {
                          extension: 'permanentDelegate',
                          state: { delegate: 'DrainDelegate11111111111111111111111111111' },
                        },
                        {
                          extension: 'transferFeeConfig',
                          state: { newerTransferFee: { transferFeeBasisPoints: 2500 } },
                        },
                      ],
                    },
                  },
                },
              },
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (body.method === 'getTokenLargestAccounts') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: 2,
            result: {
              value: [{ address: 'WhaleVault111111111111111111111111111111111', amount: '650000000000', uiAmountString: '650000' }],
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
    }
    throw new Error(`Unexpected fetch URL: ${url}`);
  };

  const { server } = createGatewayServer({
    publicBaseUrl: 'https://x402-demo.trycloudflare.com',
    facilitatorUrls: ['https://mock-facilitator.test'],
    baseRpcUrls: ['https://mock-base-rpc.test'],
    ledgerPath,
    fetchFn: mockFetch,
    nowFn: () => 1800000000,
  });

  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  const { port } = server.address();
  const localUrl = `http://127.0.0.1:${port}`;

  t.after(() => {
    server.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  await t.test('1. Free discovery endpoints (/.well-known/x402.json, /api/catalog, /openapi.json, /health)', async () => {
    const wkRes = await fetch(`${localUrl}/.well-known/x402.json`);
    assert.equal(wkRes.status, 200);
    const wk = await wkRes.json();
    assert.equal(wk.x402Version, 1);
    assert.equal(wk.payTo, '0xfEbDbB880C7f323c145d61683874a45540208a68');
    assert.equal(wk.asset, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913');
    assert.equal(wk.chainId, 8453);
    assert.equal(wk.middlemanFeeBps, 0);
    assert.equal(wk.resources.length, 7);
    assert.equal(wk.accepts.length, 7);
    assert.equal(
      wk.resources[0],
      'https://x402-demo.trycloudflare.com/api/v1/validate-address',
    );

    const catRes = await fetch(`${localUrl}/api/catalog`);
    assert.equal(catRes.status, 200);
    const cat = await catRes.json();
    assert.equal(cat.settlement.payTo, PAY_TO);
    assert.equal(cat.settlement.middlemanFeePercent, 0);
    assert.equal(cat.endpoints.length, 7);

    const htmlRes = await fetch(`${localUrl}/`, { headers: { Accept: 'text/html' } });
    assert.equal(htmlRes.status, 200);
    const html = await htmlRes.text();
    assert.ok(html.includes(PAY_TO));

    const oaRes = await fetch(`${localUrl}/openapi.json`);
    assert.equal(oaRes.status, 200);
    const oa = await oaRes.json();
    assert.equal(oa.openapi, '3.1.0');
  });

  await t.test('2. Unpaid POST & GET probes return exact HTTP 402 v1 body + v2 PAYMENT-REQUIRED header', async () => {
    for (const method of ['POST', 'GET']) {
      const res = await fetch(`${localUrl}/api/v1/validate-address`, { method });
      assert.equal(res.status, 402);
      const body = await res.json();
      assert.equal(body.x402Version, 1);
      assert.equal(body.accepts.length, 1);
      const req0 = body.accepts[0];
      assert.equal(req0.scheme, 'exact');
      assert.equal(req0.network, 'base');
      assert.equal(req0.maxAmountRequired, '10000');
      assert.equal(req0.payTo, '0xfEbDbB880C7f323c145d61683874a45540208a68');
      assert.equal(req0.asset, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913');
      assert.equal(req0.extra.name, 'USD Coin');
      assert.equal(req0.extra.version, '2');
      assert.equal(req0.outputSchema.input.method, 'POST');
      assert.ok(req0.outputSchema.input.bodyFields.address.required);

      const v2Header = res.headers.get('payment-required');
      assert.ok(v2Header);
      const v2 = decodeB64(v2Header);
      assert.equal(v2.x402Version, 2);
      assert.equal(v2.accepts[0].network, 'eip155:8453');
      assert.equal(v2.accepts[0].amount, '10000');
      assert.equal(v2.accepts[0].payTo, PAY_TO);
    }
  });

  await t.test('3. x402lint guard: bad input WITH payment header returns HTTP 400 BEFORE settling ($0 charged)', async () => {
    const payHeader = makeSamplePaymentHeader({
      nonce: `0x${'02'.repeat(32)}`,
    });
    const res = await fetch(`${localUrl}/api/v1/validate-address`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-PAYMENT': payHeader,
      },
      body: JSON.stringify({ address: '' }),
    });
    assert.equal(res.status, 400);
    const errBody = await res.json();
    assert.equal(errBody.settled, false);
    assert.equal(verifyCalls, 0);
    assert.equal(settleCalls, 0);
  });

  await t.test('4. Adversarial spoofing guards: wrong recipient, underpayment, and expired auth rejected (402)', async () => {
    // Wrong payTo
    const spoofedPay = makeSamplePaymentHeader({
      to: '0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead',
      nonce: `0x${'03'.repeat(32)}`,
    });
    const r1 = await fetch(`${localUrl}/api/v1/validate-address`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-PAYMENT': spoofedPay },
      body: JSON.stringify({ address: PAY_TO }),
    });
    assert.equal(r1.status, 402);
    assert.match((await r1.json()).error, /Recipient mismatch/);

    // Underpayment ($0.0099 instead of $0.01)
    const lowPay = makeSamplePaymentHeader({
      value: '9999',
      nonce: `0x${'04'.repeat(32)}`,
    });
    const r2 = await fetch(`${localUrl}/api/v1/validate-address`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-PAYMENT': lowPay },
      body: JSON.stringify({ address: PAY_TO }),
    });
    assert.equal(r2.status, 402);
    assert.match((await r2.json()).error, /Insufficient USDC/);

    // Expired authorization
    const expiredPay = makeSamplePaymentHeader({
      validBefore: '1700000000',
      nonce: `0x${'05'.repeat(32)}`,
    });
    const r3 = await fetch(`${localUrl}/api/v1/validate-address`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-PAYMENT': expiredPay },
      body: JSON.stringify({ address: PAY_TO }),
    });
    assert.equal(r3.status, 402);
    assert.match((await r3.json()).error, /expired/);
    assert.equal(settleCalls, 0);
  });

  await t.test('5. Paid x402 v1 (X-PAYMENT) & v2 (PAYMENT-SIGNATURE) settle cleanly and block nonce replay', async () => {
    const v1Header = makeSamplePaymentHeader({
      version: 1,
      nonce: `0x${'10'.repeat(32)}`,
    });
    const res1 = await fetch(`${localUrl}/api/v1/validate-address`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-PAYMENT': v1Header },
      body: JSON.stringify({ address: PAY_TO.toLowerCase(), chain: 'evm' }),
    });
    assert.equal(res1.status, 200);
    const json1 = await res1.json();
    assert.equal(json1.summary.valid, true);
    assert.equal(json1.summary.canonicalAddress, PAY_TO);
    assert.equal(json1.payment.payTo, PAY_TO);
    const payResp1 = decodeB64(res1.headers.get('x-payment-response'));
    assert.equal(payResp1.success, true);

    // Replay same v1 header -> must fail with 402!
    const replayRes = await fetch(`${localUrl}/api/v1/validate-address`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-PAYMENT': v1Header },
      body: JSON.stringify({ address: PAY_TO, chain: 'evm' }),
    });
    assert.equal(replayRes.status, 402);
    assert.match((await replayRes.json()).error, /replay rejected/);

    // Paid v2 header on /api/v1/audit-calldata
    const v2Header = makeSamplePaymentHeader({
      version: 2,
      nonce: `0x${'11'.repeat(32)}`,
    });
    const res2 = await fetch(`${localUrl}/api/v1/audit-calldata`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'PAYMENT-SIGNATURE': v2Header,
      },
      body: JSON.stringify({
        to: BASE_USDC_ASSET,
        data: '0x095ea7b30000000000000000000000001111111254eeb25477b68fb85ed929f73a960582ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        chainId: 8453,
      }),
    });
    assert.equal(res2.status, 200);
    const json2 = await res2.json();
    assert.equal(json2.summary.functionName, 'approve(address,uint256)');
    assert.equal(json2.summary.safeToExecute, false);
  });

  await t.test('6. Direct Base Mainnet USDC X-TX-HASH receipt verification + anti-replay', async () => {
    // Wrong recipient tx -> 402
    const badTxRes = await fetch(`${localUrl}/api/v1/reconcile-statements`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-TX-HASH': wrongRecipientTxHash,
      },
      body: JSON.stringify({
        statements: [
          { filename: 's.csv', content: 'id,date,merchant,amount,currency\no1,2026-11-20,AWS,50.00,USD\n' },
        ],
      }),
    });
    assert.equal(badTxRes.status, 402);

    // Valid Base USDC receipt ($0.02 = 20000 atomic) -> 200 OK
    const goodTxRes = await fetch(`${localUrl}/api/v1/reconcile-statements`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-TX-HASH': validTxHash,
      },
      body: JSON.stringify({
        statements: [
          { filename: 's.csv', content: 'id,date,merchant,amount,currency\no1,2026-11-20,AWS,50.00,USD\n' },
        ],
        baseCurrency: 'USD',
      }),
    });
    assert.equal(goodTxRes.status, 200);
    const reconJson = await goodTxRes.json();
    assert.equal(reconJson.status, 'ok');
    assert.equal(reconJson.payment.settledVia, 'base-mainnet-rpc');
    assert.ok(rpcCalls >= 2);

    // Replay same X-TX-HASH -> 402
    const replayTxRes = await fetch(`${localUrl}/api/v1/validate-address`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-TX-HASH': validTxHash },
      body: JSON.stringify({ address: PAY_TO }),
    });
    assert.equal(replayTxRes.status, 402);
    assert.match((await replayTxRes.json()).error, /replay rejected/);
  });

  await t.test('7. MCP Streamable HTTP (/mcp): free discovery vs x402-gated tools/call', async () => {
    const initRes = await fetch(`${localUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-06-18' },
      }),
    });
    assert.equal(initRes.status, 200);
    const initJson = await initRes.json();
    assert.equal(initJson.result.serverInfo.name, 'x402-web3-fin-gateway');

    const listRes = await fetch(`${localUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
    });
    assert.equal(listRes.status, 200);
    const listJson = await listRes.json();
    assert.equal(listJson.result.tools.length, 7);

    // Unpaid tools/call -> HTTP 402
    const unpaidCall = await fetch(`${localUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: {
          name: 'repair_cjk_csv_mojibake',
          arguments: { content: '姓名,金额\n张三,100.00\n' },
        },
      }),
    });
    assert.equal(unpaidCall.status, 402);
    const challenge = await unpaidCall.json();
    assert.equal(challenge.accepts[0].payTo, PAY_TO);

    // Paid tools/call -> HTTP 200 + structuredContent + _meta['x402/payment-response']
    const mcpPayHeader = makeSamplePaymentHeader({
      version: 1,
      nonce: `0x${'22'.repeat(32)}`,
    });
    const paidCall = await fetch(`${localUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-PAYMENT': mcpPayHeader,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: {
          name: 'repair_cjk_csv_mojibake',
          arguments: { content: '姓名,金额\n张三,=cmd|\'/C calc\'!A0\n' },
        },
      }),
    });
    assert.equal(paidCall.status, 200);
    const paidJson = await paidCall.json();
    assert.equal(paidJson.result.isError, false);
    assert.equal(paidJson.result.structuredContent.summary.rowCount, 1);
    assert.equal(paidJson.result._meta['x402/payment-response'].payTo, PAY_TO);

    // Verify cumulative ledger telemetry ($0.01 + $0.01 + $0.02 + $0.01 = $0.05 = 50000 atomic)
    const healthRes = await fetch(`${localUrl}/health`);
    const health = await healthRes.json();
    assert.equal(health.telemetry.settledPayments, 4);
    assert.equal(health.telemetry.totalSettledAtomicUsdc, '50000');
    assert.equal(health.telemetry.totalSettledUsdc, '0.050000');
  });

  await t.test('8. Live Token Rug/Honeypot Scanner (/api/v1/scan-token-risk): bytecode PUSH-skip + Token-2022 trap detection', async () => {
    // PUSH2 0xffff (data, NOT selfdestruct) vs real 0xff opcode
    const safePush = scanEvmBytecodeCapabilities('0x61ffff00');
    assert.equal(safePush.hasSelfdestruct, false);
    const realSelfdestruct = scanEvmBytecodeCapabilities('0x6340c10f19ff');
    assert.equal(realSelfdestruct.hasMintSelector, true);
    assert.equal(realSelfdestruct.hasSelfdestruct, true);

    const scanPay = makeSamplePaymentHeader({
      version: 1,
      nonce: `0x${'33'.repeat(32)}`,
    });
    const scanRes = await fetch(`${localUrl}/api/v1/scan-token-risk`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-PAYMENT': scanPay,
      },
      body: JSON.stringify({
        tokenAddress: 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263',
        chain: 'solana',
      }),
    });
    assert.equal(scanRes.status, 200);
    const scanJson = await scanRes.json();
    assert.equal(scanJson.summary.riskLevel, 'CRITICAL');
    assert.equal(scanJson.summary.safeToTrade, false);
    assert.equal(scanJson.scan.holderConcentration.top1Percent, 65);
    const codes = scanJson.scan.findings.map((f) => f.code);
    assert.ok(codes.includes('FREEZE_AUTHORITY_ACTIVE'));
    assert.ok(codes.includes('TOKEN2022_PERMANENT_DELEGATE'));
    assert.ok(codes.includes('TOKEN2022_EXTREME_TRANSFER_TAX'));
  });
});
