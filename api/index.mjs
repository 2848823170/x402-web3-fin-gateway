import { createGatewayServer } from '../src/server.mjs';

// Stateless Vercel Serverless entry point (permanent *.vercel.app HTTPS origin for x402scan.com)
const { server } = createGatewayServer({
  ledgerPath: '/tmp/settled_ledger.jsonl',
});

export default function handler(req, res) {
  server.emit('request', req, res);
}
