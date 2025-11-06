const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const crypto = require('crypto');
const dotenv = require('dotenv');

const { nowSec, makeGatewayKeypair, signGateway, verifyGateway } = require('./crypto');
const { verifySolanaMessage, verifyEvmMessage } = require('./verify');
const { receipts, rememberReceipt, markNonce, seenNonce, cleanupNonces } = require('./storage');

dotenv.config();

const app = express();
const allowed = (process.env.ORIGIN || 'https://quantum402.dev').split(',').map(s => s.trim());

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (allowed.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));

const kp = makeGatewayKeypair(process.env.GATEWAY_SEED_BASE64);
const gatewayPubB64 = Buffer.from(kp.publicKey).toString('base64');

const makeNonce = () => crypto.randomUUID().replace(/-/g, '');
const randHex32 = () => crypto.randomBytes(32).toString('hex');
const isFresh = (ts, ttl) => (nowSec() - ts) <= ttl;

const messageFromInvoice = (inv) =>
  [inv.feature, inv.amount, inv.unit, inv.nonce, inv.merkleId, inv.ts].join('|');

const messageFromReceipt = (rcpt) =>
  [rcpt.feature, rcpt.amount, rcpt.unit, rcpt.nonce, rcpt.merkleId, rcpt.ts].join('|');

app.get('/health', (_req, res) => res.json({ ok: true, t: nowSec() }));
app.get('/api/gateway', (_req, res) => res.json({ pubkeyBase64: gatewayPubB64 }));

app.post('/api/invoice', (req, res) => {
  const { feature = 'api.translate', amount = '0.01', unit = 'SOL', ttlSec = 90, wallet = 'phantom' } = req.body || {};
  const ts = nowSec();
  const invoice = {
    feature, amount, unit,
    ttl: ttlSec,
    nonce: makeNonce(),
    merkleId: randHex32(),
    ts,
    wallet
  };
  res.json({
    ok: true,
    invoice,
    messageToSign: messageFromInvoice(invoice),
    gatewayPubkey: gatewayPubB64
  });
});

app.post('/api/settle', async (req, res) => {
  try {
    const { invoice, walletProof } = req.body || {};
    if (!invoice || !walletProof) return res.status(400).json({ ok: false, error: 'missing-body' });
    if (!isFresh(invoice.ts, invoice.ttl)) return res.status(400).json({ ok: false, error: 'expired' });
    if (seenNonce(invoice.nonce)) return res.status(409).json({ ok: false, error: 'replay' });

    const msg = messageFromInvoice(invoice);
    let verified = false;

    if (walletProof.kind === 'solana') {
      verified = await verifySolanaMessage({
        message: msg,
        signatureBase64: walletProof.signatureBase64,
        account: walletProof.account
      });
    } else if (walletProof.kind === 'evm') {
      verified = await verifyEvmMessage({
        message: msg,
        signatureHex: walletProof.signatureHex,
        account: walletProof.account
      });
    }

    if (!verified) return res.status(401).json({ ok: false, error: 'bad-wallet-proof' });

    markNonce(invoice.nonce, invoice.ts + invoice.ttl);
    cleanupNonces();

    const receipt = {
      feature: invoice.feature,
      amount: invoice.amount,
      unit: invoice.unit,
      ttl: invoice.ttl,
      nonce: invoice.nonce,
      merkleId: invoice.merkleId,
      payer: walletProof.account,
      gatewayPubkey: gatewayPubB64,
      ts: invoice.ts
    };
    receipt.sig = signGateway(messageFromReceipt(receipt), kp.secretKey);

    rememberReceipt(receipt);
    return res.json({ ok: true, receipt });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'server-error' });
  }
});

app.get('/api/receipts', (_req, res) => res.json({ ok: true, items: receipts }));

app.post('/api/verify', (req, res) => {
  try {
    const { receipt } = req.body || {};
    if (!receipt) return res.status(400).json({ ok: false, error: 'missing-receipt' });
    if (!isFresh(receipt.ts, receipt.ttl)) return res.json({ ok: false, error: 'expired' });

    const ok = verifyGateway(
      messageFromReceipt(receipt),
      receipt.sig,
      Buffer.from(receipt.gatewayPubkey, 'base64')
    );
    if (!ok) return res.json({ ok: false, error: 'bad-sig' });

    const replayProtected = seenNonce(receipt.nonce);
    return res.json({ ok: true, replayProtected });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'server-error' });
  }
});

app.get('/api/translate', (req, res) => {
  const hdr = req.headers['x402-receipt'];
  if (!hdr) return res.status(402).json({ ok: false, error: 'missing-x402-receipt' });
  try {
    const receipt = JSON.parse(hdr);
    if (!isFresh(receipt.ts, receipt.ttl)) return res.status(402).json({ ok: false, error: 'expired' });

    const ok = verifyGateway(
      messageFromReceipt(receipt),
      receipt.sig,
      Buffer.from(receipt.gatewayPubkey, 'base64')
    );
    if (!ok) return res.status(401).json({ ok: false, error: 'bad-sig' });
    if (receipt.feature !== 'api.translate') return res.status(403).json({ ok: false, error: 'wrong-feature' });

    return res.json({ ok: true, data: { text: 'Hello → Halo' } });
  } catch {
    return res.status(400).json({ ok: false, error: 'bad-receipt-json' });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`quantum402 backend on http://localhost:${port}`);
  console.log(`CORS: ${allowed.join(', ')}`);
});
