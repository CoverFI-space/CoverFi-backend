import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { after, before, test } from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = '';
process.env.DATABASE_SSL = 'false';
process.env.TESTNET_RESERVE_ATTESTATION_SECRET = '';
process.env.TESTNET_RESERVE_ATTESTATION_PUBLIC_KEY = '';

const { app } = await import('../index.js');

let server;
let baseUrl;

before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

async function createSignedWalletSession(keypair) {
  const walletAddress = keypair.publicKey();
  const challengeResponse = await fetch(`${baseUrl}/api/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ walletAddress }),
  });
  const challenge = await challengeResponse.json();
  const signature = keypair.sign(Buffer.from(challenge.message, 'utf8')).toString('base64');
  const sessionResponse = await fetch(`${baseUrl}/api/auth/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      walletAddress,
      nonce: challenge.nonce,
      signature,
    }),
  });
  const session = await sessionResponse.json();
  assert.equal(sessionResponse.status, 200);
  return session;
}

function signSep53Message(keypair, message) {
  return keypair
    .sign(crypto.createHash('sha256').update(`Stellar Signed Message:\n${message}`).digest())
    .toString('base64');
}

test('legal status exposes current trust disclaimer', async () => {
  const response = await fetch(`${baseUrl}/api/legal/status`);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(typeof body.termsVersion, 'string');
  assert.match(body.protectionDisclaimer, /not insurance/i);
});

test('testnet proof endpoint never exposes a signer when none is configured', async () => {
  const response = await fetch(`${baseUrl}/api/status/proof-of-reserve`);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.status, 'not_configured');
  assert.equal('signature' in body, false);
  assert.equal('secret' in body, false);
});

test('cors allows the local protocol monitor port', async () => {
  const response = await fetch(`${baseUrl}/api/legal/status`, {
    headers: { Origin: 'http://localhost:5175' },
  });

  assert.equal(response.status, 200);
  assert.equal(
    response.headers.get('access-control-allow-origin'),
    'http://localhost:5175',
  );
});

test('invalid username route rejects before on-chain lookup', async () => {
  const response = await fetch(`${baseUrl}/api/users/not-valid!`);
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.message, /valid username/i);
});

test('http access logs redact wallet addresses in URL paths', async () => {
  const wallet = Keypair.random().publicKey();
  const lines = [];
  const originalLog = console.log;
  console.log = (line, ...rest) => {
    lines.push(String(line));
    return originalLog.call(console, line, ...rest);
  };

  try {
    await fetch(`${baseUrl}/api/account/${wallet}`);
  } finally {
    console.log = originalLog;
  }

  assert.ok(lines.some((line) => line.includes('/api/account/[wallet]')));
  assert.equal(lines.some((line) => line.includes(wallet)), false);
});

test('account route requires wallet ownership header', async () => {
  const wallet = `G${'A'.repeat(55)}`;
  const response = await fetch(`${baseUrl}/api/account/${wallet}`);
  const body = await response.json();

  assert.equal(response.status, 401);
  assert.match(body.message, /wallet header/i);
});

test('wallet auth challenge verifies a Stellar signature', async () => {
  const keypair = Keypair.random();
  const walletAddress = keypair.publicKey();
  const challengeResponse = await fetch(`${baseUrl}/api/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ walletAddress }),
  });
  const challenge = await challengeResponse.json();

  assert.equal(challengeResponse.status, 200);
  assert.equal(challenge.walletAddress, walletAddress);
  assert.equal(typeof challenge.message, 'string');
  assert.equal(typeof challenge.nonce, 'string');

  const signature = keypair.sign(Buffer.from(challenge.message, 'utf8')).toString('base64');
  const sessionResponse = await fetch(`${baseUrl}/api/auth/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      walletAddress,
      nonce: challenge.nonce,
      signature,
    }),
  });
  const session = await sessionResponse.json();

  assert.equal(sessionResponse.status, 200);
  assert.equal(session.walletAddress, walletAddress);
  assert.equal(typeof session.token, 'string');
  assert.match(session.token, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
});

test('wallet auth challenge verifies a Freighter SEP-53 signature', async () => {
  const keypair = Keypair.random();
  const walletAddress = keypair.publicKey();
  const challengeResponse = await fetch(`${baseUrl}/api/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ walletAddress }),
  });
  const challenge = await challengeResponse.json();

  assert.equal(challengeResponse.status, 200);

  const signature = signSep53Message(keypair, challenge.message);
  const sessionResponse = await fetch(`${baseUrl}/api/auth/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      walletAddress,
      nonce: challenge.nonce,
      signature,
    }),
  });
  const session = await sessionResponse.json();

  assert.equal(sessionResponse.status, 200);
  assert.equal(session.walletAddress, walletAddress);
  assert.equal(typeof session.token, 'string');
});

test('zk proof status returns wallet verified proof events after signed session', async () => {
  const keypair = Keypair.random();
  const walletAddress = keypair.publicKey();
  const circuitId = 'coverfi.email_wallet_ownership.v0';
  const message = JSON.stringify({
    typ: circuitId,
    subjectRef: walletAddress,
    purpose: 'route-test',
  });
  const digest = crypto.createHash('sha256').update(Buffer.from(message, 'utf8')).digest('hex');
  const signature = keypair.sign(Buffer.from(message, 'utf8')).toString('base64');

  const recordResponse = await fetch(`${baseUrl}/api/zk/proofs/record`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      subjectRef: walletAddress,
      circuitId,
      proofSystem: 'stellar-ed25519',
      proof: {
        signer: walletAddress,
        message,
        digest,
        signature,
        scheme: 'stellar-ed25519',
      },
      publicSignals: {
        subjectRef: walletAddress,
      },
    }),
  });
  const recordBody = await recordResponse.json();

  assert.equal(recordResponse.status, 202);
  assert.equal(recordBody.proofEvent.verification_status, 'verified');

  const session = await createSignedWalletSession(keypair);
  const statusResponse = await fetch(
    `${baseUrl}/api/zk/proofs/status?subjectRef=${encodeURIComponent(walletAddress)}&circuitId=${encodeURIComponent(circuitId)}`,
    {
      headers: {
        Authorization: `Bearer ${session.token}`,
        'X-CoverFi-Wallet-Address': walletAddress,
      },
    },
  );
  const statusBody = await statusResponse.json();

  assert.equal(statusResponse.status, 200);
  assert.equal(statusBody.verified, true);
  assert.equal(statusBody.latest.circuitId, circuitId);
  assert.equal(statusBody.latest.verificationStatus, 'verified');
});

test('registration blocks reserved usernames before storage writes', async () => {
  const response = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'support',
      walletAddress: Keypair.random().publicKey(),
    }),
  });
  const body = await response.json();

  assert.equal(response.status, 409);
  assert.match(body.message, /reserved/i);
});

test('account route rejects wallet header without signed session', async () => {
  const wallet = Keypair.random().publicKey();
  const response = await fetch(`${baseUrl}/api/account/${wallet}`, {
    headers: { 'X-CoverFi-Wallet-Address': wallet },
  });
  const body = await response.json();

  assert.equal(response.status, 401);
  assert.match(body.message, /signed wallet session/i);
});

test('legal accept requires a signed wallet session', async () => {
  const wallet = Keypair.random().publicKey();
  const response = await fetch(`${baseUrl}/api/legal/accept`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CoverFi-Wallet-Address': wallet,
    },
    body: JSON.stringify({ walletAddress: wallet, termsVersion: '2026-07-16' }),
  });
  const body = await response.json();

  assert.equal(response.status, 401);
  assert.match(body.message, /signed wallet session/i);
});

test('privacy export requires a signed wallet session', async () => {
  const wallet = Keypair.random().publicKey();
  const response = await fetch(`${baseUrl}/api/privacy/export/${wallet}`, {
    headers: { 'X-CoverFi-Wallet-Address': wallet },
  });
  const body = await response.json();

  assert.equal(response.status, 401);
  assert.match(body.message, /signed wallet session/i);
});

test('privacy delete requires a signed wallet session', async () => {
  const wallet = Keypair.random().publicKey();
  const response = await fetch(`${baseUrl}/api/privacy/${wallet}`, {
    method: 'DELETE',
    headers: { 'X-CoverFi-Wallet-Address': wallet },
  });
  const body = await response.json();

  assert.equal(response.status, 401);
  assert.match(body.message, /signed wallet session/i);
});

test('kyc status is optional without database configuration', async () => {
  const wallet = Keypair.random().publicKey();
  const response = await fetch(`${baseUrl}/api/onboarding/kyc/status`, {
    headers: { 'X-CoverFi-Wallet-Address': wallet },
  });
  const body = await response.json();

  assert.equal(response.status, 503);
  assert.match(body.message, /DATABASE_URL/i);
});

test('ai chat rejects oversized prompts', async () => {
  const response = await fetch(`${baseUrl}/api/ai/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: 'x'.repeat(2001) }),
  });
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.message, /too long/i);
});

test('protocol analytics endpoint is optional without database configuration', async () => {
  const response = await fetch(`${baseUrl}/api/analytics/protocol/daily`);
  const body = await response.json();

  assert.equal(response.status, 503);
  assert.match(body.message, /DATABASE_URL/i);
});

test('partner admin endpoint is optional without database configuration', async () => {
  const wallet = Keypair.random().publicKey();
  const response = await fetch(`${baseUrl}/api/partners/admin`, {
    headers: { 'X-CoverFi-Wallet-Address': wallet },
  });
  const body = await response.json();

  assert.equal(response.status, 503);
  assert.match(body.message, /Partner sandbox/i);
});

test('partner market config requires database-backed API key support', async () => {
  const response = await fetch(`${baseUrl}/api/partners/market-config`, {
    headers: { Authorization: 'Bearer cfpk_live_testinvalid.invalidsecret' },
  });
  const body = await response.json();

  assert.equal(response.status, 503);
  assert.match(body.message, /DATABASE_URL/i);
});
