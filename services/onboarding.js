import crypto from 'crypto';
import { rpc } from '@stellar/stellar-sdk';
import { env } from '../config/env.js';
import { isDatabaseConfigured, query } from './database.js';

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const memoryOtps = [];
const memoryWalletAccounts = [];
const memoryZkCommitments = [];
const memoryZkProofEvents = [];
const memoryMfaAuthenticators = [];
const memoryMfaChallenges = [];
const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function hmac(value, secret = env.onboarding.otpPepper) {
  return crypto.createHmac('sha256', secret).update(String(value)).digest('hex');
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function requirePersistentStore(feature) {
  if (isDatabaseConfigured()) return;
  if (!env.server.isProduction) return;

  const error = new Error(`${feature} requires DATABASE_URL in production.`);
  error.statusCode = 503;
  throw error;
}

function mfaEncryptionKey() {
  return crypto
    .createHash('sha256')
    .update(`coverfi:mfa:${env.onboarding.otpPepper}`)
    .digest();
}

function encryptMfaSecret(secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', mfaEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return {
    ciphertext: encrypted.toString('base64url'),
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
  };
}

function decryptMfaSecret(record) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    mfaEncryptionKey(),
    Buffer.from(record.secret_iv, 'base64url'),
  );
  decipher.setAuthTag(Buffer.from(record.secret_tag, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(record.secret_ciphertext, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}

function tokenSignature(header, payload) {
  return crypto
    .createHmac('sha256', env.onboarding.otpPepper)
    .update(`${header}.${payload}`)
    .digest('base64url');
}

function mfaChallengeSignature(payload) {
  return crypto
    .createHmac('sha256', env.onboarding.otpPepper)
    .update(payload)
    .digest('base64url');
}

function createMfaEnrollmentProof(emailHash) {
  const payload = base64UrlJson({
    typ: 'coverfi-mfa-enabled',
    emailHash,
    iat: Date.now(),
    jti: crypto.randomBytes(16).toString('base64url'),
  });
  return `${payload}.${mfaChallengeSignature(payload)}`;
}

function parseToken(token) {
  const [header, payload, signature] = String(token || '').split('.');
  if (!header || !payload || !signature) return null;
  const expected = tokenSignature(header, payload);
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) return null;
  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!parsed?.emailHash || !parsed?.exp || parsed.exp <= Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function cleanEmail(value) {
  return String(value || '').trim().toLowerCase().slice(0, 254);
}

export function isValidEmail(value) {
  return emailPattern.test(cleanEmail(value));
}

export function emailRef(email) {
  return hmac(`email:${cleanEmail(email)}`);
}

export function walletRef(walletAddress) {
  return hmac(`wallet:${String(walletAddress || '').trim()}`, env.server.privacyHmacSecret);
}

function cleanNetwork(value) {
  const network = String(value || env.contracts.network || 'testnet').trim().toLowerCase();
  return network === 'mainnet' ? 'mainnet' : 'testnet';
}

export function createEmailSessionToken(emailHash) {
  const header = base64UrlJson({ alg: 'HS256', typ: 'coverfi-email-session' });
  const payload = base64UrlJson({
    emailHash,
    iat: Date.now(),
    exp: Date.now() + env.onboarding.tokenTtlMs,
    jti: crypto.randomBytes(16).toString('base64url'),
  });
  return `${header}.${payload}.${tokenSignature(header, payload)}`;
}

export function verifyEmailSessionToken(token) {
  return parseToken(token);
}

function otpHash(emailHash, nonce, otp) {
  return hmac(`otp:${emailHash}:${nonce}:${otp}`);
}

function generateOtp() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}

function base32Encode(buffer) {
  let bits = '';
  for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
  let output = '';
  for (let index = 0; index < bits.length; index += 5) {
    const chunk = bits.slice(index, index + 5).padEnd(5, '0');
    output += base32Alphabet[parseInt(chunk, 2)];
  }
  return output;
}

function base32Decode(secret) {
  const clean = String(secret || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) {
    const value = base32Alphabet.indexOf(char);
    if (value < 0) continue;
    bits += value.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(parseInt(bits.slice(index, index + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function hotp(secret, counter) {
  const key = base32Decode(secret);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', key).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = (
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff)
  );
  return String(binary % 1_000_000).padStart(6, '0');
}

function verifyTotp(secret, code) {
  const clean = String(code || '').replace(/\D/g, '');
  if (!/^\d{6}$/.test(clean)) return false;
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (let drift = -1; drift <= 1; drift += 1) {
    const expected = hotp(secret, counter + drift);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(clean))) {
      return true;
    }
  }
  return false;
}

function otpauthUrl(email, secret) {
  const issuer = 'CoverFi';
  const account = cleanEmail(email);
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function otpExpiryMinutes() {
  return Math.max(1, Math.round(env.onboarding.otpTtlMs / 60000));
}

function buildOtpEmailText(otp) {
  return [
    `Your CoverFi login code is ${otp}.`,
    '',
    `This code expires in ${otpExpiryMinutes()} minutes.`,
    'If you did not request this code, you can ignore this email.',
  ].join('\n');
}

function buildOtpEmailHtml(otp) {
  const expiryMinutes = otpExpiryMinutes();
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Your CoverFi login code</title>
  </head>
  <body style="margin:0;background:#050505;color:#E1E0CC;font-family:Inter,Arial,sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#050505;padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:520px;border:1px solid rgba(225,224,204,0.14);border-radius:20px;background:#10100e;overflow:hidden;">
            <tr>
              <td style="padding:28px 28px 12px;">
                <div style="font-size:12px;letter-spacing:0.28em;text-transform:uppercase;color:rgba(225,224,204,0.52);">CoverFi verification</div>
                <h1 style="margin:16px 0 0;font-family:Georgia,serif;font-size:34px;line-height:1.05;font-weight:400;color:#E1E0CC;">Your login code</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:8px 28px 8px;">
                <p style="margin:0;color:rgba(225,224,204,0.68);font-size:15px;line-height:1.6;">Use this one-time code to continue signing in to CoverFi.</p>
              </td>
            </tr>
            <tr>
              <td style="padding:22px 28px;">
                <div style="border:1px solid rgba(225,224,204,0.16);border-radius:16px;background:#050505;padding:22px;text-align:center;">
                  <div style="font-size:34px;line-height:1;letter-spacing:0.22em;font-weight:700;color:#E1E0CC;">${otp}</div>
                </div>
              </td>
            </tr>
            <tr>
              <td style="padding:0 28px 28px;">
                <p style="margin:0;color:rgba(225,224,204,0.58);font-size:13px;line-height:1.6;">This code expires in ${expiryMinutes} minutes. If you did not request it, you can safely ignore this email.</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
}

function resendErrorMessage(status, body) {
  let parsed = null;
  try {
    parsed = JSON.parse(body);
  } catch {
    parsed = null;
  }

  const providerMessage = String(parsed?.message || body || '').trim();
  if (/api key is invalid/i.test(providerMessage)) {
    return 'Resend rejected RESEND_API_KEY. Create a new Resend API key, update server/.env, then restart the backend.';
  }

  if (/domain is not verified/i.test(providerMessage)) {
    return 'Resend rejected the sender domain. Verify mail.coverfi.space in Resend and keep ONBOARDING_EMAIL_FROM as CoverFi <donotreply@mail.coverfi.space>.';
  }

  if (/you can only send testing emails/i.test(providerMessage)) {
    return 'Resend is still in testing mode. Verify mail.coverfi.space or send only to the verified Resend account email.';
  }

  return providerMessage || `Resend returned ${status}.`;
}

async function saveOtpRecord(record) {
  if (isDatabaseConfigured()) {
    const result = await query(
      `INSERT INTO email_wallet_otps (email_hash, nonce, otp_hash, expires_at)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email_hash, nonce, status, attempts, expires_at, created_at`,
      [record.emailHash, record.nonce, record.otpHash, new Date(record.expiresAt).toISOString()],
    );
    return result.rows[0];
  }

  requirePersistentStore('Email OTP storage');
  const stored = {
    id: crypto.randomUUID(),
    email_hash: record.emailHash,
    nonce: record.nonce,
    otp_hash: record.otpHash,
    status: 'pending',
    attempts: 0,
    expires_at: new Date(record.expiresAt).toISOString(),
    created_at: new Date().toISOString(),
  };
  memoryOtps.unshift(stored);
  return stored;
}

async function sendOtpEmail(email, otp) {
  if (!env.onboarding.resendApiKey) {
    const error = new Error('RESEND_API_KEY is required for OTP email delivery.');
    error.statusCode = 503;
    throw error;
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.onboarding.resendApiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.onboarding.emailFrom,
      to: [email],
      subject: 'Your CoverFi login code',
      text: buildOtpEmailText(otp),
      html: buildOtpEmailHtml(otp),
    }),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    const error = new Error(resendErrorMessage(response.status, body));
    error.statusCode = 502;
    error.provider = 'resend';
    error.providerStatus = response.status;
    error.providerRequestId = response.headers.get('x-resend-id') || response.headers.get('x-request-id') || '';
    throw error;
  }

  return { sent: true, provider: 'resend' };
}

export async function startEmailOtp(email) {
  const normalizedEmail = cleanEmail(email);
  if (!isValidEmail(normalizedEmail)) {
    const error = new Error('A valid email address is required.');
    error.statusCode = 400;
    throw error;
  }

  const otp = generateOtp();
  const nonce = crypto.randomBytes(18).toString('base64url');
  const emailHash = emailRef(normalizedEmail);
  const expiresAt = Date.now() + env.onboarding.otpTtlMs;
  const record = await saveOtpRecord({
    emailHash,
    nonce,
    otpHash: otpHash(emailHash, nonce, otp),
    expiresAt,
  });
  let provider;
  try {
    provider = await sendOtpEmail(normalizedEmail, otp);
  } catch (error) {
    // Never leave a usable code behind when its delivery failed.
    await updateOtpRecord(record, { status: 'expired', attempts: record.attempts || 0 }).catch(() => undefined);
    throw error;
  }

  return {
    otpId: record.id,
    expiresAt: new Date(expiresAt).toISOString(),
    provider,
  };
}

async function loadOtpRecord(otpId, emailHash) {
  if (isDatabaseConfigured()) {
    const result = await query(
      `SELECT id, email_hash, nonce, otp_hash, status, attempts, expires_at
       FROM email_wallet_otps
       WHERE id = $1 AND email_hash = $2
       LIMIT 1`,
      [otpId, emailHash],
    );
    return result.rows[0] || null;
  }

  requirePersistentStore('Email OTP storage');
  return memoryOtps.find((record) => record.id === otpId && record.email_hash === emailHash) || null;
}

async function updateOtpRecord(record, updates) {
  if (isDatabaseConfigured()) {
    const result = await query(
      `UPDATE email_wallet_otps
       SET status = $2, attempts = $3, verified_at = $4
       WHERE id = $1
       RETURNING id, email_hash, status, attempts, verified_at`,
      [
        record.id,
        updates.status || record.status,
        updates.attempts ?? record.attempts,
        updates.verifiedAt ? new Date(updates.verifiedAt).toISOString() : null,
      ],
    );
    return result.rows[0];
  }

  requirePersistentStore('Email OTP storage');
  record.status = updates.status || record.status;
  record.attempts = updates.attempts ?? record.attempts;
  record.verified_at = updates.verifiedAt ? new Date(updates.verifiedAt).toISOString() : null;
  return record;
}

async function loadMfaAuthenticator(emailHash) {
  if (isDatabaseConfigured()) {
    const result = await query(
      `SELECT email_hash, secret_ciphertext, secret_iv, secret_tag, status, confirmed_at
       FROM email_mfa_authenticators
       WHERE email_hash = $1 AND status = 'active'
       LIMIT 1`,
      [emailHash],
    );
    return result.rows[0] || null;
  }

  requirePersistentStore('MFA authenticator storage');
  return memoryMfaAuthenticators.find(
    (record) => record.email_hash === emailHash && record.status === 'active',
  ) || null;
}

async function saveMfaAuthenticator(emailHash, secret) {
  const encrypted = encryptMfaSecret(secret);
  if (isDatabaseConfigured()) {
    const result = await query(
      `INSERT INTO email_mfa_authenticators
         (email_hash, secret_ciphertext, secret_iv, secret_tag, status, confirmed_at)
       VALUES ($1, $2, $3, $4, 'active', now())
       ON CONFLICT (email_hash)
       DO UPDATE SET
         secret_ciphertext = EXCLUDED.secret_ciphertext,
         secret_iv = EXCLUDED.secret_iv,
         secret_tag = EXCLUDED.secret_tag,
         status = 'active',
         confirmed_at = now()
       RETURNING email_hash, secret_ciphertext, secret_iv, secret_tag, status, confirmed_at`,
      [emailHash, encrypted.ciphertext, encrypted.iv, encrypted.tag],
    );
    return result.rows[0];
  }

  requirePersistentStore('MFA authenticator storage');
  const existing = memoryMfaAuthenticators.find((record) => record.email_hash === emailHash);
  const next = existing || { email_hash: emailHash };
  next.secret_ciphertext = encrypted.ciphertext;
  next.secret_iv = encrypted.iv;
  next.secret_tag = encrypted.tag;
  next.status = 'active';
  next.confirmed_at = new Date().toISOString();
  if (!existing) memoryMfaAuthenticators.unshift(next);
  return next;
}

function createMfaChallenge({ emailHash, email, mode, secret = '' }) {
  const expiresAt = Date.now() + 5 * 60 * 1000;
  const payload = base64UrlJson({
    typ: 'coverfi-mfa-challenge',
    emailHash,
    email: cleanEmail(email),
    mode,
    secret,
    exp: expiresAt,
    jti: crypto.randomBytes(16).toString('base64url'),
  });
  const challenge = {
    id: `${payload}.${mfaChallengeSignature(payload)}`,
    email_hash: emailHash,
    email: cleanEmail(email),
    mode,
    secret,
    attempts: 0,
    expires_at: expiresAt,
  };
  memoryMfaChallenges.unshift(challenge);
  return challenge;
}

async function loadEmailWalletAccount(emailHash, network) {
  const clean = cleanNetwork(network);
  if (isDatabaseConfigured()) {
    const result = await query(
      `SELECT id, wallet_ref, wallet_address, network, funding_status, funding_source, funding_transaction_hash, created_at, funded_at
       FROM email_wallet_accounts
       WHERE email_hash = $1 AND network = $2
       ORDER BY created_at DESC
       LIMIT 1`,
      [emailHash, clean],
    );
    return result.rows[0] || null;
  }

  requirePersistentStore('Email wallet account storage');
  return memoryWalletAccounts.find(
    (account) => account.email_hash === emailHash && account.network === clean,
  ) || null;
}

function loadMfaChallenge(challengeId, emailHash) {
  const [payload, signature] = String(challengeId || '').split('.');
  if (payload && signature) {
    const expected = mfaChallengeSignature(payload);
    const signatureBuffer = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expected);
    if (
      signatureBuffer.length === expectedBuffer.length &&
      crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
    ) {
      try {
        const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
        if (
          parsed?.typ === 'coverfi-mfa-challenge' &&
          parsed.emailHash === emailHash &&
          parsed.exp > Date.now() &&
          (parsed.mode === 'enroll' || parsed.mode === 'verify')
        ) {
          return {
            id: challengeId,
            email_hash: parsed.emailHash,
            email: cleanEmail(parsed.email),
            mode: parsed.mode,
            secret: parsed.secret || '',
            attempts: 0,
            expires_at: parsed.exp,
          };
        }
      } catch {
        // Fall through to legacy in-memory challenges.
      }
    }
  }

  const now = Date.now();
  for (let index = memoryMfaChallenges.length - 1; index >= 0; index -= 1) {
    const challenge = memoryMfaChallenges[index];
    if (challenge.expires_at <= now || challenge.attempts >= 5) {
      memoryMfaChallenges.splice(index, 1);
    }
  }
  return memoryMfaChallenges.find(
    (challenge) => challenge.id === challengeId && challenge.email_hash === emailHash,
  ) || null;
}

export async function verifyEmailOtp({ email, otpId, otp, network = env.contracts.network }) {
  const normalizedEmail = cleanEmail(email);
  if (!isValidEmail(normalizedEmail) || !otpId || !/^\d{6}$/.test(String(otp || ''))) {
    const error = new Error('Email, OTP id, and six-digit OTP are required.');
    error.statusCode = 400;
    throw error;
  }

  const emailHash = emailRef(normalizedEmail);
  const requestedNetwork = cleanNetwork(network);
  const record = await loadOtpRecord(otpId, emailHash);
  if (!record) {
    const error = new Error('OTP was not found or has expired.');
    error.statusCode = 401;
    throw error;
  }

  if (record.status !== 'pending' || new Date(record.expires_at).getTime() <= Date.now()) {
    await updateOtpRecord(record, { status: 'expired', attempts: record.attempts });
    const error = new Error('OTP is expired. Request a new code.');
    error.statusCode = 401;
    throw error;
  }

  const attempts = Number(record.attempts || 0) + 1;
  const candidateHash = otpHash(emailHash, record.nonce, otp);
  const valid = crypto.timingSafeEqual(Buffer.from(candidateHash), Buffer.from(record.otp_hash));

  if (!valid) {
    const locked = attempts >= env.onboarding.otpMaxAttempts;
    await updateOtpRecord(record, { status: locked ? 'locked' : 'pending', attempts });
    const error = new Error(locked ? 'Too many OTP attempts. Request a new code.' : 'OTP is incorrect.');
    error.statusCode = 401;
    throw error;
  }

  await updateOtpRecord(record, {
    status: 'verified',
    attempts,
    verifiedAt: Date.now(),
  });

  const authenticator = await loadMfaAuthenticator(emailHash);
  if (authenticator) {
    const challenge = createMfaChallenge({ emailHash, email: normalizedEmail, mode: 'verify' });
    return {
      emailHash,
      mfaRequired: true,
      challengeId: challenge.id,
      expiresAt: new Date(challenge.expires_at).toISOString(),
      existingWallet: await loadEmailWalletAccount(emailHash, requestedNetwork),
    };
  }

  const existingWallet = await loadEmailWalletAccount(emailHash, requestedNetwork);

  const secret = generateTotpSecret();
  const challenge = createMfaChallenge({
    emailHash,
    email: normalizedEmail,
    mode: 'enroll',
    secret,
  });
  return {
    emailHash,
    token: createEmailSessionToken(emailHash),
    expiresAt: new Date(Date.now() + env.onboarding.tokenTtlMs).toISOString(),
    existingWallet,
    mfaSetupAvailable: true,
    challengeId: challenge.id,
    secret,
    otpauthUrl: otpauthUrl(normalizedEmail, secret),
    mfaChallengeExpiresAt: new Date(challenge.expires_at).toISOString(),
  };
}

export async function verifyEmailMfa({ email, challengeId, code, network = env.contracts.network }) {
  const normalizedEmail = cleanEmail(email);
  if (!isValidEmail(normalizedEmail) || !challengeId || !/^\d{6}$/.test(String(code || ''))) {
    const error = new Error('Email, MFA challenge, and six-digit authenticator code are required.');
    error.statusCode = 400;
    throw error;
  }

  const emailHash = emailRef(normalizedEmail);
  const requestedNetwork = cleanNetwork(network);
  const challenge = loadMfaChallenge(challengeId, emailHash);
  if (!challenge) {
    const error = new Error('Authenticator challenge expired. Request a new email code.');
    error.statusCode = 401;
    throw error;
  }

  challenge.attempts += 1;
  let secret = challenge.secret;
  if (challenge.mode === 'verify') {
    const authenticator = await loadMfaAuthenticator(emailHash);
    if (!authenticator) {
      const error = new Error('Authenticator is not enrolled. Request a new email code.');
      error.statusCode = 401;
      throw error;
    }
    secret = decryptMfaSecret(authenticator);
  }

  if (!verifyTotp(secret, code)) {
    const error = new Error(challenge.attempts >= 5
      ? 'Too many authenticator attempts. Request a new email code.'
      : 'Authenticator code is incorrect.');
    error.statusCode = 401;
    throw error;
  }

  const enrolledNow = challenge.mode === 'enroll';
  if (enrolledNow) {
    await saveMfaAuthenticator(emailHash, secret);
  }
  const index = memoryMfaChallenges.findIndex((item) => item.id === challenge.id);
  if (index >= 0) memoryMfaChallenges.splice(index, 1);

  return {
    emailHash,
    token: createEmailSessionToken(emailHash),
    expiresAt: new Date(Date.now() + env.onboarding.tokenTtlMs).toISOString(),
    mfaEnabled: enrolledNow || challenge.mode === 'verify',
    mfaEnrollmentProof: enrolledNow ? createMfaEnrollmentProof(emailHash) : undefined,
    existingWallet: await loadEmailWalletAccount(emailHash, requestedNetwork),
  };
}

export async function recordEmailWallet({ emailHash, walletAddress, network, fundingStatus, fundingSource, fundingTransactionHash, metadata = {} }) {
  const ref = walletRef(walletAddress);
  if (isDatabaseConfigured()) {
    const result = await query(
      `INSERT INTO email_wallet_accounts
         (email_hash, wallet_ref, wallet_address, network, funding_status, funding_source, funding_transaction_hash, funded_at, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (email_hash, wallet_ref, network)
       DO UPDATE SET
         funding_status = EXCLUDED.funding_status,
         funding_source = EXCLUDED.funding_source,
         funding_transaction_hash = EXCLUDED.funding_transaction_hash,
         funded_at = COALESCE(EXCLUDED.funded_at, email_wallet_accounts.funded_at),
         metadata = email_wallet_accounts.metadata || EXCLUDED.metadata
       RETURNING id, wallet_address, network, funding_status, funding_source, funding_transaction_hash, created_at, funded_at`,
      [
        emailHash,
        ref,
        walletAddress,
        network,
        fundingStatus,
        fundingSource || null,
        fundingTransactionHash || null,
        fundingStatus === 'friendbot_funded' || fundingStatus === 'sponsored_funded' ? new Date().toISOString() : null,
        metadata,
      ],
    );
    return result.rows[0];
  }

  requirePersistentStore('Email wallet account storage');
  const existing = memoryWalletAccounts.find(
    (account) => account.email_hash === emailHash && account.wallet_ref === ref && account.network === network,
  );
  const next = existing || {
    id: crypto.randomUUID(),
    email_hash: emailHash,
    wallet_ref: ref,
    wallet_address: walletAddress,
    network,
    created_at: new Date().toISOString(),
  };
  next.funding_status = fundingStatus;
  next.funding_source = fundingSource || null;
  next.funding_transaction_hash = fundingTransactionHash || null;
  next.funded_at = fundingStatus === 'friendbot_funded' ? new Date().toISOString() : null;
  next.metadata = { ...(next.metadata || {}), ...metadata };
  if (!existing) memoryWalletAccounts.unshift(next);
  return next;
}

export async function fundTestnetWallet(walletAddress) {
  const url = new URL(env.onboarding.friendbotUrl);
  url.searchParams.set('addr', walletAddress);
  const response = await fetch(url, { method: 'GET' });
  const body = await response.text().catch(() => '');

  if (!response.ok) {
    const existingAccount = await waitForTestnetAccount(walletAddress).catch(() => null);
    if (existingAccount) {
      return {
        status: 'friendbot_funded',
        source: 'stellar-friendbot-existing-account',
        transactionHash: '',
        raw: body.slice(0, 500),
      };
    }

    const error = new Error(body || `Friendbot returned ${response.status}.`);
    error.statusCode = 502;
    throw error;
  }

  let parsed = null;
  try {
    parsed = body ? JSON.parse(body) : null;
  } catch {
    parsed = null;
  }

  await waitForTestnetAccount(walletAddress);

  return {
    status: 'friendbot_funded',
    source: 'stellar-friendbot',
    transactionHash: parsed?.hash || parsed?.tx_hash || parsed?.id || '',
    raw: parsed || body.slice(0, 500),
  };
}

async function waitForTestnetAccount(walletAddress) {
  const rpcUrl = env.contracts.network === 'testnet'
    ? env.contracts.rpcUrl
    : 'https://soroban-testnet.stellar.org';
  const server = new rpc.Server(rpcUrl, { allowHttp: false });
  let lastError;

  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      return await server.getAccount(walletAddress);
    } catch (error) {
      lastError = error;
      await sleep(1000);
    }
  }

  const error = new Error(`Friendbot funded the wallet, but Stellar RPC did not expose the account yet. Try again in a few seconds. ${lastError?.message || ''}`.trim());
  error.statusCode = 504;
  throw error;
}

export async function saveZkCommitment({ subjectRef, commitment, commitmentScheme = 'sha256-v0', circuitId, publicSignals = {}, expiresAt = null }) {
  if (!subjectRef || !commitment || !circuitId) {
    const error = new Error('subjectRef, commitment, and circuitId are required.');
    error.statusCode = 400;
    throw error;
  }

  if (isDatabaseConfigured()) {
    const result = await query(
      `INSERT INTO zk_commitments (subject_ref, commitment, commitment_scheme, circuit_id, public_signals, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (commitment)
       DO UPDATE SET public_signals = EXCLUDED.public_signals
       RETURNING id, subject_ref, commitment, commitment_scheme, circuit_id, public_signals, status, created_at, expires_at`,
      [subjectRef, commitment, commitmentScheme, circuitId, publicSignals, expiresAt],
    );
    return result.rows[0];
  }

  requirePersistentStore('ZK commitment storage');
  const existing = memoryZkCommitments.find((item) => item.commitment === commitment);
  if (existing) return existing;
  const stored = {
    id: crypto.randomUUID(),
    subject_ref: subjectRef,
    commitment,
    commitment_scheme: commitmentScheme,
    circuit_id: circuitId,
    public_signals: publicSignals,
    status: 'active',
    created_at: new Date().toISOString(),
    expires_at: expiresAt,
  };
  memoryZkCommitments.unshift(stored);
  return stored;
}

export async function recordZkProofEvent({ subjectRef, commitmentId = null, circuitId, proofSystem, proof, publicSignals = {}, verificationStatus = 'recorded', verifierNotes = '' }) {
  const proofHash = sha256(typeof proof === 'string' ? proof : JSON.stringify(proof || {}));
  if (isDatabaseConfigured()) {
    const result = await query(
      `INSERT INTO zk_proof_events
         (subject_ref, commitment_id, circuit_id, proof_system, proof_hash, public_signals, verification_status, verifier_notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, subject_ref, commitment_id, circuit_id, proof_system, proof_hash, public_signals, verification_status, verifier, verifier_notes, created_at`,
      [subjectRef || null, commitmentId, circuitId, proofSystem, proofHash, publicSignals, verificationStatus, verifierNotes || null],
    );
    return result.rows[0];
  }

  requirePersistentStore('ZK proof event storage');
  const stored = {
    id: crypto.randomUUID(),
    subject_ref: subjectRef || null,
    commitment_id: commitmentId,
    circuit_id: circuitId,
    proof_system: proofSystem,
    proof_hash: proofHash,
    public_signals: publicSignals,
    verification_status: verificationStatus,
    verifier: 'coverfi-backend',
    verifier_notes: verifierNotes || null,
    created_at: new Date().toISOString(),
  };
  memoryZkProofEvents.unshift(stored);
  return stored;
}

function sanitizeZkProofEvent(row) {
  if (!row) return null;
  return {
    id: row.id,
    subjectRef: row.subject_ref || null,
    commitmentId: row.commitment_id || null,
    circuitId: row.circuit_id,
    proofSystem: row.proof_system,
    proofHash: row.proof_hash,
    publicSignals: row.public_signals || {},
    verificationStatus: row.verification_status,
    verifier: row.verifier || 'coverfi-backend',
    verifierNotes: row.verifier_notes || null,
    createdAt: row.created_at,
  };
}

export async function listZkProofEvents({ subjectRef, circuitId = '', limit = 20 }) {
  const cleanSubjectRef = String(subjectRef || '').trim().slice(0, 180);
  const cleanCircuitId = String(circuitId || '').trim().slice(0, 120);
  const safeLimit = Math.min(Math.max(Number(limit) || 20, 1), 50);
  if (!cleanSubjectRef) {
    const error = new Error('subjectRef is required.');
    error.statusCode = 400;
    throw error;
  }

  if (isDatabaseConfigured()) {
    const params = [cleanSubjectRef];
    let filter = 'subject_ref = $1';
    if (cleanCircuitId) {
      params.push(cleanCircuitId);
      filter += ` AND circuit_id = $${params.length}`;
    }
    params.push(safeLimit);

    const result = await query(
      `SELECT id, subject_ref, commitment_id, circuit_id, proof_system, proof_hash, public_signals,
              verification_status, verifier, verifier_notes, created_at
         FROM zk_proof_events
        WHERE ${filter}
        ORDER BY created_at DESC
        LIMIT $${params.length}`,
      params,
    );
    return result.rows.map(sanitizeZkProofEvent);
  }

  requirePersistentStore('ZK proof event storage');
  return memoryZkProofEvents
    .filter((event) => (
      event.subject_ref === cleanSubjectRef &&
      (!cleanCircuitId || event.circuit_id === cleanCircuitId)
    ))
    .slice(0, safeLimit)
    .map(sanitizeZkProofEvent);
}
