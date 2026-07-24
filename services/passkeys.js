import crypto from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { env } from '../config/env.js';
import { isDatabaseConfigured, query } from './database.js';

function passkeyError(message, statusCode = 400) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function requirePersistentStore() {
  if (!isDatabaseConfigured()) {
    throw passkeyError('Passkeys are temporarily unavailable while secure account storage is being configured.', 503);
  }
}

function cleanLabel(value) {
  return String(value || '').trim().replace(/[\r\n\t]/g, ' ').slice(0, 80);
}

async function listCredentials(emailHash) {
  requirePersistentStore();
  const result = await query(
    `SELECT credential_id, public_key, counter, transports
       FROM email_passkeys
      WHERE email_hash = $1
      ORDER BY created_at DESC`,
    [emailHash],
  );
  return result.rows;
}

async function createChallenge(emailHash, challenge, purpose) {
  const result = await query(
    `INSERT INTO email_passkey_challenges (email_hash, challenge, purpose, expires_at)
     VALUES ($1, $2, $3, now() + ($4 * interval '1 millisecond'))
     RETURNING id`,
    [emailHash, challenge, purpose, env.passkeys.challengeTtlMs],
  );
  return result.rows[0].id;
}

async function consumeChallenge({ challengeId, emailHash, purpose }) {
  if (!/^[0-9a-f-]{36}$/i.test(String(challengeId || ''))) {
    throw passkeyError('Passkey setup has expired. Start it again.');
  }
  const result = await query(
    `UPDATE email_passkey_challenges
        SET used_at = now()
      WHERE id = $1
        AND email_hash = $2
        AND purpose = $3
        AND used_at IS NULL
        AND expires_at > now()
      RETURNING challenge`,
    [challengeId, emailHash, purpose],
  );
  if (!result.rows[0]) {
    throw passkeyError('Passkey setup has expired or was already used. Start it again.');
  }
  return result.rows[0].challenge;
}

export async function createPasskeyRegistrationOptions({ emailHash, label = '' }) {
  requirePersistentStore();
  const existing = await listCredentials(emailHash);
  const displayName = cleanLabel(label) || 'CoverFi account';
  const options = await generateRegistrationOptions({
    rpName: env.passkeys.rpName,
    rpID: env.passkeys.rpId,
    userName: `coverfi-${emailHash.slice(0, 24)}`,
    userDisplayName: displayName,
    userID: crypto.createHash('sha256').update(`coverfi-passkey:${emailHash}`).digest(),
    attestationType: 'none',
    timeout: 60_000,
    excludeCredentials: existing.map((credential) => ({
      id: credential.credential_id,
      transports: Array.isArray(credential.transports) ? credential.transports : [],
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
    supportedAlgorithmIDs: [-7, -257],
  });
  const challengeId = await createChallenge(emailHash, options.challenge, 'registration');
  return { challengeId, options };
}

export async function verifyPasskeyRegistration({ emailHash, challengeId, response }) {
  requirePersistentStore();
  if (!response || typeof response !== 'object') {
    throw passkeyError('Passkey response is required.');
  }
  const expectedChallenge = await consumeChallenge({ challengeId, emailHash, purpose: 'registration' });
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: env.passkeys.origin,
      expectedRPID: env.passkeys.rpId,
      requireUserVerification: true,
    });
  } catch (error) {
    throw passkeyError(error instanceof Error ? `Passkey verification failed: ${error.message}` : 'Passkey verification failed.');
  }
  if (!verification.verified || !verification.registrationInfo?.credential) {
    throw passkeyError('Passkey verification was not accepted.');
  }
  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  const result = await query(
    `INSERT INTO email_passkeys
       (email_hash, credential_id, public_key, counter, transports, device_type, backed_up)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (credential_id)
     DO UPDATE SET
       email_hash = EXCLUDED.email_hash,
       public_key = EXCLUDED.public_key,
       counter = EXCLUDED.counter,
       transports = EXCLUDED.transports,
       device_type = EXCLUDED.device_type,
       backed_up = EXCLUDED.backed_up,
       last_used_at = now()
     RETURNING id, created_at`,
    [
      emailHash,
      credential.id,
      Buffer.from(credential.publicKey),
      credential.counter,
      JSON.stringify(credential.transports || []),
      credentialDeviceType,
      credentialBackedUp,
    ],
  );
  return { id: result.rows[0].id, createdAt: result.rows[0].created_at };
}

export async function createPasskeyAuthenticationOptions({ emailHash }) {
  requirePersistentStore();
  const credentials = await listCredentials(emailHash);
  if (!credentials.length) {
    throw passkeyError('No passkey is available for this email. Use email OTP instead.', 404);
  }
  const options = await generateAuthenticationOptions({
    rpID: env.passkeys.rpId,
    timeout: 60_000,
    userVerification: 'required',
    allowCredentials: credentials.map((credential) => ({
      id: credential.credential_id,
      transports: Array.isArray(credential.transports) ? credential.transports : [],
    })),
  });
  const challengeId = await createChallenge(emailHash, options.challenge, 'authentication');
  return { challengeId, options };
}

export async function verifyPasskeyAuthentication({ emailHash, challengeId, response }) {
  requirePersistentStore();
  if (!response || typeof response !== 'object' || !response.id) {
    throw passkeyError('Passkey response is required.');
  }
  const expectedChallenge = await consumeChallenge({ challengeId, emailHash, purpose: 'authentication' });
  const credentialResult = await query(
    `SELECT id, credential_id, public_key, counter, transports
       FROM email_passkeys
      WHERE email_hash = $1 AND credential_id = $2
      LIMIT 1`,
    [emailHash, String(response.id)],
  );
  const stored = credentialResult.rows[0];
  if (!stored) {
    throw passkeyError('This passkey is not registered for the selected email.', 401);
  }
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: env.passkeys.origin,
      expectedRPID: env.passkeys.rpId,
      credential: {
        id: stored.credential_id,
        publicKey: new Uint8Array(stored.public_key),
        counter: Number(stored.counter || 0),
        transports: Array.isArray(stored.transports) ? stored.transports : [],
      },
      requireUserVerification: true,
    });
  } catch (error) {
    throw passkeyError(error instanceof Error ? `Passkey verification failed: ${error.message}` : 'Passkey verification failed.', 401);
  }
  if (!verification.verified || !verification.authenticationInfo.userVerified) {
    throw passkeyError('Passkey verification was not accepted.', 401);
  }
  const update = await query(
    `UPDATE email_passkeys
        SET counter = $1,
            device_type = $2,
            backed_up = $3,
            last_used_at = now()
      WHERE id = $4 AND counter <= $1`,
    [
      verification.authenticationInfo.newCounter,
      verification.authenticationInfo.credentialDeviceType,
      verification.authenticationInfo.credentialBackedUp,
      stored.id,
    ],
  );
  if (!update.rowCount) {
    throw passkeyError('Passkey counter could not be safely updated. Use email OTP instead.', 401);
  }
  return { verified: true };
}
