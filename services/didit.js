import crypto from 'crypto';
import { env } from '../config/env.js';
import { query } from './database.js';

export const DIDIT_KYB_WORKFLOW_ID = env.didit.kybWorkflowId || '08c532dc-4911-4044-8a16-138a1c3dfd19';
export const DIDIT_KYC_WORKFLOW_ID = env.didit.kycWorkflowId || '617b14a8-6576-4a00-a7a6-c35f6c8bfdbf';
const DIDIT_VERIFICATION_BASE_URL = 'https://verification.didit.me';
const diditStatusMap = {
  'Not Started': 'not_started',
  'In Progress': 'in_progress',
  'Awaiting User': 'awaiting_user',
  'In Review': 'in_review',
  Approved: 'verified',
  Declined: 'declined',
  Resubmitted: 'resubmitted',
  Abandoned: 'abandoned',
  Expired: 'expired',
  'Kyc Expired': 'expired',
};

export function isDiditConfigured() {
  return Boolean(env.didit.apiKey);
}

export function isDiditKycConfigured() {
  return Boolean(env.didit.apiKey && DIDIT_KYC_WORKFLOW_ID);
}

export function isDiditWebhookConfigured() {
  return Boolean(env.didit.webhookSecret);
}

export function normalizeDiditStatus(status) {
  return diditStatusMap[status] || 'unknown';
}

function shortenFloats(value) {
  if (Array.isArray(value)) return value.map(shortenFloats);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, shortenFloats(nested)]),
    );
  }
  if (typeof value === 'number' && !Number.isInteger(value) && value % 1 === 0) {
    return Math.trunc(value);
  }
  return value;
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        acc[key] = sortKeys(value[key]);
        return acc;
      }, {});
  }
  return value;
}

function timingSafeEqualText(left, right) {
  const leftBuffer = Buffer.from(String(left || ''), 'utf8');
  const rightBuffer = Buffer.from(String(right || ''), 'utf8');
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

export function verifyDiditWebhookPayload({ payload, signature, timestamp }) {
  const ts = Number(timestamp);
  if (!ts || Math.abs(Date.now() / 1000 - ts) > 300) {
    return { ok: false, code: 'stale' };
  }

  if (!isDiditWebhookConfigured()) {
    return { ok: false, code: 'not_configured' };
  }

  const canonical = JSON.stringify(sortKeys(shortenFloats(payload)));
  const expected = crypto
    .createHmac('sha256', env.didit.webhookSecret)
    .update(canonical, 'utf8')
    .digest('hex');

  if (!timingSafeEqualText(signature, expected)) {
    return { ok: false, code: 'bad_signature' };
  }

  return { ok: true };
}

export async function createDiditKybSession(input) {
  if (!isDiditConfigured()) {
    const error = new Error('DIDIT_API_KEY is not configured.');
    error.statusCode = 503;
    throw error;
  }

  const response = await fetch(`${DIDIT_VERIFICATION_BASE_URL}/v3/session/`, {
    method: 'POST',
    headers: {
      'x-api-key': env.didit.apiKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      workflow_id: DIDIT_KYB_WORKFLOW_ID,
      vendor_data: input.vendorData,
      callback: input.callbackUrl,
      metadata: {
        partner_id: input.partnerId,
        partner_slug: input.partnerSlug,
        verification_kind: 'partner_kyb',
      },
    }),
  });

  const bodyText = await response.text();
  const body = bodyText ? JSON.parse(bodyText) : null;

  if (!response.ok) {
    const error = new Error(body?.detail || body?.message || 'Didit KYB session creation failed.');
    error.statusCode = response.status === 403 ? 502 : response.status;
    error.providerStatus = response.status;
    throw error;
  }

  return body;
}

export async function createDiditKycSession(input) {
  if (!isDiditKycConfigured()) {
    const error = new Error('DIDIT_API_KEY and DIDIT_KYC_WORKFLOW_ID are required for user KYC.');
    error.statusCode = 503;
    throw error;
  }

  const response = await fetch(`${DIDIT_VERIFICATION_BASE_URL}/v3/session/`, {
    method: 'POST',
    headers: {
      'x-api-key': env.didit.apiKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      workflow_id: DIDIT_KYC_WORKFLOW_ID,
      vendor_data: input.vendorData,
      callback: input.callbackUrl,
      metadata: {
        wallet_ref: input.walletRef,
        payout_usd: input.payoutUsd,
        verification_kind: 'user_kyc',
      },
    }),
  });

  const bodyText = await response.text();
  const body = bodyText ? JSON.parse(bodyText) : null;

  if (!response.ok) {
    const error = new Error(body?.detail || body?.message || 'Didit KYC session creation failed.');
    error.statusCode = response.status === 403 ? 502 : response.status;
    error.providerStatus = response.status;
    throw error;
  }

  return body;
}

export async function savePartnerKybSession(input) {
  const result = await query(
    `INSERT INTO partner_kyb_sessions
       (partner_id, provider_session_id, provider_business_session_id, vendor_data,
        status, normalized_status, verification_url, workflow_id, callback_url,
        created_by_wallet_ref)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
     ON CONFLICT (provider_session_id) DO UPDATE
       SET status = EXCLUDED.status,
           normalized_status = EXCLUDED.normalized_status,
           verification_url = EXCLUDED.verification_url,
           updated_at = now()
     RETURNING id, partner_id, provider_session_id, provider_business_session_id,
       vendor_data, status, normalized_status, verification_url, workflow_id,
       callback_url, created_at, updated_at`,
    [
      input.partnerId,
      input.providerSessionId,
      input.providerBusinessSessionId || null,
      input.vendorData,
      input.status || 'Not Started',
      normalizeDiditStatus(input.status || 'Not Started'),
      input.verificationUrl,
      input.workflowId || DIDIT_KYB_WORKFLOW_ID,
      input.callbackUrl || null,
      input.createdByWalletRef || null,
    ],
  );
  await updatePartnerKybSummary(input.partnerId, {
    status: input.status || 'Not Started',
    providerSessionId: input.providerSessionId,
    decision: null,
  });
  return result.rows[0];
}

export async function getLatestPartnerKybSession(partnerId) {
  const result = await query(
    `SELECT id, partner_id, provider_session_id, provider_business_session_id,
       vendor_data, status, normalized_status, verification_url, workflow_id,
       callback_url, decision, last_webhook_event_id, created_at, updated_at
     FROM partner_kyb_sessions
     WHERE partner_id = $1
     ORDER BY created_at DESC
     LIMIT 1`,
    [partnerId],
  );
  return result.rows[0] || null;
}

export async function saveUserKycSession(input) {
  const result = await query(
    `INSERT INTO user_kyc_sessions
       (wallet_ref, provider_session_id, vendor_data, status, normalized_status,
        verification_url, workflow_id, callback_url, payout_usd)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     ON CONFLICT (provider_session_id) DO UPDATE
       SET status = EXCLUDED.status,
           normalized_status = EXCLUDED.normalized_status,
           verification_url = EXCLUDED.verification_url,
           payout_usd = EXCLUDED.payout_usd,
           updated_at = now()
     RETURNING id, wallet_ref, provider_session_id, vendor_data, status,
       normalized_status, verification_url, workflow_id, callback_url,
       payout_usd, decision, created_at, updated_at`,
    [
      input.walletRef,
      input.providerSessionId,
      input.vendorData,
      input.status || 'Not Started',
      normalizeDiditStatus(input.status || 'Not Started'),
      input.verificationUrl,
      input.workflowId || DIDIT_KYC_WORKFLOW_ID,
      input.callbackUrl || null,
      input.payoutUsd || null,
    ],
  );
  return result.rows[0];
}

export async function getLatestUserKycSession(walletRef) {
  const result = await query(
    `SELECT id, wallet_ref, provider_session_id, vendor_data, status,
       normalized_status, verification_url, workflow_id, callback_url,
       payout_usd, decision, last_webhook_event_id, created_at, updated_at
     FROM user_kyc_sessions
     WHERE wallet_ref = $1
     ORDER BY created_at DESC
     LIMIT 1`,
    [walletRef],
  );
  return result.rows[0] || null;
}

async function updatePartnerKybSummary(partnerId, input) {
  const normalizedStatus = normalizeDiditStatus(input.status);
  const result = await query(
    `UPDATE partners
     SET kyb_status = $2,
         kyb_provider = 'didit',
         kyb_session_id = $3,
         kyb_decision = $4,
         kyb_verified_at = CASE WHEN $2 = 'verified' THEN now() ELSE kyb_verified_at END,
         kyb_updated_at = now(),
         updated_at = now()
     WHERE id = $1
     RETURNING id, kyb_status, kyb_provider, kyb_session_id, kyb_verified_at, kyb_updated_at`,
    [partnerId, normalizedStatus, input.providerSessionId || null, input.decision || null],
  );
  return result.rows[0] || null;
}

export async function processDiditWebhookEvent(payload) {
  const eventId = String(payload.event_id || '');
  if (!eventId) {
    const error = new Error('Didit webhook event_id is required.');
    error.statusCode = 400;
    throw error;
  }

  const providerSessionId = String(payload.session_id || '');
  const vendorData = String(payload.vendor_data || '');
  const userSessionResult = await query(
    `SELECT wallet_ref
     FROM user_kyc_sessions
     WHERE provider_session_id = $1 OR vendor_data = $2
     ORDER BY created_at DESC
     LIMIT 1`,
    [providerSessionId, vendorData],
  );
  const userWalletRef = userSessionResult.rows[0]?.wallet_ref || null;

  const sessionResult = await query(
    `SELECT partner_id
     FROM partner_kyb_sessions
     WHERE provider_session_id = $1 OR vendor_data = $2
     ORDER BY created_at DESC
     LIMIT 1`,
    [providerSessionId, vendorData],
  );
  const partnerId = sessionResult.rows[0]?.partner_id || null;

  const eventResult = await query(
    `INSERT INTO didit_webhook_events
       (event_id, provider_session_id, partner_id, user_wallet_ref, webhook_type, status, payload)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (event_id) DO NOTHING
     RETURNING event_id`,
    [
      eventId,
      providerSessionId || null,
      partnerId,
      userWalletRef,
      payload.webhook_type || null,
      payload.status || null,
      payload,
    ],
  );

  if (!eventResult.rows[0]) {
    return { processed: false, duplicate: true, partnerId, userWalletRef };
  }

  if (providerSessionId || vendorData) {
    await query(
      `UPDATE partner_kyb_sessions
       SET status = $3,
           normalized_status = $4,
           provider_business_session_id = COALESCE($5, provider_business_session_id),
           decision = $6,
           last_webhook_event_id = $7,
           updated_at = now()
       WHERE provider_session_id = $1 OR vendor_data = $2`,
      [
        providerSessionId,
        vendorData,
        payload.status || 'Not Started',
        normalizeDiditStatus(payload.status || 'Not Started'),
        payload.business_session_id || null,
        payload.decision || null,
        eventId,
      ],
    );
  }

  if (partnerId) {
    await updatePartnerKybSummary(partnerId, {
      status: payload.status || 'Not Started',
      providerSessionId,
      decision: payload.decision || null,
    });
  }

  if (userWalletRef && (providerSessionId || vendorData)) {
    await query(
      `UPDATE user_kyc_sessions
       SET status = $3,
           normalized_status = $4,
           decision = $5,
           last_webhook_event_id = $6,
           updated_at = now()
       WHERE provider_session_id = $1 OR vendor_data = $2`,
      [
        providerSessionId,
        vendorData,
        payload.status || 'Not Started',
        normalizeDiditStatus(payload.status || 'Not Started'),
        payload.decision || null,
        eventId,
      ],
    );
  }

  return { processed: true, duplicate: false, partnerId, userWalletRef };
}
