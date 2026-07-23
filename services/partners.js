import crypto from 'crypto';
import { env } from '../config/env.js';
import { query } from './database.js';

const slugPattern = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;
const apiKeyPattern = /^(cf_(test|live)_[A-Za-z0-9_-]{28,}|cfpk_live_[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{32,})$/;
const publicKeyPattern = /^cf_pk_(test|live)_[A-Za-z0-9_-]{28,}$/;
const defaultScopes = [
  'protection.quotes.create',
  'protection.positions.create',
  'protection.positions.read',
  'protection.positions.cancel',
  'assets.read',
  'pricing.read',
  'usage.read',
  'wallets.read',
  'wallets.submit',
  'claims.read',
  'payouts.read',
  'receipts.read',
  'webhooks.manage',
];
const sessionTokenPattern = /^cfs_[A-Za-z0-9_-]{28,}$/;

export function isPartnerAdminWallet(walletAddress) {
  return env.partners.adminWallets.includes(walletAddress);
}

export function validatePartnerSlug(slug) {
  const value = String(slug || '').trim().toLowerCase();
  return slugPattern.test(value) ? value : '';
}

export function validateApplicationEnvironment(value) {
  const environment = String(value || '').trim().toLowerCase();
  return ['development', 'staging', 'production'].includes(environment)
    ? environment
    : 'development';
}

export function validateKeyMode(value) {
  const mode = String(value || '').trim().toLowerCase();
  return mode === 'live' ? 'live' : 'test';
}

function partnerKeyHash(secret) {
  return crypto
    .createHmac('sha256', env.partners.apiKeyPepper)
    .update(`partner-api-key:${secret}`)
    .digest('hex');
}

export function createPartnerApiSecret(mode = 'test') {
  return `cf_${validateKeyMode(mode)}_${crypto.randomBytes(32).toString('base64url')}`;
}

export function createPartnerPublishableKey(mode = 'test') {
  return `cf_pk_${validateKeyMode(mode)}_${crypto.randomBytes(24).toString('base64url')}`;
}

export function parsePartnerApiKey(value) {
  const secret = String(value || '').trim();
  if (!apiKeyPattern.test(secret)) return null;
  const mode = secret.startsWith('cf_live_') || secret.startsWith('cfpk_live_') ? 'live' : 'test';
  return {
    secret,
    mode,
    prefix: secret.includes('.') ? secret.split('.')[0] : secret.slice(0, 16),
    last4: secret.slice(-4),
    hash: partnerKeyHash(secret),
  };
}

export function parsePartnerPublishableKey(value) {
  const key = String(value || '').trim();
  if (!publicKeyPattern.test(key)) return null;
  return {
    key,
    mode: key.startsWith('cf_pk_live_') ? 'live' : 'test',
    prefix: key.slice(0, 19),
    last4: key.slice(-4),
    hash: partnerKeyHash(key),
  };
}

export async function createPartner(input) {
  const result = await query(
    `INSERT INTO partners (slug, display_name, onchain_partner_address, website_url, status, created_by_wallet_ref)
     VALUES ($1, $2, $3, $4, 'pending', $5)
     RETURNING id, slug, display_name, onchain_partner_address, website_url, status, created_at, updated_at`,
    [
      input.slug,
      input.displayName,
      input.onchainPartnerAddress || null,
      input.websiteUrl || null,
      input.createdByWalletRef || null,
    ],
  );
  return result.rows[0];
}

export async function listPartners() {
  const result = await query(
    `SELECT id, slug, display_name, onchain_partner_address, website_url, status, created_at, updated_at
     FROM partners
     ORDER BY created_at DESC
     LIMIT 100`,
  );
  return result.rows;
}

export async function listPartnersForWalletRef(walletRef, walletAddress = '') {
  const result = await query(
    `SELECT id, slug, display_name, onchain_partner_address, website_url, status,
       kyb_status, kyb_provider, kyb_session_id, kyb_verified_at, kyb_updated_at,
       created_at, updated_at
     FROM partners
     WHERE created_by_wallet_ref = $1
        OR ($2::text != '' AND onchain_partner_address = $2)
     ORDER BY created_at DESC
     LIMIT 100`,
    [walletRef, walletAddress || ''],
  );
  return result.rows;
}

export async function setPartnerStatus(partnerId, status) {
  const result = await query(
    `UPDATE partners
     SET status = $2, updated_at = now()
     WHERE id = $1
     RETURNING id, slug, display_name, onchain_partner_address, website_url, status, created_at, updated_at`,
    [partnerId, status],
  );
  return result.rows[0] || null;
}

export async function createPartnerApplication(input) {
  const publishable = createPartnerPublishableKey(input.mode || input.environment);
  const parsed = parsePartnerPublishableKey(publishable);
  const result = await query(
    `INSERT INTO partner_applications
       (partner_id, name, slug, description, website_url, logo_url, environment,
        allowed_origins, allowed_ip_addresses, webhook_url, status,
        publishable_key_prefix, publishable_key_last4, publishable_key_hash)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending_review', $11, $12, $13)
     RETURNING id, partner_id, name, slug, description, website_url, logo_url,
       environment, allowed_origins, allowed_ip_addresses, webhook_url, status,
       publishable_key_prefix, publishable_key_last4, created_at, updated_at`,
    [
      input.partnerId,
      input.name,
      input.slug,
      input.description || null,
      input.websiteUrl || null,
      input.logoUrl || null,
      validateApplicationEnvironment(input.environment),
      input.allowedOrigins || [],
      input.allowedIpAddresses || [],
      input.webhookUrl || null,
      parsed.prefix,
      parsed.last4,
      parsed.hash,
    ],
  );
  return {
    ...result.rows[0],
    publishableKey: publishable,
  };
}

export async function listPartnerApplications(partnerId) {
  const result = await query(
    `SELECT id, partner_id, name, slug, description, website_url, logo_url,
       environment, allowed_origins, allowed_ip_addresses, webhook_url, status,
       publishable_key_prefix, publishable_key_last4, created_at, updated_at
     FROM partner_applications
     WHERE partner_id = $1 AND status != 'deleted'
     ORDER BY created_at DESC`,
    [partnerId],
  );
  return result.rows;
}

export async function getPartnerOwnedByWallet(partnerId, walletRef, walletAddress = '') {
  const result = await query(
    `SELECT id, slug, display_name, status, created_by_wallet_ref,
       kyb_status, kyb_provider, kyb_session_id, kyb_verified_at, kyb_updated_at
     FROM partners
     WHERE id = $1
       AND (
         created_by_wallet_ref = $2
         OR ($3::text != '' AND onchain_partner_address = $3)
       )`,
    [partnerId, walletRef, walletAddress || ''],
  );
  return result.rows[0] || null;
}

export async function createPartnerKey(input) {
  const mode = validateKeyMode(input.mode);
  const secret = createPartnerApiSecret(mode);
  const parsed = parsePartnerApiKey(secret);
  const scopes = Array.isArray(input.scopes) && input.scopes.length
    ? input.scopes.map(String)
    : defaultScopes;
  const result = await query(
    `INSERT INTO partner_api_keys
       (partner_id, application_id, label, mode, key_prefix, key_last4, key_hash,
        scopes, allowed_origins, allowed_ip_addresses, expires_at,
        rate_limit_per_minute, created_by_wallet_ref)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
     RETURNING id, partner_id, application_id, label, mode, key_prefix, key_last4,
       scopes, allowed_origins, allowed_ip_addresses, expires_at,
       rate_limit_per_minute, active, revoked_at, created_at`,
    [
      input.partnerId,
      input.applicationId || null,
      input.label,
      mode,
      parsed.prefix,
      parsed.last4,
      parsed.hash,
      scopes,
      input.allowedOrigins || [],
      input.allowedIpAddresses || [],
      input.expiresAt || null,
      input.rateLimitPerMinute || env.partners.defaultRateLimitPerMinute,
      input.createdByWalletRef || null,
    ],
  );
  return {
    ...result.rows[0],
    secret,
  };
}

export async function createPartnerWebhook(input) {
  const secret = crypto.randomBytes(32).toString('base64url');
  const secretHash = crypto
    .createHmac('sha256', env.partners.apiKeyPepper)
    .update(`partner-webhook:${secret}`)
    .digest('hex');
  const eventTypes = Array.isArray(input.eventTypes) && input.eventTypes.length
    ? input.eventTypes.map(String)
    : [
      'position.created',
      'position.awaiting_oracle',
      'position.settled',
      'payout.claimed',
      'principal.withdrawn',
      'reserve.utilization_changed',
      'oracle.stale',
      'oracle.recovered',
    ];
  const result = await query(
    `INSERT INTO partner_webhooks (partner_id, url, secret_hash, event_types)
     VALUES ($1, $2, $3, $4)
     RETURNING id, partner_id, url, event_types, active, created_at`,
    [input.partnerId, input.url, secretHash, eventTypes],
  );
  return {
    ...result.rows[0],
    secret,
  };
}

export async function authenticatePartnerApiKey(headerValue, requiredScope) {
  const parsed = parsePartnerApiKey(String(headerValue || '').replace(/^Bearer\s+/i, ''));
  if (!parsed) return null;

  const result = await query(
    `UPDATE partner_api_keys key
     SET last_used_at = now()
       , request_count = request_count + 1
     FROM partners partner
     LEFT JOIN partner_applications app ON app.id = key.application_id
     WHERE key.partner_id = partner.id
       AND key.key_hash = $1
       AND key.active = true
       AND key.revoked_at IS NULL
       AND (key.expires_at IS NULL OR key.expires_at > now())
       AND partner.status = 'enabled'
       AND partner.kyb_status = 'verified'
       AND (app.id IS NULL OR app.status = 'active')
     RETURNING key.id, key.partner_id, key.application_id, key.mode, key.scopes,
       key.allowed_origins, key.allowed_ip_addresses, key.rate_limit_per_minute,
       partner.slug, partner.display_name, partner.status, partner.kyb_status,
       app.slug AS application_slug, app.name AS application_name,
       app.environment AS application_environment, app.status AS application_status,
       app.allowed_origins AS application_allowed_origins,
       app.allowed_ip_addresses AS application_allowed_ip_addresses`,
    [parsed.hash],
  );
  const key = result.rows[0];
  if (!key) return null;
  if (requiredScope && !key.scopes.includes(requiredScope)) return null;
  return { ...key, credential_type: 'api_key' };
}

export async function authenticatePartnerSession(headerValue, requiredScope) {
  const token = String(headerValue || '').replace(/^Bearer\s+/i, '').trim();
  if (!sessionTokenPattern.test(token)) return null;
  const tokenHash = partnerKeyHash(token);

  const result = await query(
    `SELECT session.id, session.partner_id, session.application_id, session.scopes,
       partner.slug, partner.display_name, partner.status, partner.kyb_status,
       app.slug AS application_slug, app.name AS application_name,
       app.environment AS application_environment, app.status AS application_status,
       app.allowed_origins AS application_allowed_origins,
       app.allowed_ip_addresses AS application_allowed_ip_addresses
     FROM partner_sessions session
     JOIN partners partner ON partner.id = session.partner_id
     LEFT JOIN partner_applications app ON app.id = session.application_id
     WHERE session.token_hash = $1
       AND session.revoked_at IS NULL
       AND session.expires_at > now()
       AND partner.status = 'enabled'
       AND partner.kyb_status = 'verified'
       AND (app.id IS NULL OR app.status = 'active')`,
    [tokenHash],
  );
  const session = result.rows[0];
  if (!session) return null;
  if (requiredScope && !session.scopes.includes(requiredScope)) return null;
  return {
    ...session,
    credential_type: 'session',
    rate_limit_per_minute: env.partners.defaultRateLimitPerMinute,
    allowed_origins: [],
    allowed_ip_addresses: [],
  };
}

export async function logPartnerRequest(input) {
  const result = await query(
    `INSERT INTO partner_requests
       (request_id, partner_id, application_id, api_key_id, method, path,
        status_code, error_code, latency_ms, idempotency_key, request_body, response_body)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
     RETURNING id, request_id, created_at`,
    [
      input.requestId,
      input.partnerId || null,
      input.applicationId || null,
      input.apiKeyId || null,
      input.method,
      input.path,
      input.statusCode || null,
      input.errorCode || null,
      input.latencyMs || null,
      input.idempotencyKey || null,
      input.requestBody || null,
      input.responseBody || null,
    ],
  );
  return result.rows[0];
}

export async function createPartnerQuote(input) {
  const result = await query(
    `INSERT INTO partner_quotes
       (partner_id, application_id, asset, amount, duration_days, protection_percentage,
        premium_amount, maximum_payout, quote_payload, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + interval '15 minutes')
     RETURNING id, asset, amount, duration_days, protection_percentage,
       premium_amount, maximum_payout, quote_payload, expires_at, created_at`,
    [
      input.partnerId,
      input.applicationId || null,
      input.asset,
      input.amount,
      input.durationDays,
      input.protectionPercentage,
      input.premiumAmount,
      input.maximumPayout,
      input.quotePayload || {},
    ],
  );
  return result.rows[0];
}

export async function getPartnerQuote(quoteId, partnerId) {
  const result = await query(
    `SELECT id, partner_id, application_id, asset, amount, duration_days,
       protection_percentage, premium_amount, maximum_payout, quote_payload,
       expires_at, created_at
     FROM partner_quotes
     WHERE id = $1 AND partner_id = $2`,
    [quoteId, partnerId],
  );
  return result.rows[0] || null;
}

export async function createPartnerPosition(input) {
  const result = await query(
    `INSERT INTO partner_positions
       (partner_id, application_id, quote_id, wallet_ref, status, network,
        transaction_xdr, contract_position_id, position_payload, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + interval '15 minutes')
     RETURNING id, quote_id, status, network, transaction_xdr,
       contract_position_id, position_payload, expires_at, created_at, updated_at`,
    [
      input.partnerId,
      input.applicationId || null,
      input.quoteId,
      input.walletRef || null,
      input.status,
      input.network,
      input.transactionXdr || null,
      input.contractPositionId || null,
      input.positionPayload || {},
    ],
  );
  return result.rows[0];
}

export async function getPartnerPosition(positionId, partnerId) {
  const result = await query(
    `SELECT id, quote_id, status, network, transaction_xdr, contract_position_id,
       wallet_ref, position_payload, expires_at, created_at, updated_at
     FROM partner_positions
     WHERE id = $1 AND partner_id = $2`,
    [positionId, partnerId],
  );
  return result.rows[0] || null;
}

export async function listPartnerPositions(partnerId, limit = 50) {
  const result = await query(
    `SELECT id, quote_id, status, network, contract_position_id,
       position_payload, expires_at, created_at, updated_at
     FROM partner_positions
     WHERE partner_id = $1
     ORDER BY created_at DESC
     LIMIT $2`,
    [partnerId, Math.max(1, Math.min(100, Number(limit) || 50))],
  );
  return result.rows;
}

export async function createPartnerSession(input) {
  const token = `cfs_${crypto.randomBytes(32).toString('base64url')}`;
  const tokenHash = partnerKeyHash(token);
  const result = await query(
    `INSERT INTO partner_sessions
       (partner_id, application_id, token_hash, customer_reference, wallet_ref, scopes, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, now() + ($7::int * interval '1 second'))
     RETURNING id, partner_id, application_id, customer_reference, scopes, expires_at, created_at`,
    [
      input.partnerId,
      input.applicationId || null,
      tokenHash,
      input.customerReference || null,
      input.walletRef || null,
      input.scopes || ['protection.quotes.create', 'protection.positions.create'],
      Math.max(60, Math.min(3600, Number(input.expiresIn) || 900)),
    ],
  );
  return {
    ...result.rows[0],
    token,
  };
}

export async function getPartnerMetrics(partnerId, days = 30) {
  const result = await query(
    `SELECT day, active_wallets, positions, protected_notional_stroops,
       premium_volume_stroops, payouts_stroops, cohort_suppressed
     FROM daily_partner_metrics
     WHERE partner_id = $1
       AND day >= current_date - ($2::int * interval '1 day')
     ORDER BY day DESC`,
    [partnerId, Math.max(1, Math.min(365, Number(days) || 30))],
  );
  return result.rows;
}

export async function getProtocolMetrics(days = 30) {
  const result = await query(
    `SELECT day, active_wallets, new_wallets, quotes, positions,
       protected_notional_stroops, premium_volume_stroops, protocol_revenue_stroops,
       safety_funding_stroops, automation_funding_stroops, underwriting_premium_stroops,
       settlements, claims, payouts_stroops, reserve_providers, reserve_nav_stroops,
       utilization_bps, usernames, receipts, cohort_suppressed
     FROM daily_protocol_metrics
     WHERE day >= current_date - ($1::int * interval '1 day')
     ORDER BY day DESC`,
    [Math.max(1, Math.min(365, Number(days) || 30))],
  );
  return result.rows;
}
