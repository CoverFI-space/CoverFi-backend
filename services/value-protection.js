import crypto from 'crypto';
import { isDatabaseConfigured, query } from './database.js';

const tokenHash = (value) => crypto.createHash('sha256').update(`coverfi-invoice:${value}`).digest('hex');

export function createPublicInvoiceToken() {
  return `cfi_${crypto.randomBytes(24).toString('base64url')}`;
}

export function createInvoiceHash(input) {
  return crypto.createHash('sha256').update(JSON.stringify({
    merchantWallet: input.merchantWallet,
    assetContractId: input.assetContractId,
    payoutAssetContractId: input.payoutAssetContractId,
    amountStroops: String(input.amountStroops),
    durationSeconds: input.durationSeconds,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
  })).digest('hex');
}

export async function createPaymentInvoice(input) {
  if (!isDatabaseConfigured()) {
    const error = new Error('Protected invoices require the configured database.');
    error.statusCode = 503;
    throw error;
  }
  const publicToken = createPublicInvoiceToken();
  const nonce = crypto.randomUUID();
  const invoiceHash = createInvoiceHash({ ...input, nonce });
  const result = await query(
    `INSERT INTO payment_invoices
      (partner_id, public_token_hash, invoice_hash, merchant_wallet, asset_contract_id,
       payout_asset_contract_id, amount_stroops, rate_lock_duration_seconds, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     RETURNING id, invoice_hash, merchant_wallet, asset_contract_id, payout_asset_contract_id,
       amount_stroops, rate_lock_duration_seconds, expires_at, status, created_at`,
    [input.partnerId, tokenHash(publicToken), invoiceHash, input.merchantWallet, input.assetContractId,
      input.payoutAssetContractId, String(input.amountStroops), input.durationSeconds, input.expiresAt],
  );
  return { invoice: result.rows[0], publicToken };
}

export async function getPublicPaymentInvoice(publicToken) {
  if (!isDatabaseConfigured()) return null;
  const result = await query(
    `SELECT id, partner_id, invoice_hash, merchant_wallet, asset_contract_id, payout_asset_contract_id,
       amount_stroops, rate_lock_duration_seconds, expires_at, status
     FROM payment_invoices
     WHERE public_token_hash = $1 AND status NOT IN ('cancelled', 'expired')`,
    [tokenHash(publicToken)],
  );
  const invoice = result.rows[0] || null;
  if (!invoice) return null;
  if (new Date(invoice.expires_at).getTime() <= Date.now()) {
    await query(`UPDATE payment_invoices SET status='expired', updated_at=now() WHERE id=$1`, [invoice.id]);
    return null;
  }
  return invoice;
}

export async function markPaymentInvoice(input) {
  if (!isDatabaseConfigured()) return null;
  const allowed = new Set(['opened', 'drafted', 'submitted', 'protected', 'settled', 'payout_paid', 'cancelled']);
  if (!allowed.has(input.status)) return null;
  const result = await query(
    `UPDATE payment_invoices SET status=$2, payment_lock_id=COALESCE($3,payment_lock_id),
       customer_wallet_ref=COALESCE($4,customer_wallet_ref), updated_at=now()
     WHERE id=$1
     RETURNING id, invoice_hash, status, payment_lock_id, expires_at`,
    [input.invoiceId, input.status, input.paymentLockId || null, input.customerWalletRef || null],
  );
  return result.rows[0] || null;
}

export async function queueNotification(input) {
  if (!isDatabaseConfigured() || !input.walletRef) return null;
  const result = await query(
    `INSERT INTO notification_outbox (wallet_ref,event_type,payload,channel,status)
     VALUES ($1,$2,$3,'in_app','queued') RETURNING id,event_type,created_at`,
    [input.walletRef, input.eventType, input.payload || {}],
  );
  return result.rows[0];
}

export async function listNotifications(walletRef, limit = 30) {
  if (!isDatabaseConfigured()) return [];
  const result = await query(
    `SELECT id,event_type,payload,status,created_at,delivered_at FROM notification_outbox
     WHERE wallet_ref=$1 ORDER BY created_at DESC LIMIT $2`,
    [walletRef, Math.max(1, Math.min(100, Number(limit) || 30))],
  );
  return result.rows;
}
