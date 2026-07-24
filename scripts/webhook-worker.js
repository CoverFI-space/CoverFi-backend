import crypto from 'node:crypto';
import { closeDatabasePool, isDatabaseConfigured, query } from '../services/database.js';
import { decryptWebhookSecret } from '../services/partners.js';

const loop = process.argv.includes('--loop');
const pollIntervalMs = Math.max(1_000, Number(process.env.WEBHOOK_POLL_INTERVAL_MS || 10_000));
const maxAttempts = Math.max(1, Number(process.env.WEBHOOK_MAX_ATTEMPTS || 10));

function base64url(value) { return Buffer.from(value).toString('base64url'); }
function signature(timestamp, payload, secret) { return crypto.createHmac('sha256', secret).update(`${timestamp}.${payload}`).digest('base64url'); }
function retryDelayMs(attempt) { return Math.min(60 * 60 * 1000, 1_000 * (2 ** Math.min(12, attempt))); }

async function deliver(row) {
  const secret = decryptWebhookSecret(row.secret_ciphertext);
  if (!secret) {
    await query(`UPDATE webhook_deliveries SET status='dead_letter', last_attempt_at=now(), response_body_preview='webhook secret unavailable' WHERE id=$1`, [row.id]);
    return;
  }
  const envelope = { id: row.delivery_id, type: row.event_type, createdAt: new Date().toISOString(), partnerId: row.partner_id, data: row.payload || {} };
  const payload = JSON.stringify(envelope); const timestamp = String(Math.floor(Date.now() / 1000));
  let response; let preview = '';
  try {
    response = await fetch(row.url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-coverfi-timestamp': timestamp, 'x-coverfi-signature': signature(timestamp, payload, secret), 'x-coverfi-delivery-id': row.delivery_id }, body: payload, signal: AbortSignal.timeout(10_000) });
    preview = (await response.text()).slice(0, 512);
  } catch (error) { preview = error instanceof Error ? error.message.slice(0, 512) : 'delivery failed'; }
  const attempt = Number(row.attempt_count || 0) + 1;
  if (response?.ok) {
    await query(`UPDATE webhook_deliveries SET status='delivered',attempt_count=$2,last_attempt_at=now(),response_status=$3,response_body_preview=$4 WHERE id=$1`, [row.id, attempt, response.status, preview]);
  } else {
    const status = attempt >= maxAttempts ? 'dead_letter' : 'retrying';
    const next = new Date(Date.now() + retryDelayMs(attempt)).toISOString();
    await query(`UPDATE webhook_deliveries SET status=$2,attempt_count=$3,last_attempt_at=now(),next_attempt_at=$4,response_status=$5,response_body_preview=$6 WHERE id=$1`, [row.id, status, attempt, next, response?.status || null, preview]);
  }
}

async function runOnce() {
  if (!isDatabaseConfigured()) return;
  const rows = await query(`SELECT d.id,d.delivery_id,d.event_type,d.payload,d.attempt_count,w.url,w.secret_ciphertext,w.partner_id FROM webhook_deliveries d JOIN partner_webhooks w ON w.id=d.webhook_id WHERE d.status IN ('pending','retrying') AND COALESCE(d.next_attempt_at,d.created_at)<=now() AND w.active=true ORDER BY d.created_at LIMIT 50`);
  for (const row of rows.rows) await deliver(row);
}

try { if (loop) { for (;;) { await runOnce(); await new Promise((resolve) => setTimeout(resolve, pollIntervalMs)); } } else await runOnce(); } finally { if (!loop) await closeDatabasePool(); }
