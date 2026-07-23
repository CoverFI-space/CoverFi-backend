import crypto from 'node:crypto';
import { env } from '../config/env.js';
import { isDatabaseConfigured, query } from './database.js';

const walletAddressPattern = /^G[A-Z2-7]{55}$/;
const hashPattern = /^[a-fA-F0-9]{64}$/;

export function walletRef(walletAddress) {
  const clean = String(walletAddress || '').trim().toUpperCase();
  if (!walletAddressPattern.test(clean)) return '';
  return crypto
    .createHmac('sha256', env.server.privacyHmacSecret)
    .update(`wallet:${clean}`)
    .digest('hex');
}

export function getConfiguredContractIds() {
  return Object.entries({
    protectionEngine: env.contracts.protectionEngine,
    protectedBalanceVault: env.contracts.protectedBalanceVault,
    reserveVault: env.contracts.reserveVault,
    oracleAdapter: env.contracts.oracleAdapter,
    usernameRegistry: env.contracts.usernameRegistry,
    receiptRegistry: env.contracts.receiptRegistry,
    zkVerifier: env.contracts.zkVerifier,
  })
    .map(([key, contractId]) => ({ key, contractId: String(contractId || '').trim() }))
    .filter((item) => item.contractId);
}

function cleanLimit(value, fallback = 50, max = 200) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(Math.floor(parsed), max);
}

function serializeEvent(row) {
  const payload = row.payload || {};
  const safePayload = payload && typeof payload === 'object'
    ? Object.fromEntries(Object.entries(payload).filter(([key]) => key !== 'raw'))
    : {};
  return {
    id: row.id,
    contractId: row.contract_id,
    ledger: Number(row.ledger),
    transactionHash: row.transaction_hash,
    eventType: row.event_type,
    occurredAt: row.occurred_at,
    payload: safePayload,
  };
}

export async function listWalletEvents(walletAddress, options = {}) {
  if (!isDatabaseConfigured()) {
    return { events: [], source: 'database-disabled' };
  }

  const ref = walletRef(walletAddress);
  if (!ref) {
    const error = new Error('A valid Stellar public key is required.');
    error.statusCode = 400;
    throw error;
  }

  const result = await query(
    `SELECT id, contract_id, ledger, transaction_hash, event_type, occurred_at, payload
     FROM contract_events
     WHERE wallet_ref = $1
     ORDER BY occurred_at DESC, ledger DESC
     LIMIT $2`,
    [ref, cleanLimit(options.limit)],
  );
  return {
    events: result.rows.map(serializeEvent),
    source: 'contract_events',
  };
}

export async function listWalletActivity(walletAddress, options = {}) {
  const ref = walletRef(walletAddress);
  if (!ref) {
    const error = new Error('A valid Stellar public key is required.');
    error.statusCode = 400;
    throw error;
  }

  const eventsResult = isDatabaseConfigured()
    ? await listWalletEvents(walletAddress, options)
    : { events: [], source: 'database-disabled' };

  const localRecords = isDatabaseConfigured()
    ? await query(
      `SELECT 'receipt' AS kind, tx_hash AS transaction_hash, created_at AS occurred_at,
              jsonb_build_object(
                'status', status,
                'amount', amount,
                'fee', fee,
                'receiptHash', receipt_hash
              ) AS payload
       FROM receipts
       WHERE wallet_ref = $1
       UNION ALL
       SELECT 'payment' AS kind, tx_hash AS transaction_hash, created_at AS occurred_at,
              jsonb_build_object(
                'username', username,
                'amount', amount,
                'asset', asset,
                'status', status
              ) AS payload
       FROM payments
       WHERE wallet_ref = $1
       ORDER BY occurred_at DESC
       LIMIT $2`,
      [ref, cleanLimit(options.limit)],
    ).catch(() => ({ rows: [] }))
    : { rows: [] };

  return {
    walletRef: ref,
    source: eventsResult.source,
    events: eventsResult.events,
    records: localRecords.rows.map((row) => ({
      kind: row.kind,
      transactionHash: hashPattern.test(String(row.transaction_hash || '')) ? row.transaction_hash : null,
      occurredAt: row.occurred_at,
      payload: row.payload || {},
    })),
  };
}

export async function getIndexerStatus() {
  if (!isDatabaseConfigured()) {
    return {
      ok: false,
      databaseConfigured: false,
      cursors: [],
      eventCount24h: 0,
      lagSeconds: null,
    };
  }

  const cursorResult = await query(
    `SELECT id, contract_id, last_ledger, last_paging_token, updated_at
     FROM indexer_cursors
     ORDER BY id`,
  );
  const countResult = await query(
    `SELECT count(*)::int AS count
     FROM contract_events
     WHERE occurred_at >= now() - interval '24 hours'`,
  );
  const latestResult = await query(
    `SELECT max(occurred_at) AS latest_event_at
     FROM contract_events`,
  );
  const latest = latestResult.rows[0]?.latest_event_at
    ? new Date(latestResult.rows[0].latest_event_at).getTime()
    : null;

  return {
    ok: true,
    databaseConfigured: true,
    network: env.contracts.network,
    rpcConfigured: Boolean(env.contracts.rpcUrl),
    watchedContracts: getConfiguredContractIds().map((item) => item.key),
    cursors: cursorResult.rows.map((row) => ({
      id: row.id,
      contractId: row.contract_id,
      lastLedger: Number(row.last_ledger || 0),
      updatedAt: row.updated_at,
    })),
    eventCount24h: Number(countResult.rows[0]?.count || 0),
    latestEventAt: latestResult.rows[0]?.latest_event_at || null,
    lagSeconds: latest ? Math.max(0, Math.floor((Date.now() - latest) / 1000)) : null,
  };
}

export async function upsertContractEvent(event) {
  const result = await query(
    `INSERT INTO contract_events
       (contract_id, ledger, transaction_hash, event_type, occurred_at, wallet_ref, partner_id, payload)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (contract_id, ledger, transaction_hash, event_type)
     DO UPDATE SET payload = EXCLUDED.payload
     RETURNING id`,
    [
      event.contractId,
      event.ledger,
      event.transactionHash,
      event.eventType,
      event.occurredAt,
      event.walletRef || null,
      event.partnerId || null,
      event.payload || {},
    ],
  );
  return result.rows[0];
}

export async function upsertIndexerCursor(cursor) {
  await query(
    `INSERT INTO indexer_cursors (id, contract_id, last_ledger, last_paging_token, updated_at)
     VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (id)
     DO UPDATE SET
       contract_id = EXCLUDED.contract_id,
       last_ledger = GREATEST(indexer_cursors.last_ledger, EXCLUDED.last_ledger),
       last_paging_token = EXCLUDED.last_paging_token,
       updated_at = now()`,
    [
      cursor.id,
      cursor.contractId,
      cursor.lastLedger || 0,
      cursor.lastPagingToken || '',
    ],
  );
}
