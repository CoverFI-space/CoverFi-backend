import { env } from '../config/env.js';
import { closeDatabasePool, isDatabaseConfigured, query } from '../services/database.js';
import {
  getConfiguredContractIds,
  upsertContractEvent,
  upsertIndexerCursor,
} from '../services/history.js';

const pollIntervalMs = Number(process.env.INDEXER_POLL_INTERVAL_MS || 30_000);
const eventLimit = Number(process.env.INDEXER_EVENT_LIMIT || 200);
const loop = process.argv.includes('--loop');

function log(level, event, details = {}) {
  const payload = {
    level,
    event,
    at: new Date().toISOString(),
    ...details,
  };
  const line = JSON.stringify(payload);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

async function rpcRequest(method, params) {
  const response = await fetch(env.contracts.rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: Date.now(),
      method,
      params,
    }),
  });
  const body = await response.json().catch(() => null);
  if (!response.ok || body?.error) {
    const message = body?.error?.message || `RPC ${method} failed with ${response.status}`;
    const error = new Error(message);
    error.payload = body;
    throw error;
  }
  return body.result;
}

async function getLatestLedger() {
  const result = await rpcRequest('getLatestLedger', {});
  return Number(result?.sequence || result?.latestLedger || result?.ledger || 0);
}

async function getCursor(contractId) {
  const result = await query(
    `SELECT last_ledger, last_paging_token
     FROM indexer_cursors
     WHERE id = $1`,
    [`contract:${contractId}`],
  );
  return result.rows[0] || null;
}

function topicLabel(event) {
  const first = Array.isArray(event.topic) ? event.topic[0] : Array.isArray(event.topics) ? event.topics[0] : null;
  if (!first) return 'contract.event';
  if (typeof first === 'string') return first;
  if (first.sym) return first.sym;
  if (first.symbol) return first.symbol;
  if (first._value) return String(first._value);
  return 'contract.event';
}

function extractWalletRef() {
  // Keep the first production indexer privacy-safe. Wallet-specific linking should
  // be added through typed contract event schemas rather than raw address scraping.
  return null;
}

function normalizeRpcEvent(event, contractId) {
  const ledger = Number(event.ledger || event.ledgerNumber || event.ledgerSequence || 0);
  const transactionHash = String(event.txHash || event.transactionHash || event.id || '').replace(/^0x/, '');
  const occurredAt = event.timestamp
    ? new Date(Number(event.timestamp) * 1000).toISOString()
    : new Date().toISOString();

  return {
    contractId: event.contractId || event.contract_id || contractId,
    ledger,
    transactionHash: transactionHash || `${contractId}:${ledger}:${topicLabel(event)}`,
    eventType: topicLabel(event),
    occurredAt,
    walletRef: extractWalletRef(event),
    payload: {
      topic: event.topic || event.topics || [],
      value: event.value || event.data || null,
      raw: event,
    },
  };
}

async function indexContract(contract) {
  const latestLedger = await getLatestLedger();
  const cursor = await getCursor(contract.contractId);
  const startLedger = Math.max(1, Number(cursor?.last_ledger || 0) + 1);

  if (latestLedger && startLedger > latestLedger) {
    await upsertIndexerCursor({
      id: `contract:${contract.contractId}`,
      contractId: contract.contractId,
      lastLedger: latestLedger,
      lastPagingToken: cursor?.last_paging_token || '',
    });
    return { contract: contract.key, indexed: 0, latestLedger };
  }

  const result = await rpcRequest('getEvents', {
    startLedger,
    filters: [
      {
        type: 'contract',
        contractIds: [contract.contractId],
      },
    ],
    pagination: {
      limit: eventLimit,
      cursor: cursor?.last_paging_token || undefined,
    },
  });

  const events = Array.isArray(result?.events) ? result.events : [];
  let highestLedger = startLedger - 1;

  for (const event of events) {
    const normalized = normalizeRpcEvent(event, contract.contractId);
    if (normalized.ledger > highestLedger) highestLedger = normalized.ledger;
    await upsertContractEvent(normalized);
  }

  await upsertIndexerCursor({
    id: `contract:${contract.contractId}`,
    contractId: contract.contractId,
    lastLedger: Math.max(highestLedger, startLedger - 1),
    lastPagingToken: result?.cursor || result?.latestLedger || '',
  });

  return {
    contract: contract.key,
    indexed: events.length,
    startLedger,
    latestLedger,
  };
}

async function runOnce() {
  if (!isDatabaseConfigured()) {
    log('warn', 'indexer_skipped', { reason: 'DATABASE_URL is not configured' });
    return;
  }
  if (!env.contracts.rpcUrl) {
    log('warn', 'indexer_skipped', { reason: 'STELLAR_RPC_URL is not configured' });
    return;
  }

  const contracts = getConfiguredContractIds();
  const results = [];
  for (const contract of contracts) {
    try {
      results.push(await indexContract(contract));
    } catch (error) {
      log('error', 'indexer_contract_failed', {
        contract: contract.key,
        contractId: contract.contractId,
        message: error.message,
      });
    }
  }
  log('info', 'indexer_cycle_complete', { results });
}

try {
  if (loop) {
    log('info', 'indexer_worker_started', { pollIntervalMs });
    for (;;) {
      await runOnce();
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }
  } else {
    await runOnce();
  }
} finally {
  if (!loop) {
    await closeDatabasePool();
  }
}
