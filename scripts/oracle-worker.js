import { env } from '../config/env.js';
import { refreshOracle } from './refresh-oracle.js';

const DEFAULT_INTERVAL_MS = 5 * 60 * 1000;
const intervalMs = Math.max(
  60_000,
  Number(process.env.ORACLE_REFRESH_INTERVAL_MS || DEFAULT_INTERVAL_MS),
);

async function tick() {
  const startedAt = new Date().toISOString();
  try {
    await refreshOracle();
    console.log(JSON.stringify({
      ok: true,
      worker: 'oracle-refresh',
      network: env.contracts.network,
      startedAt,
      nextRunMs: intervalMs,
    }));
  } catch (error) {
    console.error(JSON.stringify({
      ok: false,
      worker: 'oracle-refresh',
      network: env.contracts.network,
      startedAt,
      message: error instanceof Error ? error.message : String(error),
    }));
  }
}

await tick();
setInterval(() => {
  void tick();
}, intervalMs);
