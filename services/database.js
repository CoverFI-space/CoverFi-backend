import { Pool } from 'pg';
import { env } from '../config/env.js';

let pool;

export function isDatabaseConfigured() {
  return Boolean(env.database.url);
}

export function getDatabasePool() {
  if (!isDatabaseConfigured()) {
    const error = new Error('DATABASE_URL is not configured.');
    error.statusCode = 503;
    throw error;
  }

  if (!pool) {
    pool = new Pool({
      connectionString: env.database.url,
      // Never silently accept an untrusted database certificate. Configure the
      // provider CA chain when a private CA is used.
      ssl: env.database.ssl ? { rejectUnauthorized: true } : false,
      max: 5,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
    });
  }

  return pool;
}

export async function query(text, params = []) {
  return getDatabasePool().query(text, params);
}

export async function closeDatabasePool() {
  if (!pool) return;
  await pool.end();
  pool = null;
}
