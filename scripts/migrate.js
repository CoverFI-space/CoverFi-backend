import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { closeDatabasePool, query } from '../services/database.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const migrationsDir = path.resolve(__dirname, '..', 'migrations');

const files = (await fs.readdir(migrationsDir))
  .filter((file) => file.endsWith('.sql'))
  .sort();

try {
  await query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  for (const file of files) {
    const existing = await query(
      'SELECT filename FROM schema_migrations WHERE filename = $1',
      [file],
    );
    if (existing.rows.length) {
      console.log(`skipped ${file}`);
      continue;
    }

    const sql = await fs.readFile(path.join(migrationsDir, file), 'utf8');
    await query('BEGIN');
    try {
      await query(sql);
      await query(
        'INSERT INTO schema_migrations (filename) VALUES ($1)',
        [file],
      );
      await query('COMMIT');
    } catch (error) {
      await query('ROLLBACK');
      throw error;
    }
    console.log(`applied ${file}`);
  }
} finally {
  await closeDatabasePool();
}
