ALTER TABLE partner_webhooks
  ADD COLUMN IF NOT EXISTS secret_ciphertext text;

ALTER TABLE webhook_deliveries
  ADD COLUMN IF NOT EXISTS event_type text,
  ADD COLUMN IF NOT EXISTS payload jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS webhook_deliveries_ready_idx
  ON webhook_deliveries (status, next_attempt_at, created_at);
