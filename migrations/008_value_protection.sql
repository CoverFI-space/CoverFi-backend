CREATE TABLE IF NOT EXISTS payment_invoices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  partner_id uuid NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
  public_token_hash text NOT NULL UNIQUE,
  invoice_hash text NOT NULL UNIQUE,
  merchant_wallet text NOT NULL,
  asset_contract_id text NOT NULL,
  payout_asset_contract_id text NOT NULL,
  amount_stroops numeric(38, 0) NOT NULL,
  rate_lock_duration_seconds integer NOT NULL,
  expires_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'issued',
  payment_lock_id text,
  customer_wallet_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (rate_lock_duration_seconds IN (900, 3600, 86400)),
  CHECK (status IN ('issued', 'opened', 'drafted', 'submitted', 'protected', 'settled', 'payout_paid', 'expired', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS payment_invoices_partner_created_idx
  ON payment_invoices (partner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS payment_invoices_status_expiry_idx
  ON payment_invoices (status, expires_at);

CREATE TABLE IF NOT EXISTS notification_preferences (
  wallet_ref text PRIMARY KEY,
  email_opt_in boolean NOT NULL DEFAULT false,
  position_events boolean NOT NULL DEFAULT true,
  payment_lock_events boolean NOT NULL DEFAULT true,
  floor_shield_events boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notification_outbox (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  wallet_ref text NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  channel text NOT NULL DEFAULT 'in_app',
  status text NOT NULL DEFAULT 'queued',
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  CHECK (channel IN ('in_app', 'email')),
  CHECK (status IN ('queued', 'delivered', 'suppressed', 'failed'))
);

CREATE INDEX IF NOT EXISTS notification_outbox_wallet_created_idx
  ON notification_outbox (wallet_ref, created_at DESC);
