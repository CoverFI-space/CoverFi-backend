ALTER TABLE partners
  ADD COLUMN IF NOT EXISTS plan text NOT NULL DEFAULT 'sandbox',
  ADD COLUMN IF NOT EXISTS credits_remaining integer NOT NULL DEFAULT 10000;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'partners_plan_check'
  ) THEN
    ALTER TABLE partners
      ADD CONSTRAINT partners_plan_check
      CHECK (plan IN ('sandbox', 'starter', 'growth', 'enterprise'));
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS partner_applications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  partner_id uuid NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
  name text NOT NULL,
  slug text NOT NULL,
  description text,
  website_url text,
  logo_url text,
  environment text NOT NULL DEFAULT 'development',
  allowed_origins text[] NOT NULL DEFAULT ARRAY[]::text[],
  allowed_ip_addresses text[] NOT NULL DEFAULT ARRAY[]::text[],
  webhook_url text,
  webhook_secret_id uuid,
  status text NOT NULL DEFAULT 'pending_review',
  publishable_key_prefix text,
  publishable_key_last4 text,
  publishable_key_hash text UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (partner_id, slug),
  CHECK (environment IN ('development', 'staging', 'production')),
  CHECK (status IN ('pending_review', 'active', 'suspended', 'rejected', 'deleted'))
);

ALTER TABLE partner_api_keys
  ADD COLUMN IF NOT EXISTS application_id uuid REFERENCES partner_applications(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'test',
  ADD COLUMN IF NOT EXISTS key_last4 text,
  ADD COLUMN IF NOT EXISTS allowed_origins text[] NOT NULL DEFAULT ARRAY[]::text[],
  ADD COLUMN IF NOT EXISTS allowed_ip_addresses text[] NOT NULL DEFAULT ARRAY[]::text[],
  ADD COLUMN IF NOT EXISTS expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS revoked_at timestamptz,
  ADD COLUMN IF NOT EXISTS last_used_ip_ref text,
  ADD COLUMN IF NOT EXISTS request_count bigint NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS partner_api_keys_application_idx
  ON partner_api_keys (application_id, active);

CREATE TABLE IF NOT EXISTS partner_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id text NOT NULL UNIQUE,
  partner_id uuid REFERENCES partners(id) ON DELETE SET NULL,
  application_id uuid REFERENCES partner_applications(id) ON DELETE SET NULL,
  api_key_id uuid REFERENCES partner_api_keys(id) ON DELETE SET NULL,
  method text NOT NULL,
  path text NOT NULL,
  status_code integer,
  error_code text,
  latency_ms integer,
  idempotency_key text,
  request_body jsonb,
  response_body jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS partner_requests_partner_created_idx
  ON partner_requests (partner_id, created_at DESC);

CREATE TABLE IF NOT EXISTS partner_idempotency_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  partner_id uuid NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
  application_id uuid REFERENCES partner_applications(id) ON DELETE CASCADE,
  idempotency_key text NOT NULL,
  method text NOT NULL,
  path text NOT NULL,
  response_status integer,
  response_body jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT now() + interval '24 hours',
  UNIQUE (partner_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS partner_quotes (
  id text PRIMARY KEY DEFAULT ('quote_' || encode(gen_random_bytes(16), 'hex')),
  partner_id uuid NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
  application_id uuid REFERENCES partner_applications(id) ON DELETE SET NULL,
  asset text NOT NULL,
  amount text NOT NULL,
  duration_days integer NOT NULL,
  protection_percentage integer NOT NULL,
  premium_amount text NOT NULL,
  maximum_payout text NOT NULL,
  quote_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS partner_quotes_partner_created_idx
  ON partner_quotes (partner_id, created_at DESC);

CREATE TABLE IF NOT EXISTS partner_positions (
  id text PRIMARY KEY DEFAULT ('pos_' || encode(gen_random_bytes(16), 'hex')),
  partner_id uuid NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
  application_id uuid REFERENCES partner_applications(id) ON DELETE SET NULL,
  quote_id text REFERENCES partner_quotes(id) ON DELETE SET NULL,
  wallet_ref text,
  status text NOT NULL,
  network text NOT NULL,
  transaction_xdr text,
  contract_position_id text,
  position_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (status IN (
    'quote_created',
    'awaiting_signature',
    'submitted',
    'active',
    'expired',
    'claimable',
    'claimed',
    'paid',
    'cancelled',
    'failed'
  ))
);

CREATE INDEX IF NOT EXISTS partner_positions_partner_created_idx
  ON partner_positions (partner_id, created_at DESC);

CREATE TABLE IF NOT EXISTS partner_sessions (
  id text PRIMARY KEY DEFAULT ('sess_' || encode(gen_random_bytes(16), 'hex')),
  partner_id uuid NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
  application_id uuid REFERENCES partner_applications(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  customer_reference text,
  wallet_ref text,
  scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
  revoked_at timestamptz,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
