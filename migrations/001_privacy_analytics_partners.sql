CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS indexer_cursors (
  id text PRIMARY KEY,
  contract_id text NOT NULL,
  last_ledger bigint NOT NULL DEFAULT 0,
  last_paging_token text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS contract_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contract_id text NOT NULL,
  ledger bigint NOT NULL,
  transaction_hash text NOT NULL,
  event_type text NOT NULL,
  occurred_at timestamptz NOT NULL,
  wallet_ref text,
  partner_id uuid,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  inserted_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (contract_id, ledger, transaction_hash, event_type)
);

CREATE INDEX IF NOT EXISTS contract_events_type_day_idx
  ON contract_events (event_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS contract_events_partner_day_idx
  ON contract_events (partner_id, occurred_at DESC)
  WHERE partner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS contract_events_wallet_ref_idx
  ON contract_events (wallet_ref)
  WHERE wallet_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS daily_protocol_metrics (
  day date PRIMARY KEY,
  active_wallets integer NOT NULL DEFAULT 0,
  new_wallets integer NOT NULL DEFAULT 0,
  quotes integer NOT NULL DEFAULT 0,
  positions integer NOT NULL DEFAULT 0,
  protected_notional_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  premium_volume_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  protocol_revenue_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  safety_funding_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  automation_funding_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  underwriting_premium_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  settlements integer NOT NULL DEFAULT 0,
  claims integer NOT NULL DEFAULT 0,
  payouts_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  reserve_providers integer NOT NULL DEFAULT 0,
  reserve_nav_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  utilization_bps integer NOT NULL DEFAULT 0,
  usernames integer NOT NULL DEFAULT 0,
  receipts integer NOT NULL DEFAULT 0,
  cohort_suppressed boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS partners (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE,
  display_name text NOT NULL,
  onchain_partner_address text,
  website_url text,
  status text NOT NULL DEFAULT 'pending',
  created_by_wallet_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (status IN ('pending', 'enabled', 'suspended', 'revoked'))
);

CREATE TABLE IF NOT EXISTS partner_api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  partner_id uuid NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
  label text NOT NULL,
  key_prefix text NOT NULL,
  key_hash text NOT NULL UNIQUE,
  scopes text[] NOT NULL DEFAULT ARRAY['quote:read', 'tx:build', 'metrics:read'],
  rate_limit_per_minute integer NOT NULL DEFAULT 120,
  active boolean NOT NULL DEFAULT true,
  created_by_wallet_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE INDEX IF NOT EXISTS partner_api_keys_partner_idx
  ON partner_api_keys (partner_id, active);

CREATE TABLE IF NOT EXISTS partner_webhooks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  partner_id uuid NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
  url text NOT NULL,
  secret_hash text NOT NULL,
  event_types text[] NOT NULL DEFAULT ARRAY[
    'position.created',
    'position.awaiting_oracle',
    'position.settled',
    'payout.claimed',
    'principal.withdrawn',
    'reserve.utilization_changed',
    'oracle.stale',
    'oracle.recovered'
  ],
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id uuid NOT NULL REFERENCES partner_webhooks(id) ON DELETE CASCADE,
  event_id uuid REFERENCES contract_events(id) ON DELETE SET NULL,
  delivery_id text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'pending',
  attempt_count integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz,
  last_attempt_at timestamptz,
  response_status integer,
  response_body_preview text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (status IN ('pending', 'delivered', 'retrying', 'dead_letter'))
);

CREATE TABLE IF NOT EXISTS daily_partner_metrics (
  day date NOT NULL,
  partner_id uuid NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
  active_wallets integer NOT NULL DEFAULT 0,
  positions integer NOT NULL DEFAULT 0,
  protected_notional_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  premium_volume_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  payouts_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  cohort_suppressed boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (day, partner_id)
);

CREATE TABLE IF NOT EXISTS keeper_activity (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  day date NOT NULL,
  keeper_ref text NOT NULL,
  action_type text NOT NULL,
  reward_stroops numeric(38, 0) NOT NULL DEFAULT 0,
  transaction_hash text NOT NULL,
  occurred_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS oracle_health_samples (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sampled_at timestamptz NOT NULL DEFAULT now(),
  asset_contract_id text NOT NULL,
  price text,
  age_seconds integer,
  status text NOT NULL,
  disagreement_bps integer,
  source_count integer,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb
);
