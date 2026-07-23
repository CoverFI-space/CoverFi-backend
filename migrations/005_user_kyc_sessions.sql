CREATE TABLE IF NOT EXISTS user_kyc_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  wallet_ref text NOT NULL,
  provider text NOT NULL DEFAULT 'didit',
  provider_session_id text NOT NULL UNIQUE,
  vendor_data text NOT NULL,
  status text NOT NULL DEFAULT 'Not Started',
  normalized_status text NOT NULL DEFAULT 'not_started',
  verification_url text,
  workflow_id text NOT NULL,
  callback_url text,
  payout_usd numeric(20, 6),
  decision jsonb,
  last_webhook_event_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (normalized_status IN (
    'not_started',
    'in_progress',
    'awaiting_user',
    'in_review',
    'verified',
    'declined',
    'resubmitted',
    'abandoned',
    'expired',
    'unknown'
  ))
);

CREATE INDEX IF NOT EXISTS user_kyc_sessions_wallet_created_idx
  ON user_kyc_sessions (wallet_ref, created_at DESC);

CREATE INDEX IF NOT EXISTS user_kyc_sessions_vendor_data_idx
  ON user_kyc_sessions (vendor_data);

ALTER TABLE didit_webhook_events
  ADD COLUMN IF NOT EXISTS user_wallet_ref text;

CREATE INDEX IF NOT EXISTS didit_webhook_events_user_received_idx
  ON didit_webhook_events (user_wallet_ref, received_at DESC);
