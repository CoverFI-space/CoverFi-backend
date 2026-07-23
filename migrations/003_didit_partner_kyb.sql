ALTER TABLE partners
  ADD COLUMN IF NOT EXISTS kyb_status text NOT NULL DEFAULT 'not_started',
  ADD COLUMN IF NOT EXISTS kyb_provider text,
  ADD COLUMN IF NOT EXISTS kyb_session_id text,
  ADD COLUMN IF NOT EXISTS kyb_verified_at timestamptz,
  ADD COLUMN IF NOT EXISTS kyb_decision jsonb,
  ADD COLUMN IF NOT EXISTS kyb_updated_at timestamptz;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'partners_kyb_status_check'
  ) THEN
    ALTER TABLE partners
      ADD CONSTRAINT partners_kyb_status_check
      CHECK (kyb_status IN (
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
      ));
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS partner_kyb_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  partner_id uuid NOT NULL REFERENCES partners(id) ON DELETE CASCADE,
  provider text NOT NULL DEFAULT 'didit',
  provider_session_id text NOT NULL UNIQUE,
  provider_business_session_id text,
  vendor_data text NOT NULL,
  status text NOT NULL DEFAULT 'Not Started',
  normalized_status text NOT NULL DEFAULT 'not_started',
  verification_url text,
  workflow_id text NOT NULL,
  callback_url text,
  decision jsonb,
  last_webhook_event_id text,
  created_by_wallet_ref text,
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

CREATE INDEX IF NOT EXISTS partner_kyb_sessions_partner_created_idx
  ON partner_kyb_sessions (partner_id, created_at DESC);

CREATE INDEX IF NOT EXISTS partner_kyb_sessions_vendor_data_idx
  ON partner_kyb_sessions (vendor_data);

CREATE TABLE IF NOT EXISTS didit_webhook_events (
  event_id text PRIMARY KEY,
  provider_session_id text,
  partner_id uuid REFERENCES partners(id) ON DELETE SET NULL,
  webhook_type text,
  status text,
  payload jsonb NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS didit_webhook_events_partner_received_idx
  ON didit_webhook_events (partner_id, received_at DESC);
