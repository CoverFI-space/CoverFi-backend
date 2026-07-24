CREATE TABLE IF NOT EXISTS email_passkeys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_hash text NOT NULL,
  credential_id text NOT NULL UNIQUE,
  public_key bytea NOT NULL,
  counter bigint NOT NULL DEFAULT 0,
  transports jsonb NOT NULL DEFAULT '[]'::jsonb,
  device_type text NOT NULL DEFAULT 'singleDevice',
  backed_up boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  CONSTRAINT email_passkeys_counter_check CHECK (counter >= 0)
);

CREATE INDEX IF NOT EXISTS email_passkeys_email_hash_idx
  ON email_passkeys (email_hash, created_at DESC);

CREATE TABLE IF NOT EXISTS email_passkey_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_hash text NOT NULL,
  challenge text NOT NULL,
  purpose text NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT email_passkey_challenges_purpose_check
    CHECK (purpose IN ('registration', 'authentication'))
);

CREATE INDEX IF NOT EXISTS email_passkey_challenges_lookup_idx
  ON email_passkey_challenges (id, email_hash, purpose, expires_at)
  WHERE used_at IS NULL;
