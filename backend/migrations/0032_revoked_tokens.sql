-- Revoked JWT tokens (logout). `jti` is the JWT "jti" claim (a UUID).
-- Rows are pruned when their `expires_at` passes — the token would be
-- rejected by signature expiry anyway, so keeping them is wasteful.
CREATE TABLE revoked_tokens (
    jti         UUID        PRIMARY KEY,
    user_id     UUID        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_revoked_tokens_expires_at ON revoked_tokens (expires_at);
