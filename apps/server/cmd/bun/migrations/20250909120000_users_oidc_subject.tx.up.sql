-- OIDC subject binding for the admin account: "{issuer}|{sub}"
ALTER TABLE users ADD COLUMN oidc_subject VARCHAR(512) NULL;

-- NULLs are excluded from unique indexes on every supported dialect, so this
-- enforces "one OIDC subject, one account" without blocking password-only users.
CREATE UNIQUE INDEX idx_users_oidc_subject ON users(oidc_subject);
