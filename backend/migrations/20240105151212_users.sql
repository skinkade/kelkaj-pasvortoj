CREATE TABLE users (
    id UUID PRIMARY KEY,
    account_id CHAR(6) NOT NULL,
    email_address VARCHAR(255) NOT NULL,
    email_lower VARCHAR(255) NOT NULL,
    auk_params JSONB NOT NULL,
    srp_verifier TEXT NOT NULL,
    srp_params JSONB NOT NULL,
    public_key TEXT NOT NULL,
    enc_priv_key JSONB NOT NULL,
    CONSTRAINT users_lower_email_key
        UNIQUE (email_lower, account_id)
);
