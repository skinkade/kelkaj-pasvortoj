CREATE TABLE srp_confirmations (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES users (id),
    shared_secret BYTEA NOT NULL,
    expiration TIMESTAMPTZ NOT NULL
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES users (id),
    shared_secret BYTEA NOT NULL,
    expiration TIMESTAMPTZ NOT NULL
);
