CREATE TABLE user_vaults (
    id UUID PRIMARY KEY,
    enc_overview JSONB NOT NULL,
    enc_details JSONB NOT NULL
);

CREATE TABLE user_vaults_access (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES users (id),
    user_vault_id UUID NOT NULL
        REFERENCES user_vaults (id),
    CONSTRAINT user_vaults_access_key
        UNIQUE (user_id, user_vault_id),
    enc_vault_key TEXT NOT NULL,
    owner_flag BOOLEAN NOT NULL
);

CREATE TABLE user_vaults_items (
    id UUID PRIMARY KEY,
    user_vault_id UUID NOT NULL
        REFERENCES user_vaults (id),
    enc_overview JSONB NOT NULL,
    enc_details JSONB NOT NULL
);

CREATE INDEX user_vaults_item_vault
ON user_vaults_items (user_vault_id);
