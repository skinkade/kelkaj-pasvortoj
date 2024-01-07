CREATE TABLE invites (
    id UUID PRIMARY KEY,
    acceptance_token TEXT NOT NULL,
    account_id CHAR(6) NOT NULL,
    email_address TEXT NOT NULL
);
