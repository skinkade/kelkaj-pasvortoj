use uuid::Uuid;

#[derive(sqlx::FromRow)]
pub struct Invite {
    pub id: Uuid,
    pub acceptance_token: String,
    pub account_id: String,
    pub email_address: String,
}

#[derive(sqlx::FromRow)]
pub struct User {
    id: Uuid,
    account_id: String,
    email_address: String,
    email_lower: String,
    auk_params: String,
    srp_verifier: String,
    srp_params: String,
    public_key: String,
    enc_priv_key: String
}

#[derive(sqlx::FromRow)]
pub struct UserVault {
    id: Uuid,
    enc_overview: String,
    enc_details: String
}

#[derive(sqlx::FromRow)]
pub struct UserVaultAccess {
    id: Uuid,
    user_id: Uuid,
    user_vault_id: Uuid,
    enc_vault_key: String,
    owner_flag: bool
}

#[derive(sqlx::FromRow)]
pub struct UserVaultItem {
    id: Uuid,
    user_vault_id: Uuid,
    enc_overview: String,
    enc_details: String
}

#[derive(sqlx::FromRow)]
pub struct SrpConfirmation {
    pub id: Uuid,
    pub user_id: Uuid,
    pub shared_secret: Vec<u8>,
    pub expiration: chrono::DateTime<chrono::Utc>
}

#[derive(sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub shared_secret: Vec<u8>,
    pub expiration: chrono::DateTime<chrono::Utc>
}