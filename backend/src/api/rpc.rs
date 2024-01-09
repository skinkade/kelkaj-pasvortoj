use anyhow::Error;
use axum::{
    body::Body,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::json;
use shared::{
    crypto::{
        aes256_gcm_decrypt, aes256_gcm_encrypt, crypt_rand_uniform,
        generate_server_srp_exchange_values,
    },
    flows::LoginHandshakeStartResponse,
    primitives::{AutoZeroedByteArray, SrpVerifier, Aes256GcmEncryptedData},
    rpc::{
        CreateVaultEntryPayload, CreateVaultEntryResponse, EncryptedRpcPayload, RpcPayload,
        RpcResponse,
    }, utils::b64_url_decode,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Pool, Postgres};
use uuid::Uuid;

use crate::models;

async fn create_vault_entry(payload: CreateVaultEntryPayload, pool: &Pool<Postgres>) -> String {
    // pretend we have authz
    let id = Uuid::now_v7();
    sqlx::query(
        "
        INSERT INTO user_vaults_items
        (id, user_vault_id, enc_overview, enc_details)
        VALUES
        ($1, $2, $3, $4)
    ",
    )
    .bind(id)
    .bind(payload.vault_id)
    .bind(json!(payload.enc_overview))
    .bind(json!(payload.enc_details))
    .execute(pool)
    .await
    .unwrap();

    json!(CreateVaultEntryResponse { id }).to_string()
}

async fn get_default_vault(session: &models::Session, pool: &Pool<Postgres>) -> String {
    let vault: models::UserVaultQueryResult = sqlx::query_as("
        SELECT user_vaults.*, uva.enc_vault_key
        FROM user_vaults_access uva
        JOIN user_vaults
            ON uva.user_vault_id = user_vaults.id
        WHERE uva.user_id = $1
            AND uva.owner_flag = TRUE
        LIMIT 1
    ")
    .bind(session.user_id)
    .fetch_one(pool)
    .await
    .unwrap();

    let items: Vec<models::UserVaultItem> = sqlx::query_as("
        SELECT *
        FROM user_vaults_items
        WHERE user_vault_id = $1
    ")
    .bind(vault.id)
    .fetch_all(pool)
    .await
    .unwrap();

    json!({
        "id": vault.id,
        "enc_overview": vault.enc_overview,
        "enc_details": vault.enc_details,
        "enc_vault_key": vault.enc_vault_key,
        "items": items
    }).to_string()
}

async fn rpc_dispatch(
    payload: &RpcPayload,
    pool: &Pool<Postgres>,
    session: &models::Session,
) -> Option<EncryptedRpcPayload> {
    let result: Option<String> = match &payload.command[..] {
        "get-default-vault/v1" => Some(get_default_vault(&session, &pool).await),
        "create-vault-entry/v1" => Some(create_vault_entry(
            serde_json::from_str(&payload.parameters).unwrap(),
            &pool,
        ).await),
        _ => panic!("Unknown RPC command: {}", payload.command),
    };

    match result {
        None => None,
        Some(p) => Some(EncryptedRpcPayload {
            payload: aes256_gcm_encrypt(p.as_bytes(), &session.shared_secret, &[]).to_b64(),
        }),
    }
}

pub async fn process_command(
    headers: HeaderMap,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<EncryptedRpcPayload>,
) -> (StatusCode, Json<Option<EncryptedRpcPayload>>) {
    let session_id = match headers.get("session") {
        None => return (StatusCode::FORBIDDEN, Json(None)),
        Some(id) => id.to_str().unwrap().to_owned(),
    };

    let session_id = Uuid::parse_str(&session_id).unwrap();

    let session: Option<models::Session> = sqlx::query_as(
        "
        SELECT *
        FROM sessions
        WHERE id = $1
    ",
    )
    .bind(session_id)
    .fetch_optional(&pool)
    .await
    .unwrap();

    let session = match session {
        None => return (StatusCode::FORBIDDEN, Json(None)),
        Some(s) => s,
    };

    if session.expiration <= chrono::Utc::now() {
        return (StatusCode::FORBIDDEN, Json(None));
    }

    let payload = Aes256GcmEncryptedData::from_b64(payload.payload).unwrap();
    let decrypted = aes256_gcm_decrypt(payload, &session.shared_secret, None);

    let decrypted = match decrypted {
        Err(_) => return (StatusCode::FORBIDDEN, Json(None)),
        Ok(d) => d,
    };

    let json_payload: RpcPayload = serde_json::from_slice(&decrypted).unwrap();

    let result = rpc_dispatch(&json_payload, &pool, &session).await;

    (StatusCode::OK, Json(result))
}
