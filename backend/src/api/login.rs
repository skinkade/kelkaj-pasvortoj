use std::ops::Add;

use axum::{
    body::Body,
    extract::{Extension, State},
    http::StatusCode,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use rand::{rngs::OsRng, RngCore};
use shared::{
    crypto::{crypt_rand_uniform, generate_server_srp_exchange_values, aes256_gcm_decrypt},
    flows::{LoginHandshakeStartResponse, LoginHandshakeConfirmationResponse},
    primitives::{AutoZeroedByteArray, SrpVerifier, Aes256GcmEncryptedData}, utils::{b64_url_decode, b64_url_encode},
};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres, PgPool};

use crate::models;

#[derive(sqlx::FromRow)]
struct LoginQueryResult {
    pub id: uuid::Uuid,
    pub srp_verifier: String,
}

pub async fn begin_login(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<shared::flows::LoginHandshakeStart>,
) -> Json<LoginHandshakeStartResponse> {
    let user: LoginQueryResult = sqlx::query_as(
        "
        SELECT id, srp_verifier
        FROM users
        WHERE email_lower = $1
            AND account_id = $2
    ",
    )
    .bind(payload.email.to_lowercase())
    .bind(payload.account_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let v = SrpVerifier(AutoZeroedByteArray::new(
        b64_url_decode(&user.srp_verifier).unwrap(),
    ));
    let a_pub = b64_url_decode(&payload.a_pub).unwrap();

    let srp_values = generate_server_srp_exchange_values(v, a_pub);

    println!(
        "Shared secret: {:?}",
        shared::crypto::hashing::sha256(srp_values.shared_secret.as_slice())
    );

    let handshake_id = uuid::Uuid::now_v7();
    let expiration = chrono::Utc::now() + chrono::Duration::seconds(60);
    let shared_secret = shared::crypto::hashing::sha256(&srp_values.shared_secret.as_slice());

    sqlx::query("
        INSERT INTO srp_confirmations
        (id, user_id, shared_secret, expiration)
        VALUES
        ($1, $2, $3, $4)
    ")
    .bind(handshake_id)
    .bind(user.id)
    .bind(shared_secret)
    .bind(expiration)
    .execute(&pool)
    .await
    .unwrap();

    Json(LoginHandshakeStartResponse {
        handshake_id,
        b_pub: b64_url_encode(&srp_values.b_pub),
    })
}

pub async fn confirm_login(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<shared::flows::LoginHandshakeConfirmation>,
) -> Json<LoginHandshakeConfirmationResponse> {
    let handshake: models::SrpConfirmation = sqlx::query_as("
        SELECT *
        FROM srp_confirmations
        WHERE id = $1
    ")
    .bind(payload.handshake_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(handshake.expiration > chrono::Utc::now());

    let confirmation = Aes256GcmEncryptedData::from_b64(payload.confirmation).unwrap();
    let decrypted = aes256_gcm_decrypt(confirmation, &handshake.shared_secret, None).unwrap();

    assert!(decrypted == handshake.id.as_bytes());

    let session = models::Session {
        id: uuid::Uuid::now_v7(),
        user_id: handshake.user_id,
        shared_secret: handshake.shared_secret,
        expiration: chrono::Utc::now() + chrono::Duration::hours(8)
    };

    sqlx::query("
        INSERT INTO sessions
        (id, user_id, shared_secret, expiration)
        VALUES
        ($1, $2, $3, $4)
    ")
    .bind(session.id)
    .bind(session.user_id)
    .bind(session.shared_secret)
    .bind(session.expiration)
    .execute(&pool)
    .await
    .unwrap();

    Json(LoginHandshakeConfirmationResponse {
        session_id: session.id
    })
}