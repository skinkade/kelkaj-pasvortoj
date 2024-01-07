use anyhow::Error;
use axum::{
    body::Body,
    extract::{Extension, State},
    http::StatusCode,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::json;
use shared::{
    crypto::{crypt_rand_uniform, generate_server_srp_exchange_values},
    flows::LoginHandshakeStartResponse,
    primitives::{AutoZeroedByteArray, SrpVerifier},
};
use sqlx::{postgres::PgPoolOptions, PgPool, Pool, Postgres};

use crate::models;

pub async fn dummy(Extension(pool): Extension<PgPool>) -> &'static str {
    "hello"
}

pub async fn create_invite(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<shared::flows::RegistrationInitiationRequest>,
) -> Result<StatusCode, ()> {
    println!("{}", 1);
    let invitation_id = uuid::Uuid::now_v7();
    let mut acceptance_token = [0u8; 16];
    OsRng.fill_bytes(&mut acceptance_token);
    let acceptance_token = hex::encode(&acceptance_token);

    let key_mask: Vec<char> = "23456789ABCDEFGHJKLMNPQRSTVWXYZ".chars().collect();
    let key_mask_len: u32 = key_mask.len() as u32;
    let account_id: String = (0..6)
        .map(|_| key_mask[crypt_rand_uniform(key_mask_len) as usize])
        .collect();

    sqlx::query(
        "
        INSERT INTO invites
        (id, acceptance_token, account_id, email_address)
        VALUES
        ($1, $2, $3, $4)
    ",
    )
    .bind(invitation_id)
    .bind(acceptance_token.clone())
    .bind(account_id.clone())
    .bind(payload.email)
    .execute(&pool)
    .await
    .expect("Invitation insert failed");

    println!("Invitation ID:\t\t{}", invitation_id);
    println!("Acceptance token:\t{}", acceptance_token);
    println!("Account ID:\t\t{}", account_id);

    Ok(StatusCode::CREATED)
}

pub async fn accept_invite(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<shared::flows::RegistrationCompletionRequest>,
) -> StatusCode {
    // println!("{:?}", payload);
    let invite = sqlx::query_as::<_, models::Invite>(
        "
        SELECT *
        FROM invites
        WHERE id = $1
    ",
    )
    .bind(payload.invite_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(invite.acceptance_token == payload.acceptance_token);

    let user_id = uuid::Uuid::now_v7();
    sqlx::query(
        "
        INSERT INTO users
        (id, account_id, email_address, email_lower,
         auk_params, srp_verifier, srp_params,
         public_key, enc_priv_key)
        VALUES
        ($1, $2, $3, $4,
         $5, $6, $7,
         $8, $9)
    ",
    )
    .bind(user_id)
    .bind(invite.account_id)
    .bind(invite.email_address.clone())
    .bind(invite.email_address.to_lowercase())
    .bind(json!(payload.auk_params))
    .bind(payload.srp_verifier)
    .bind(json!(payload.srp_params))
    .bind(payload.public_key)
    .bind(json!(payload.enc_priv_key))
    .execute(&pool)
    .await
    .unwrap();

    StatusCode::OK
}
