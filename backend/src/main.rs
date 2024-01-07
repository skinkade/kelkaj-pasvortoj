use anyhow::{Context, Ok};
use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    response::Response,
    routing::{get, post},
    Extension, Json, Router,
};
use base64::{engine::general_purpose, Engine};
use num_bigint::BigUint;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use shared::{
    crypto::{crypt_rand_uniform, generate_server_srp_exchange_values},
    flows::LoginHandshakeStartResponse,
    primitives::{AutoZeroedByteArray, SrpVerifier},
};
use sqlx::{postgres::PgPoolOptions, PgPool, Pool, Postgres};

use dotenvy::dotenv;
use std::env;
use tracing_subscriber::filter::LevelFilter;
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::{info_span, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
pub mod models;

// async fn run_migrations(pool: &SqlitePool) {
//     sqlx::query(
//         "
//         CREATE TABLE invites (
//             id TEXT PRIMARY KEY,
//             acceptance_token TEXT NOT NULL,
//             account_id TEXT NOT NULL,
//             email TEXT NOT NULL
//         );
//     ",
//     )
//     .execute(pool)
//     .await
//     .unwrap();

//     sqlx::query(
//         "
//         CREATE TABLE users (
//             id TEXT PRIMARY KEY,
//             account_id TEXT NOT NULL,
//             email TEXT NOT NULL,
//             email_lower TEXT NOT NULL,
//             public_key TEXT,
//             srp_verifier TEXT
//         );
//     ",
//     )
//     .execute(pool)
//     .await
//     .unwrap();
// }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    // initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                "example_tracing_aka_logging=debug,tower_http=debug,axum::rejection=trace".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = PgPoolOptions::new()
        .connect(&db_url)
        .await
        .context("could not connect to database")?;

    sqlx::migrate!()
        .run(&db_pool)
        .await
        .context("could not run migrations")?;

    // build our application with a route
    let app = Router::new()
        // // `GET /` goes to `root`
        // .route("/", get(root))
        // // `POST /users` goes to `create_user`
        // .route("/users", post(create_user))
        .route("/dummy", get(api::registration::dummy))
        .route("/invites/create", post(api::registration::create_invite))
        .route("/invites/accept", post(api::registration::accept_invite))
        .route("/login/begin", post(api::login::begin_login))
        .route("/login/confirm", post(api::login::confirm_login))
        // .route("/login", post(begin_login))
        .layer(Extension(db_pool))
        .layer(TraceLayer::new_for_http());

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await?;
    Ok(())
}

// async fn create_invite(
//     Extension(pool): Extension<PgPool>,
//     Json(payload): Json<shared::flows::RegistrationInitiationRequest>,
// ) -> StatusCode {
//     let invitation_id = uuid::Uuid::now_v7();
//     let mut acceptance_token = [0u8; 16];
//     OsRng.fill_bytes(&mut acceptance_token);
//     let acceptance_token = hex::encode(&acceptance_token);

//     let key_mask: Vec<char> = "23456789ABCDEFGHJKLMNPQRSTVWXYZ".chars().collect();
//     let key_mask_len: u32 = key_mask.len() as u32;
//     let account_id: String = (0..6)
//         .map(|_| key_mask[crypt_rand_uniform(key_mask_len) as usize])
//         .collect();

//     sqlx::query(
//         "
//         INSERT INTO invites
//         (id, acceptance_token, account_id, email)
//         VALUES
//         (?, ?, ?, ?)
//     ",
//     )
//     .bind(invitation_id.to_string())
//     .bind(acceptance_token.clone())
//     .bind(account_id.clone())
//     .bind(payload.email)
//     .execute(&pool)
//     .await
//     .expect("Invitation insert failed");

//     println!("Invitation ID:\t\t{}", invitation_id);
//     println!("Acceptance token:\t{}", acceptance_token);
//     println!("Account ID:\t\t{}", account_id);

//     StatusCode::CREATED
// }

// #[derive(sqlx::FromRow)]
// struct Invite {
//     id: String,
//     acceptance_token: String,
//     account_id: String,
//     email: String,
// }

// async fn accept_invite(
//     Extension(pool): Extension<PgPool>,
//     Json(payload): Json<shared::flows::RegistrationCompletionRequest>,
// ) -> StatusCode {
//     println!("{:?}", payload);
//     let invite = sqlx::query_as::<_, Invite>(
//         "
//         SELECT *
//         FROM invites
//         WHERE id = ?
//     ",
//     )
//     .bind(payload.invite_id)
//     .fetch_one(&pool)
//     .await
//     .unwrap();

//     assert!(invite.acceptance_token == payload.acceptance_token);

//     let user_id = uuid::Uuid::now_v7();
//     sqlx::query(
//         "
//         INSERT INTO users
//         (id, account_id, email, email_lower, public_key, srp_verifier)
//         VALUES
//         (?, ?, ?, ?, ?, ?)
//     ",
//     )
//     .bind(user_id.to_string())
//     .bind(invite.account_id)
//     .bind(invite.email.clone())
//     .bind(invite.email.to_lowercase())
//     .bind(payload.public_key)
//     .bind(payload.srp_verifier)
//     .execute(&pool)
//     .await
//     .unwrap();

//     StatusCode::OK
// }

// async fn begin_login(
//     Extension(pool): Extension<PgPool>,
//     Json(payload): Json<shared::flows::LoginHandshakeStart>,
// ) -> Json<LoginHandshakeResponse> {
//     let v: String = sqlx::query_scalar(
//         "
//         SELECT srp_verifier
//         FROM users
//         WHERE email = ?
//             AND account_id = ?
//     ",
//     )
//     .bind(payload.email)
//     .bind(payload.account_id)
//     .fetch_one(&pool)
//     .await
//     .unwrap();

//     let v = SrpVerifier(AutoZeroedByteArray::new(
//         general_purpose::STANDARD.decode(&v).unwrap(),
//     ));
//     let a_pub = general_purpose::STANDARD.decode(payload.a_pub).unwrap();

//     let srp_values = generate_server_srp_exchange_values(v, a_pub);

//     println!(
//         "Shared secret: {:?}",
//         shared::crypto::hashing::sha256(srp_values.shared_secret.as_slice())
//     );

//     Json(LoginHandshakeResponse {
//         b_pub: general_purpose::STANDARD.encode(srp_values.b_pub),
//     })
// }
