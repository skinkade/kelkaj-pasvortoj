use base64::{engine::general_purpose, Engine};
use clap::{Args, Parser, Subcommand};
use pkcs1::EncodeRsaPublicKey;
use serde_json::json;
use shared::{
    crypto::{finalize_srp_exchange, generate_client_srp_exchange_value},
    flows::{
        generate_registration_info, LoginHandshakeResponse, LoginHandshakeStart,
        RegistrationCompletionRequest,
    },
};
use std::io::{self, BufRead};
mod persistence;

#[derive(Args, Debug)]
struct RegisterInput {
    email: String,
}

#[derive(Subcommand, Debug)]
pub enum Subcommands {
    Register(RegisterInput),
}

#[derive(Parser, Debug)]
struct Arguments {
    #[command(subcommand)]
    command: Subcommands,
}

async fn send_initial_registration_request(email: &str) {
    let client = reqwest::Client::new();
    let reg_body = serde_json::json!({ "email": email });
    println!("Sending registration request...");
    let resp = client
        .post("http://localhost:3000/invites/create")
        .json(&reg_body)
        .send()
        .await
        .unwrap();
    println!("{:?}", resp);
    println!("Sent! Check backend console for the following:");

    print!("Invitation ID: ");
    let mut invite_id = String::new();
    let _ = io::stdin().read_line(&mut invite_id);
    let invite_id = invite_id.trim().to_owned();

    print!("\nAcceptance token: ");
    let mut acceptance_token = String::new();
    let _ = io::stdin().read_line(&mut acceptance_token);
    let acceptance_token = acceptance_token.trim().to_owned();

    print!("\nAccount ID: ");
    let mut account_id = String::new();
    let _ = io::stdin().read_line(&mut account_id);
    let account_id = account_id.trim().to_owned();

    print!("\nAnd now choose your password: ");
    let mut password = String::new();
    let _ = io::stdin().lock().read_line(&mut password);
    let password = password.trim().to_owned();

    let registration_info = generate_registration_info(&password, &email, &account_id);

    let confirmation = RegistrationCompletionRequest {
        invite_id,
        acceptance_token,
        public_key: general_purpose::STANDARD.encode(
            registration_info
                .public_key
                .to_pkcs1_der()
                .unwrap()
                .as_bytes(),
        ),
        srp_verifier: general_purpose::STANDARD.encode(registration_info.srp_verifier.0.as_slice()),
    };

    let resp = client
        .post("http://localhost:3000/invites/accept")
        .json(&confirmation)
        .send()
        .await
        .unwrap();
    println!("{:?}", resp);

    let srp_values = generate_client_srp_exchange_value();
    let login = LoginHandshakeStart {
        a_pub: general_purpose::STANDARD.encode(srp_values.a_pub),
        email: email.to_owned(),
        account_id,
    };
    let resp = client
        .post("http://localhost:3000/login")
        .json(&login)
        .send()
        .await
        .unwrap();
    let login_resp: LoginHandshakeResponse = resp.json().await.unwrap();
    let finalized = finalize_srp_exchange(
        &registration_info.srp,
        srp_values.a.as_slice(),
        &general_purpose::STANDARD.decode(login_resp.b_pub).unwrap(),
    );
    println!(
        "Shared secret: {:?}",
        shared::crypto::hashing::sha256(&finalized)
    );
}

#[tokio::main]
async fn main() {
    let args = Arguments::parse();

    match args.command {
        Subcommands::Register(input) => {
            send_initial_registration_request(&input.email).await;
        }
    }
}
