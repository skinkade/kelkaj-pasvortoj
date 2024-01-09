use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose as b64, Engine};

pub fn b64_url_encode(bytes: &[u8]) -> String {
    b64::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64_url_decode(str: &str) -> Result<Vec<u8>> {
    b64::URL_SAFE_NO_PAD
        .decode(&str)
        .context("b64_url_decode failure: invalid input")
}
