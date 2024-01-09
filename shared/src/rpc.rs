use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::primitives::Aes256GcmEncryptedDataB64;

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcPayload {
    pub command: String,
    pub parameters: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcResponse {
    pub result: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedRpcPayload {
    pub payload: Aes256GcmEncryptedDataB64
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateVaultEntryPayload {
    pub vault_id: Uuid,
    pub enc_overview: Aes256GcmEncryptedDataB64,
    pub enc_details: Aes256GcmEncryptedDataB64
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateVaultEntryResponse {
    pub id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RpcInput {
    CreateVaultEntry(CreateVaultEntryPayload),
    ModifyVaultEntry,
    DeleteVaultEntry
}
