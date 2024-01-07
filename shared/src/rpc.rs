use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::primitives::Aes256GcmEncryptedData;

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
    pub payload: Aes256GcmEncryptedData
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateVaultEntryPayload {
    pub vault_id: Uuid,
    pub enc_overview: Aes256GcmEncryptedData,
    pub enc_details: Aes256GcmEncryptedData
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
