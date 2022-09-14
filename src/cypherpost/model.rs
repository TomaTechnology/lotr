use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CypherPostModel{
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: String,
    pub cypher_json: String,
    pub derivation_scheme: String,
    pub edited : bool,
    pub decryption_key: Option<String>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlainPostModel{
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: String,
    pub plain_json: String,
    pub edited : bool
}