use serde::{Deserialize, Serialize};
use crate::e::{S5Error,ErrorKind};

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
    pub plain_post: PlainPost,
    pub edited : bool
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PostKind{
    Message,
    Pubkey,
    Psbt
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlainPost{
    pub kind: PostKind,
    pub value: String,
}
impl PlainPost{
    pub fn stringify(&self) -> Result<String, S5Error> {
        match serde_json::to_string(self) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying PlainPost"))
            }
        }
    }
    pub fn structify(stringified: &str) -> Result<PlainPost, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying PlainPost"))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LotrContract{
    pub builder: String,
    pub facilitator: String,
    pub escrow: String,
}



