use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemberIdentity{
    pub username: String,
    pub pubkey: String,
}
