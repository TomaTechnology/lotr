use serde::{Deserialize, Serialize};
use bitcoin::secp256k1::{XOnlyPublicKey};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemberIdentity{
    pub username: String,
    pub pubkey: XOnlyPublicKey,
}
