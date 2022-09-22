use crate::key::encryption::key_hash256;
use crate::key::ec::{schnorr_sign,schnorr_verify};


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalPostModel {
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: String,
    pub post: Post,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Post {
    pub to: Recipient,
    pub payload: Payload,
    pub checksum: String,
    pub signature : String,
}

impl Post{
    pub fn new(
        to: Recipient, 
        payload: Payload, 
        key_pair: KeyPair
    )->Self{
        let checksum_message = &to.to_string() + ":" + payload.to_string();
        let checksum = key_hash256(checksum_message);
        Post {
            to,
            payload,
            checksum.clone(),
            schnorr_sign(checksum, key_pair),
        }
    }
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
    pub fn encypher(&self, social_root: &str, derivation: &str)->String{
        let enc_source = key::child::to_path_str(social_root, derivation).unwrap().xprv;
        let encryption_key  = key::encryption::key_hash256(&enc_source);
        let cypher = key::encryption::cc20p1305_encrypt(&self.stringify().unwrap(), &encryption_key).unwrap();
        cypher
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Recipient {
    Direct(pubkey: String),
    Group(id: String),
}
impl Recipient {
    pub fn to_string(&self)->String{
        match self{
            Direct(pubkey)=>pubkey,
            Group(id)=>id
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Payload {
    Ping, // All contracts start with a ping
    ChecksumPong(checksum: String), // All pings responded with pong and checksum proof.
    Message(text: String),
    Confirm(reference: String), // thumbs up another post
    Reject(reference: String), // thumbs down another post
    Comment(reference: String, text: String), // comment on another post
    PolicyXpub(xpub: PolicyXpub),
    Address(address: WalletAddress),
    Psbt(psbt: WalletPsbt),
    Document(doc: std::file::File),
    Jitsi(url: String),
}
impl Payload{
}


pub enum FiatUnit{
    INR
}
pub struct PolicyXPub{
    pub label: String,
    pub value: bitcoin::*::ExtendedPubkey
}

pub struct WalletAddress {
    pub label: String,
    pub index: u64,
    pub value: bitcoin::*::Address
}

pub struct WalletPsbt {
    pub label: String,
    pub value: bitcoin::*::PartiallySignedTransaction
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecryptionKey{
   pub decryption_key: String,
   pub receiver: String
}
impl DecryptionKey{
    pub fn new(decryption_key: &str,receiver: &str)->DecryptionKey{
        DecryptionKey {
            decryption_key: decryption_key.to_string(),
            receiver: receiver.to_string()
        }
    }
}