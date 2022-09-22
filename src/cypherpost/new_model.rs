use crate::key::encryption::key_hash256;
use crate::key::ec::{schnorr_sign,schnorr_verify};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CypherpostIdentity{
    pub username: String,
    pub pubkey: String,
}

pub struct ServerPostRequest{
    pub expiry: u64,
    pub cypher_json: String,
    pub derivation_scheme: String,
}

pub struct ServerPostResponse{
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: String,
    pub cypher_json: String,
    pub derivation_scheme: String,
    pub decryption_key: Option<String>
}

pub struct PostModel {
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: String,
    pub post: Post,
}

pub struct Post {
    pub to: Recipient,
    pub payload: Payload,
    pub checksum: String,
    pub signature : String,
}

impl Post{

    pub fn sign(&self)->String{
        let value = &self.to.to_string() + ":" + self.payload.to_string();
        key_hash256(value)
    }
    pub fn new(
        to: Recipient, 
        payload: Payload, 
    )->Self{
        Post {
            to,
            payload,
            key_hash256(&to.to_string() + ":" + payload.to_string()),
            this.sign(),
        }
    }
}

pub enum Recipient {
    Direct(pubkey: String),
    Group(id: String),
}
pub enum Payload {
    Ping, // All contracts start with a ping
    ChecksumPong(checksum: String), // All pings responded with pong and checksum proof.
    Message(text: String),
    Quote(quote: Quotation),  // quote an exchange rate
    Confirm(reference: String), // thumbs up another post
    Reject(reference: String), // thumbs down another post
    Comment(reference: String, text: String), // comment on another post
    PolicyXpub(xpub: PolicyXpub),
    Address(address: WalletAddress),
    Psbt(psbt: WalletPsbt),
    Document(doc: std::file::File),
    Jitsi(url: String),
}

pub struct Quotation{
    pub base: FiatUnit,
    pub source_url: String,
    pub source_rate: u64,
    pub insurance: f64, // escrow base fees
    pub dispute: f64, // escrow dispute fees, shared by maker and taker in case of a dispute
    pub margin: f64, // maker margin
    pub price: u64, // your final quote
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
pub struct AllPosts{
    pub posts: Vec<LocalPost>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AllContacts{
    pub contacts: Vec<CypherpostIdentity>
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