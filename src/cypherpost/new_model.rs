use crate::key::encryption::key_hash256;
use crate::key::ec::{schnorr_sign,schnorr_verify};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CypherpostIdentity{
    pub username: String,
    pub pubkey: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostRequest{
    pub expiry: u64,
    pub cypher_json: String,
    pub derivation_scheme: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostResponse{
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: String,
    pub cypher_json: String,
    pub derivation_scheme: String,
    pub decryption_key: Option<String>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PostModel {
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: String,
    pub post: Post,
}
impl PostModel{
    
    pub fn from_cypher(
        cypherpost: ServerPostResponse,
        social_root: &str
    )->Result<Self, S5Error>{
        // check if reponse owner is self or other
        let my_pubkey = XOnlyPair::from_keypair(ec::keypair_from_xprv_str(social_root.clone()).unwrap()).pubkey;
        if cypherpost.owner == my_pubkey {
            let decryption_key_root = child::to_path_str(social_root, &cypherpost.derivation_scheme).unwrap();
            let decryption_key = key_hash256(&decryption_key_root.xprv);
            let plain_json_string = cc20p1305_decrypt(&cypherpost.cypher_json, &decryption_key){
                Ok(plain)=>{
                    plain
                }
                Err(err)=>{
                    return Err(S5Error::new(ErrorKind::Key, "Decryption failure."));
                }
            }
            PostModel{
                id: cypherpost.id,
                genesis: cypherpost.genesis,
                expiry: cypherpost.expiry,
                owner: cypherpost.owner,
                post: Post::structify(&plain_json_string).unwrap(),
            }
        }
        else {
            let my_key_pair = ec::keypair_from_xprv_str(social_root).unwrap();
            let my_xonly_pair = ec::XOnlyPair::from_keypair(my_key_pair);
            let shared_secret = ec::compute_shared_secret_str(&my_xonly_pair.seckey, &cypherpost.owner).unwrap();
            let decryption_key = cc20p1305_decrypt(&cypherpost.decryption_key.unwrap(), &shared_secret).unwrap_or("Bad Key".to_string());
            let plain_json_string = cc20p1305_decrypt(&cypherpost.cypher_json, &decryption_key)
            .unwrap_or(Post::new(PostKind::Message, None, PostItem::new(None, "Decryption Error".to_string())).stringify().unwrap());
    
            Ok(PostModel{
                id: cypherpost.id,
                genesis: cypherpost.genesis,
                expiry: cypherpost.expiry,
                owner: cypherpost.owner,
                post: Post::structify(&plain_json_string).unwrap(),
            });
        }

        // parse into Post and create PostModel
    }
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
            schnorr_sign(checksum),
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