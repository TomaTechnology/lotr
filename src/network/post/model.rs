use crate::key::encryption::key_hash256;
use crate::key::ec::{schnorr_sign,schnorr_verify};
use bitcoin::secp256k1::{XOnlyPublicKey};


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalPostModel {
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: XOnlyPublicKey,
    pub post: Post,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Post {
    pub to: Recipient,
    pub payload: Payload,
    pub checksum: String,
    pub signature : Signature,
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
    Direct(to: XOnlyPublicKey),
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecryptionKey{
   pub decryption_key: String,
   pub receiver: XOnlyPublicKey
}
impl DecryptionKey{
    pub fn new(decryption_key: &str,receiver: &str)->DecryptionKey{
        DecryptionKey {
            decryption_key: decryption_key.to_string(),
            receiver: receiver.to_string()
        }
    }
}


// MOVED TO PlainPost METHOD
pub fn create_cypherjson(social_root: &str, post: PlainPost)->Result<(String,String),S5Error>{
    let ds = get_and_update_last_ds();
    let enc_source = key::child::to_path_str(social_root, &ds).unwrap().xprv;
    let encryption_key  = key_hash256(&enc_source);
    let cypher_json = cc20p1305_encrypt(&post.stringify().unwrap(), &encryption_key).unwrap();
    Ok((ds,cypher_json))
}

pub fn create_decryption_keys(social_root: &str, derivation_scheme: &str, recipients: Vec<CypherpostIdentity>)->Result<Vec<DecryptionKey>,S5Error>{
    let enc_source = key::child::to_path_str(social_root, &derivation_scheme).unwrap().xprv;
    let encryption_key  = key_hash256(&enc_source);
    let key_pair = ec::keypair_from_xprv_str(&social_root).unwrap();
    let xonly_pair = ec::XOnlyPair::from_keypair(key_pair);// MUST USE TO ENCFORCE PARITY CHECK
    let decryption_keys:Vec<DecryptionKey>  = recipients.into_iter().map(|contact|{
        let shared_secret = ec::compute_shared_secret_str(&xonly_pair.seckey, &contact.pubkey).unwrap();
        let decryption_key = cc20p1305_encrypt(&encryption_key, &shared_secret).unwrap();
        DecryptionKey{
            decryption_key: decryption_key,
            receiver: contact.pubkey
        }
    }).collect();
    Ok(decryption_keys)
}

pub fn decrypt_others_posts(others_posts: Vec<CypherPostModel>, social_root: &str)->Result<Vec<PlainPostModel>,S5Error>{
    Ok(others_posts.into_iter().map(|cypherpost|{
        let my_key_pair = ec::keypair_from_xprv_str(social_root).unwrap();
        let my_xonly_pair = ec::XOnlyPair::from_keypair(my_key_pair);
        let shared_secret = ec::compute_shared_secret_str(&my_xonly_pair.seckey, &cypherpost.owner).unwrap();
        let decryption_key = cc20p1305_decrypt(&cypherpost.decryption_key.unwrap(), &shared_secret).unwrap_or("Bad Key".to_string());
        let plain_json_string = cc20p1305_decrypt(&cypherpost.cypher_json, &decryption_key)
        .unwrap_or(PlainPost::new(PostKind::Message, None, PostItem::new(None, "Decryption Error".to_string())).stringify().unwrap());

        PlainPostModel{
            id: cypherpost.id,
            genesis: cypherpost.genesis,
            expiry: cypherpost.expiry,
            owner: cypherpost.owner,
            plain_post: PlainPost::structify(&plain_json_string).unwrap(),
        }
    }).collect())
}
pub fn decrypt_my_posts(my_posts: Vec<CypherPostModel>, social_root: &str)->Result<Vec<PlainPostModel>,S5Error>{
    Ok(my_posts.into_iter().map(|cypherpost|{
        let decryption_key_root = child::to_path_str(social_root, &cypherpost.derivation_scheme).unwrap();
        let decryption_key = key_hash256(&decryption_key_root.xprv);
        let plain_json_string = cc20p1305_decrypt(&cypherpost.cypher_json, &decryption_key)
        .unwrap_or(PlainPost::new(PostKind::Message, None, PostItem::new(None, "Decryption Error".to_string())).stringify().unwrap());
        
        PlainPostModel{
            id: cypherpost.id,
            genesis: cypherpost.genesis,
            expiry: cypherpost.expiry,
            owner: cypherpost.owner,
            plain_post: PlainPost::structify(&plain_json_string).unwrap(),
        }
    }).collect())
}
pub fn update_and_organize_posts(my_posts: Vec<CypherPostModel>, others_posts: Vec<CypherPostModel>,social_root: &str)->Result<Vec<PlainPostModel>,S5Error>{
    let mut all_posts = decrypt_my_posts(my_posts, social_root).unwrap();
    let mut others_posts = decrypt_others_posts(others_posts, social_root).unwrap();
    all_posts.append(&mut others_posts);
    all_posts.sort_by_key(|post| post.genesis);
    cypherpost::storage::create_posts(all_posts.clone()).unwrap();
    Ok(all_posts)
}