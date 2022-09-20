use serde::{Deserialize, Serialize};
use crate::lib::e::{S5Error,ErrorKind};
use crate::key;

pub enum ServerKind{
    Standard,
    Websocket
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPreferences{
    pub server: String,
    pub last_ds: String
}

impl ServerPreferences {
    pub fn new(server: &str, last_ds: &str)->Self{
        ServerPreferences{
            server: server.to_string(),
            last_ds: last_ds.to_string()
        }
    }
    pub fn server_url_parse(&self, kind: ServerKind)->String{
        match kind{
            ServerKind::Standard=>{
                if self.server.starts_with("local") {
                    "http://".to_string() + &self.server
                }
                else{
                    "https://".to_string() + &self.server
                }
            }
            ServerKind::Websocket=>{
                if self.server.starts_with("local") {
                    "ws://".to_string() + &self.server
                }
                else{
                    "wss://".to_string() + &self.server
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CypherpostIdentity{
    pub username: String,
    pub pubkey: String,
}

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum PostKind{
    Message,
    Pubkey,
    AddressIndex,
    Psbt,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PostItem{
    pub label : Option<String>,
    pub value : String,
}

impl PostItem{
    pub fn new(label: Option<String>, value: String) -> Self{
        PostItem{
            label: label,
            value: value
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlainPost{
    pub kind: PostKind,
    pub reference: Option<String>,
    pub signature : Option<String>,
    pub item: PostItem,
}
impl PlainPost{
    pub fn new(kind: PostKind, reference: Option<String>,  item: PostItem)->Self{
        PlainPost{
            kind: kind,
            reference: reference,
            signature: None,
            item: item
        }
    }

    pub fn to_cypher(&self, social_root: &str, derivation: &str)->String{
        let enc_source = key::child::to_path_str(social_root, derivation).unwrap().xprv;
        let encryption_key  = key::encryption::key_hash256(&enc_source);
        let cypher = key::encryption::cc20p1305_encrypt(&self.stringify().unwrap(), &encryption_key).unwrap();
        cypher
    }

    pub fn sign(&mut self, social_root: &str)->PlainPost{
        let message = self.clone().reference.unwrap_or("None".to_string()) + " " + &self.clone().item.label.unwrap_or("None".to_string()) + " " + &key::encryption::nonce();
        let keypair = key::ec::keypair_from_xprv_str(&social_root).unwrap();
        let signature = key::ec::schnorr_sign(&message, keypair). unwrap();
        self.signature = Some(signature.to_string());
        self.clone()
    }
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
pub struct PlainPostModel{
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: String,
    pub plain_post: PlainPost,
    pub edited : bool
}
impl PlainPostModel{
    pub fn stringify(&self) -> Result<String, S5Error> {
        match serde_json::to_string(self) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying PlainPostModel"))
            }
        }
    }
    pub fn structify(stringified: &str) -> Result<PlainPostModel, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying PlainPostModel"))
            }
        }
    }
    pub fn get_posts_by_kind(mut posts: Vec<PlainPostModel>, kind: PostKind)->Vec<PlainPostModel>{
        posts.retain(|x| x.plain_post.kind == kind);
        posts
    }
}



#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AllPosts{
    pub posts: Vec<PlainPostModel>
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cypherpost_models(){
        let example  = PlainPost::new(
            PostKind::Message,None,
            PostItem::new(
                Some("msg".to_string()), "Secret just for me!".to_string()
            )
        );
        let stringified = example.stringify().unwrap();
        println!("{:#?}",stringified);
    }
    
}
