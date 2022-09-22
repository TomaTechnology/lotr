use crate::lib::e::{ErrorKind, S5Error};
use secp256k1::{KeyPair};
use ureq;
use crate::cypherpost::handler::{HttpHeader,HttpMethod,APIEndPoint, sign_request};
use crate::cypherpost::model::{CypherPostModel,DecryptionKey};
use serde::{Deserialize, Serialize};
use secp256k1::rand::{thread_rng,Rng};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostRequest{
    expiry: u64,
    derivation_scheme: String,
    cypher_json: String
}

impl ServerPostRequest{
    pub fn new(expiry: u64, derivation_scheme: &str, cypher_json: &str)->ServerPostRequest{
        ServerPostRequest {
            expiry,
            derivation_scheme: derivation_scheme.to_string(),
            cypher_json: cypher_json.to_string()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostIdResponse{
    pub id: String
}
impl ServerPostIdResponse{
    pub fn structify(stringified: &str) -> Result<ServerPostIdResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying ServerPostIdResponse"))
            }
        }
    }
}

pub fn create(url: &str,key_pair: KeyPair, cpost_req: ServerPostRequest)->Result<String, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::Post(None).to_string();
    let mut rng = thread_rng();
    let random = rng.gen::<u64>();
    let random_string = random.to_string();
    let signature = sign_request(key_pair, HttpMethod::Put, APIEndPoint::Post(None), &random_string).unwrap();

    let response: String = ureq::put(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.public_key().to_string())
        .set(&HttpHeader::Nonce.to_string(), &random_string)
        .send_json(cpost_req).unwrap()
        .into_string().unwrap();

    Ok(ServerPostIdResponse::structify(&response).unwrap().id)
}

pub fn remove(url: &str,key_pair: KeyPair, id: &str)->Result<bool, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::Post(Some(id.to_string())).to_string();
    let mut rng = thread_rng();
    let random = rng.gen::<u64>();
    let random_string = random.to_string();
    let signature = sign_request(key_pair, HttpMethod::Delete, APIEndPoint::Post(Some(id.to_string())), &random_string).unwrap();

    let response: String = ureq::delete(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.public_key().to_string())
        .set(&HttpHeader::Nonce.to_string(), &random_string)
        .call().unwrap()
        .into_string().unwrap();

    Ok(ServerStatusResponse::structify(&response).unwrap().status)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostKeysRequest{
    post_id: String,
    decryption_keys: Vec<DecryptionKey>
}

impl ServerPostKeysRequest{
    pub fn new(post_id: &str, decryption_keys: Vec<DecryptionKey>)->ServerPostKeysRequest{
        ServerPostKeysRequest {
            post_id: post_id.to_string(),
            decryption_keys
        }
    }
}

pub fn keys(url: &str,key_pair: KeyPair, post_id: &str, decryption_keys: Vec<DecryptionKey>)->Result<ServerStatusResponse, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::PostKeys.to_string();
    let mut rng = thread_rng();
    let random = rng.gen::<u64>();
    let random_string = random.to_string();
    let signature = sign_request(key_pair, HttpMethod::Put, APIEndPoint::PostKeys, &random_string).unwrap();
    let body = ServerPostKeysRequest::new(post_id, decryption_keys);

    let response: String = ureq::put(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.public_key().to_string())
        .set(&HttpHeader::Nonce.to_string(), &random_string)
        .send_json(body).unwrap()
        .into_string().unwrap();

    ServerStatusResponse::structify(&response)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostRequest{
    pub expiry: u64,
    pub cypher_json: String,
    pub derivation_scheme: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostModel{
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: String,
    pub cypher_json: String,
    pub derivation_scheme: String,
    pub decryption_key: Option<String>
}
impl ServerPostModel{
    pub fn decypher(
        &self,
        social_root: &str
    )->Result<Self, S5Error>{
        // check if reponse owner is self or other
        let my_pubkey = XOnlyPair::from_keypair(ec::keypair_from_xprv_str(social_root.clone()).unwrap()).pubkey;
        if self.owner == my_pubkey {
            let decryption_key_root = child::to_path_str(social_root, &self.derivation_scheme).unwrap();
            let decryption_key = key_hash256(&decryption_key_root.xprv);
            let plain_json_string = cc20p1305_decrypt(&self.cypher_json, &decryption_key){
                Ok(plain)=>{
                    plain
                }
                Err(err)=>{
                    return Err(S5Error::new(ErrorKind::Key, "Decryption failure."));
                }
            }
            PostModel{
                id: self.id,
                genesis: self.genesis,
                expiry: self.expiry,
                owner: self.owner,
                post: Post::structify(&plain_json_string).unwrap(),
            }
        }
        else {
            let my_key_pair = ec::keypair_from_xprv_str(social_root).unwrap();
            let my_xonly_pair = ec::XOnlyPair::from_keypair(my_key_pair);
            let shared_secret = ec::compute_shared_secret_str(&my_xonly_pair.seckey, &self.owner).unwrap();
            let decryption_key = cc20p1305_decrypt(&self.decryption_key.unwrap(), &shared_secret).unwrap_or("Bad Key".to_string());
            let plain_json_string = cc20p1305_decrypt(&self.cypher_json, &decryption_key)
            .unwrap_or(Post::new(PostKind::Message, None, PostItem::new(None, "Decryption Error".to_string())).stringify().unwrap());
    
            Ok(PostModel{
                id: self.id,
                genesis: self.genesis,
                expiry: self.expiry,
                owner: self.owner,
                post: Post::structify(&plain_json_string).unwrap(),
            });
        }

    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostModelResponse{
    pub posts: Vec<ServerPost>
}
impl ServerPostModelResponse{
    pub fn structify(stringified: &str) -> Result<ServerPostModelResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying ServerPostModelResponse"))
            }
        }
    }
}

pub fn my_posts(url: &str,key_pair: KeyPair)->Result<Vec<ServerPostModel>, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::Post(Some("self".to_string())).to_string();
    let mut rng = thread_rng();
    let random = rng.gen::<u64>();
    let random_string = random.to_string();
    let signature = sign_request(key_pair, HttpMethod::Get, APIEndPoint::Post(Some("self".to_string())), &random_string).unwrap();

    let response: String = ureq::get(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.public_key().to_string())
        .set(&HttpHeader::Nonce.to_string(), &random_string)
        .call().unwrap()
        .into_string().unwrap();

    Ok(ServerPostModelResponse::structify(&response).unwrap().posts)
}

pub fn others_posts(url: &str,key_pair: KeyPair)->Result<Vec<ServerPostModel>, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::Post(Some("others".to_string())).to_string();
    let mut rng = thread_rng();
    let random = rng.gen::<u64>();
    let random_string = random.to_string();
    let signature = sign_request(key_pair, HttpMethod::Get, APIEndPoint::Post(Some("others".to_string())), &random_string).unwrap();

    let response: String = ureq::get(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.public_key().to_string())
        .set(&HttpHeader::Nonce.to_string(), &random_string)
        .call().unwrap()
        .into_string().unwrap();

    Ok(ServerPostModelResponse::structify(&response).unwrap().posts)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPostSingleResponse{
    pub post: ServerPostModel
}
impl ServerPostSingleResponse{
    pub fn structify(stringified: &str) -> Result<ServerPostSingleResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying ServerPostSingleResponse"))
            }
        }
    }
}

pub fn single_post(url: &str,key_pair: KeyPair,post_id: &str)->Result<ServerPostModel, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::Post(Some(post_id.to_string())).to_string();
    let mut rng = thread_rng();
    let random = rng.gen::<u64>();
    let random_string = random.to_string();
    let signature = sign_request(key_pair, HttpMethod::Get, APIEndPoint::Post(Some(post_id.to_string())), &random_string).unwrap();

    let response: String = ureq::get(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.public_key().to_string())
        .set(&HttpHeader::Nonce.to_string(), &random_string)
        .call().unwrap()
        .into_string().unwrap();

    Ok(ServerPostSingleResponse::structify(&response).unwrap().post)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cypherpost::identity::{admin_invite,register,get_all};
    use crate::key::ec;
    use crate::key::seed;
    use crate::key::child;
    use crate::cypherpost::model::{PlainPost,PostKind,PostItem};
    use crate::key::encryption::{cc20p1305_encrypt, key_hash256};
    use crate::cypherpost::handler::{decrypt_my_posts,decrypt_others_posts};
    use bdk::bitcoin::network::constants::Network;
    
    #[test] #[ignore]
    fn test_post_flow(){
        let url = "http://localhost:3021";
        // ADMIN INVITE
        let admin_invite_code = "098f6bcd4621d373cade4e832627b4f6";
        let client_invite_code1 = admin_invite(url,admin_invite_code).unwrap();
        assert_eq!(client_invite_code1.len() , 32);
        
        let client_invite_code2 = admin_invite(url,admin_invite_code).unwrap();
        assert_eq!(client_invite_code1.len() , 32);

        let client_invite_code3 = admin_invite(url,admin_invite_code).unwrap();
        assert_eq!(client_invite_code1.len() , 32);

        // REGISTER USERS
        let social_root_scheme = "m/128h/0h";

        let mut rng = thread_rng();
        let random = rng.gen::<u64>();
        let random_string = random.to_string();

        let seed1 = seed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child1 = child::to_path_str(&seed1.xprv, social_root_scheme).unwrap();
        let key_pair1 = ec::keypair_from_xprv_str(&social_child1.xprv).unwrap();
        let xonly_pair1 = ec::XOnlyPair::from_keypair(key_pair1);
        let user1 = "builder".to_string() + &random_string[0..3];

        let response = register(url, key_pair1, &client_invite_code1, &user1).unwrap();
        assert!(response.status);

        let seed2 = seed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child2 = child::to_path_str(&seed2.xprv, social_root_scheme).unwrap();
        let key_pair2 = ec::keypair_from_xprv_str(&social_child2.xprv).unwrap();
        let xonly_pair2 = ec::XOnlyPair::from_keypair(key_pair2);
        let user2 = "facilitator".to_string() + &random_string[0..3];
        
        let response = register(url, key_pair2, &client_invite_code2, &user2).unwrap();
        assert!(response.status);

        let seed3 = seed::generate(24, "", Network::Bitcoin).unwrap();
        let social_child3 = child::to_path_str(&seed3.xprv, social_root_scheme).unwrap();
        let key_pair3 = ec::keypair_from_xprv_str(&social_child3.xprv).unwrap();
        let xonly_pair3 = ec::XOnlyPair::from_keypair(key_pair3);
        let user3 = "escrow".to_string() + &random_string[0..3];
        
        let response = register(url, key_pair3, &client_invite_code3, &user3).unwrap();
        assert!(response.status);

        // GET ALL USERS
        let identities = get_all(url, key_pair1).unwrap();
        let user_count = identities.len();
        assert!(user_count>0);
        println!("{:#?}", response);

        // Create a struct to share
        let xpub_to_share = PlainPost::new(
            PostKind::Pubkey,
            None,
            PostItem::new(
                Some("xkey".to_string()), "xpubsomesomerands".to_string()
            )
        );
    
        // Json stringify it
        let stringy_xpub = xpub_to_share.stringify().unwrap();
        // Create an encryption key for it using a derivation_scheme from mk
        let encryption_key_scheme = "m/1h/0h";

        let encryption_key_source = child::to_path_str(&social_child1.xprv, encryption_key_scheme).unwrap();
        let encryption_key  = key_hash256(&encryption_key_source.xprv);
        // Encrypt it into cypherjson
        let cypher_json = cc20p1305_encrypt(&stringy_xpub, &encryption_key).unwrap();
        // PUT cypherjson
        let cpost_req = ServerPostRequest::new(0, encryption_key_scheme,&cypher_json);
        let post_id = create(url,key_pair1, cpost_req).unwrap();
        assert_eq!(post_id.len(), 24);
        // calculate shared secrets with recipients
        let user12ss = ec::compute_shared_secret_str(&xonly_pair1.seckey, &xonly_pair2.pubkey).unwrap();
        let user21ss = ec::compute_shared_secret_str(&xonly_pair2.seckey, &xonly_pair1.pubkey).unwrap();
        assert_eq!(user21ss, user12ss);

        let user13ss = ec::compute_shared_secret_str(&xonly_pair1.seckey, &xonly_pair3.pubkey).unwrap();
        // encrypt encryption key with shared secrets and create decryption_keys
        let decryption_key12 = DecryptionKey::new(&cc20p1305_encrypt(&encryption_key, &user12ss).unwrap(), &xonly_pair2.pubkey);
        let decryption_key13 = DecryptionKey::new(&cc20p1305_encrypt(&encryption_key, &user13ss).unwrap(), &xonly_pair3.pubkey);
        let decryption_keys: Vec<DecryptionKey> = [decryption_key12,decryption_key13].to_vec();
        // PUT post_keys
        let response = keys(url, key_pair1, &post_id,decryption_keys).unwrap();
        assert!(response.status);
        // Get posts & keys as user2
        let posts = others_posts(url,key_pair2).unwrap();
        assert_eq!(posts.len(),1);
        println!("{:#?}",posts);
        let decrypted = decrypt_others_posts(posts, &social_child2.xprv).unwrap();
        assert_eq!(decrypted.len(),1);
        assert_eq!(decrypted[0].plain_post.stringify().unwrap(),stringy_xpub);

        // Get posts & keys as user3
        let posts = others_posts(url,key_pair3).unwrap();
        assert_eq!(posts.len(),1);
        println!("{:#?}",posts);
        let decrypted = decrypt_others_posts(posts, &social_child3.xprv).unwrap();
        assert_eq!(decrypted.len(),1);
        assert_eq!(decrypted[0].plain_post.stringify().unwrap(),stringy_xpub);

        // Get posts as self
        let posts = my_posts(url,key_pair1).unwrap();
        assert_eq!(posts.len(),1);
        let decrypted = decrypt_my_posts(posts, &social_child1.xprv).unwrap();
        assert_eq!(decrypted.len(),1);
        assert_eq!(decrypted[0].plain_post.stringify().unwrap(),stringy_xpub);
        // Delete post
        let status = remove(url,key_pair1, &post_id).unwrap();
        assert!(status);
        // KEEP BUILDING!

    }
}