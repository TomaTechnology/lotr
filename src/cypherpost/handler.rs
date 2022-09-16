use crate::key::ec;
use secp256k1::{KeyPair};
use crate::lib::e::{S5Error,ErrorKind};
use crate::cypherpost;
use crate::cypherpost::model::{CypherPostModel,PlainPostModel,PlainPost,DecryptionKey,CypherpostIdentity};
use crate::key;
use crate::key::child;
use crate::key::encryption::{key_hash256,cc20p1305_decrypt,cc20p1305_encrypt};

pub enum HttpMethod{
    Get,
    Put,
    Post,
    Delete    
}

impl HttpMethod{
    pub fn to_string(&self)->String{
        match self{
            HttpMethod::Get=>"GET".to_string(),
            HttpMethod::Put=>"PUT".to_string(),
            HttpMethod::Post=>"POST".to_string(),
            HttpMethod::Delete=>"DELETE".to_string(),
        }
    }
}

pub enum HttpHeader{
    AdminInvite,
    ClientInvite,
    Pubkey,
    Signature,
    Nonce
}

impl HttpHeader{
    pub fn to_string(&self)->String{
        match self{
            HttpHeader::AdminInvite=>"x-admin-invite-secret".to_string(),
            HttpHeader::ClientInvite=>"x-client-invite-code".to_string(),
            HttpHeader::Pubkey=>"x-client-pubkey".to_string(),
            HttpHeader::Signature=>"x-client-signature".to_string(),
            HttpHeader::Nonce=>"x-nonce".to_string(),
        }
    }
}

pub enum APIEndPoint{
    AdminInvite,
    Identity,
    AllIdentities,
    Post(Option<String>),
    PostKeys,
    Notifications
}

impl APIEndPoint{
    pub fn to_string(&self)->String{
        match self{
            APIEndPoint::AdminInvite=>"/api/v2/identity/admin/invitation".to_string(),
            APIEndPoint::Identity=>"/api/v2/identity".to_string(),
            APIEndPoint::AllIdentities=>"/api/v2/identity/all".to_string(),
            APIEndPoint::Post(id)=>{
                match id {
                    Some(id)=>"/api/v2/post".to_string() + "/" + id,
                    None=>"/api/v2/post".to_string()
                }
            },
            APIEndPoint::PostKeys=>"/api/v2/post/keys".to_string(),
            APIEndPoint::Notifications=>"/api/v3/notifications".to_string(),
        }
    }
}

pub fn sign_request(key_pair: KeyPair, method: HttpMethod, endpoint: APIEndPoint, nonce: &str)-> Result<String, S5Error>{
    let message = method.to_string() + " " + &endpoint.to_string() + " " + nonce;
    let signature = ec::schnorr_sign(&message, key_pair).unwrap();
    return Ok(signature.to_string());
}

fn get_and_update_last_ds()->String{
    let mut prefs = cypherpost::storage::read_prefs().unwrap();
    let last_ds = prefs.last_ds;
    let mut split_ds: Vec<String> = last_ds.replace("h","").replace("'","").split("/").map(|s| s.to_string()).collect();
    let rotator = split_ds.pop().unwrap().parse::<u64>().unwrap() + 1;
    let join: String = split_ds.into_iter().map(|val| {
        if val == "m" { val + "/"} 
        else { val + "h/" }
    }).collect();
    let new_ds = join + &rotator.to_string() + "h";
    
    prefs.last_ds = new_ds.clone();
    cypherpost::storage::create_prefs(prefs).unwrap();
    new_ds

}

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

pub fn decrypt_my_posts(my_posts: Vec<CypherPostModel>, social_root: &str)->Result<Vec<PlainPostModel>,S5Error>{
    Ok(my_posts.into_iter().map(|cypherpost|{
        let decryption_key_root = child::to_path_str(social_root, &cypherpost.derivation_scheme).unwrap();
        let decryption_key = key_hash256(&decryption_key_root.xprv);
        let plain_json_string = cc20p1305_decrypt(&cypherpost.cypher_json, &decryption_key).unwrap();
        PlainPostModel{
            id: cypherpost.id,
            genesis: cypherpost.genesis,
            expiry: cypherpost.expiry,
            owner: cypherpost.owner,
            plain_post: PlainPost::structify(&plain_json_string).unwrap(),
            edited : cypherpost.edited
        }
    }).collect())
}

pub fn decrypt_others_posts(others_posts: Vec<CypherPostModel>, social_root: &str)->Result<Vec<PlainPostModel>,S5Error>{
    Ok(others_posts.into_iter().map(|cypherpost|{
        let my_key_pair = ec::keypair_from_xprv_str(social_root).unwrap();
        let my_xonly_pair = ec::XOnlyPair::from_keypair(my_key_pair);
        let shared_secret = ec::compute_shared_secret_str(&my_xonly_pair.seckey, &cypherpost.owner).unwrap();
        let decryption_key = cc20p1305_decrypt(&cypherpost.decryption_key.unwrap(), &shared_secret).unwrap();
        let plain_json_string = cc20p1305_decrypt(&cypherpost.cypher_json, &decryption_key).unwrap();

        PlainPostModel{
            id: cypherpost.id,
            genesis: cypherpost.genesis,
            expiry: cypherpost.expiry,
            owner: cypherpost.owner,
            plain_post: PlainPost::structify(&plain_json_string).unwrap(),
            edited : cypherpost.edited
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

pub fn get_username_by_pubkey(pubkey: &str)->Result<String,S5Error>{
    let mut contacts = cypherpost::storage::read_all_contacts().unwrap().contacts;
    contacts.retain(|val| val.pubkey == pubkey);
    if contacts.len() > 0 {
        Ok(contacts[0].username.to_string())
    }
    else {
        Err(S5Error::new(ErrorKind::Input, "No username found with this pubkey."))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::ec;
    use crate::key::seed;
    use bitcoin::network::constants::Network;
    // use crate::cypherpost::model::{PostKind};

    #[test]
    fn test_sign_cp_request(){
        let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
        let key_pair = ec::keypair_from_xprv_str(&seed.xprv).unwrap();
        let signature = sign_request(key_pair, HttpMethod::Get, APIEndPoint::AllIdentities, "56783999222311").unwrap();
        let message = "GET /api/v2/identity/all 56783999222311";
        let verification = ec::schnorr_verify(&signature, message , &key_pair.public_key().to_string()).unwrap();
        assert!(verification);
    }
    #[test]
    fn test_create_post_and_keys(){
        // let post = PlainPost {
        //     kind: PostKind::Message,
        //     label: None,
        //     value: "THIS IS IT!".to_string(),
        // };
        // let recipient = 
        // let result = get_and_update_last_ds();
        // println!("{}",result);
    }

}