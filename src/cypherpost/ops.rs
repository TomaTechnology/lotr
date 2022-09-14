use crate::key::ec;
use secp256k1::{KeyPair};
use crate::e::{S5Error};
use crate::cypherpost::model::{CypherPostModel,PlainPostModel};
use crate::key::child;
use crate::key::encryption::{key_hash256,cc20p1305_decrypt};

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
    PostKeys
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
        }
    }
}

pub fn sign_request(key_pair: KeyPair, method: HttpMethod, endpoint: APIEndPoint, nonce: &str)-> Result<String, S5Error>{
    let message = method.to_string() + " " + &endpoint.to_string() + " " + nonce;
    let signature = ec::schnorr_sign(&message, key_pair).unwrap();
    return Ok(signature.to_string());
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
            plain_json: plain_json_string,
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
            plain_json: plain_json_string,
            edited : cypherpost.edited
        }
    }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::ec;
    use crate::key::seed;
    use bitcoin::network::constants::Network;

    #[test]
    fn test_sign_cp_request(){
        let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
        let key_pair = ec::keypair_from_xprv_str(&seed.xprv).unwrap();
        let signature = sign_request(key_pair, HttpMethod::Get, APIEndPoint::AllIdentities, "56783999222311").unwrap();
        let message = "GET /api/v2/identity/all 56783999222311";
        let verification = ec::schnorr_verify(&signature, message , &key_pair.public_key().to_string()).unwrap();
        assert!(verification);
    }

}