use crate::e::{ErrorKind, S5Error};
use secp256k1::{KeyPair};
use ureq;
use crate::cypherpost::ops::{HttpHeader,HttpMethod,APIEndPoint, sign_request};
use crate::cypherpost::model::{CypherpostIdentity};
use serde::{Deserialize, Serialize};
use secp256k1::rand::{thread_rng,Rng};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AdminInviteResponse{
    pub invite_code: String
}
impl AdminInviteResponse{
    pub fn structify(stringified: &str) -> Result<AdminInviteResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying AdminInviteResponse"))
            }
        }
    }
}
pub fn admin_invite(url: &str, admin_secret: &str)->Result<AdminInviteResponse, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::AdminInvite.to_string();
    let response: String = ureq::get(&full_url)
        .set(&HttpHeader::AdminInvite.to_string(), admin_secret)
        .call().unwrap()
        .into_string().unwrap();

    AdminInviteResponse::structify(&response)
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientRegisterRequest{
    username: String
}
impl ClientRegisterRequest{
    pub fn new(username: &str)->ClientRegisterRequest{
        ClientRegisterRequest {
            username: username.to_string()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientIdentityStatusResponse{
    pub status: bool
}
impl ClientIdentityStatusResponse{
    pub fn structify(stringified: &str) -> Result<ClientIdentityStatusResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying ClientIdentityStatusResponse"))
            }
        }
    }
}

pub fn register(url: &str,key_pair: KeyPair, invite_code: &str, username: &str)->Result<ClientIdentityStatusResponse, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::Identity.to_string();
    let mut rng = thread_rng();
    let random = rng.gen::<u64>();
    let random_string = random.to_string();
    let signature = sign_request(key_pair, HttpMethod::Post, APIEndPoint::Identity, &random_string).unwrap();
    let body = ClientRegisterRequest::new(username);

    let response: String = ureq::post(&full_url)
        .set(&HttpHeader::ClientInvite.to_string(), invite_code)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.public_key().to_string())
        .set(&HttpHeader::Nonce.to_string(), &random_string)
        .send_json(body).unwrap()
        .into_string().unwrap();

    ClientIdentityStatusResponse::structify(&response)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AllIdentitiesResponse{
    pub identities: Vec<CypherpostIdentity>
}

impl AllIdentitiesResponse{
    pub fn structify(stringified: &str) -> Result<AllIdentitiesResponse, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying AllIdentitiesResponse"))
            }
        }
    }
}

pub fn get_all(url: &str,key_pair: KeyPair)->Result<AllIdentitiesResponse, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::AllIdentities.to_string();
    let mut rng = thread_rng();
    let random = rng.gen::<u64>();
    let random_string = random.to_string();
    let signature = sign_request(key_pair, HttpMethod::Get, APIEndPoint::AllIdentities, &random_string).unwrap();

    let response: String = ureq::get(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.public_key().to_string())
        .set(&HttpHeader::Nonce.to_string(), &random_string)
        .call().unwrap()
        .into_string().unwrap();

    AllIdentitiesResponse::structify(&response)
}

pub fn remove(url: &str,key_pair: KeyPair)->Result<ClientIdentityStatusResponse, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::Identity.to_string();
    let mut rng = thread_rng();
    let random = rng.gen::<u64>();
    let random_string = random.to_string();
    let signature = sign_request(key_pair, HttpMethod::Delete, APIEndPoint::Identity, &random_string).unwrap();

    let response: String = ureq::delete(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &key_pair.public_key().to_string())
        .set(&HttpHeader::Nonce.to_string(), &random_string)
        .call().unwrap()
        .into_string().unwrap();

    ClientIdentityStatusResponse::structify(&response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::ec;
    use crate::key::seed;
    use bitcoin::network::constants::Network;

    #[test]
    fn test_invite_flow(){
        let url = "http://localhost:3021";
        // ADMIN INVITE
        let admin_invite_code = "098f6bcd4621d373cade4e832627b4f6";
        let response = admin_invite(url,admin_invite_code).unwrap();
        let client_invite_code = response.invite_code;
        assert_eq!(client_invite_code.len() , 32);
        // REGISTER USER
        let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
        let key_pair = ec::keypair_from_xprv_str(&seed.xprv).unwrap();
        let mut rng = thread_rng();
        let random = rng.gen::<u64>();
        let random_string = random.to_string();
        let username = "ishi".to_string() + &random_string[0..5];
        let response = register(url, key_pair, &client_invite_code, &username).unwrap();
        assert!(response.status);
        // GET ALL USERS
        let response = get_all(url, key_pair).unwrap();
        let user_count = response.identities.len();
        assert!(user_count>0);
        println!("{:#?}", response);
        // REMOVE ONE USER
        let response = remove(url, key_pair).unwrap();
        assert!(response.status);
    }
}