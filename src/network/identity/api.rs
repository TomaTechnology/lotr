use ureq;
use serde::{Deserialize, Serialize};

use crate::key::encryption::{nonce};
use crate::key::ec::{XOnlyPair};
use crate::network::handler::{HttpHeader,HttpMethod,APIEndPoint,ServerStatusResponse,ServerErrorResponse, sign_request};
use crate::network::identity::model::{MemberIdentity};
use crate::lib::e::{ErrorKind, S5Error};

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
    match ureq::get(&full_url)
        .set(&HttpHeader::AdminInvite.to_string(), admin_secret)
        .call()
        {
            Ok(response)=>  Ok(
                match AdminInviteResponse::structify(&response.into_string().unwrap()){
                    Ok(result)=>result,
                    Err(e) =>{
                        return Err(e);
                    }
                }
            ),
            Err(e)=>{
                return Err(S5Error::from_ureq(e))
            }
        }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityRegisterRequest{
    username: String
}
impl IdentityRegisterRequest{
    pub fn new(username: &str)->IdentityRegisterRequest{
        IdentityRegisterRequest {
            username: username.to_string()
        }
    }
}

pub fn register(url: &str,keys: XOnlyPair, invite_code: &str, username: &str)->Result<ServerStatusResponse, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::Identity.to_string();
    let nonce = nonce();
    let signature = sign_request(keys.clone(), HttpMethod::Post, APIEndPoint::Identity, &nonce).unwrap();
    let body = IdentityRegisterRequest::new(username);

    match ureq::post(&full_url)
        .set(&HttpHeader::ClientInvite.to_string(), invite_code)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &keys.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .send_json(body){
            Ok(response)=>  
                match ServerStatusResponse::structify(&response.into_string().unwrap())
                {
                    Ok(result)=>Ok(result),
                    Err(e) =>{
                        Err(e)
                    }
                }            
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AllIdentitiesResponse{
    pub identities: Vec<MemberIdentity>
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

pub fn get_all(url: &str,keys: XOnlyPair)->Result<AllIdentitiesResponse, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::AllIdentities.to_string();
    let nonce = nonce();
    let signature = sign_request(keys.clone(), HttpMethod::Get, APIEndPoint::AllIdentities, &nonce).unwrap();

    match ureq::get(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &keys.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .call(){
            Ok(response)=>
                match AllIdentitiesResponse::structify(&response.into_string().unwrap())
                {
                    Ok(result)=>Ok(result),
                    Err(e) =>{
                        Err(e)
                    }
                },
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }
}

pub fn remove(url: &str,keys: XOnlyPair)->Result<ServerStatusResponse, S5Error>{
    let full_url = url.to_string() + &APIEndPoint::Identity.to_string();
    let nonce = nonce();
    let signature = sign_request(keys.clone(), HttpMethod::Delete, APIEndPoint::Identity, &nonce).unwrap();

    match ureq::delete(&full_url)
        .set(&HttpHeader::Signature.to_string(), &signature)
        .set(&HttpHeader::Pubkey.to_string(), &keys.pubkey.to_string())
        .set(&HttpHeader::Nonce.to_string(), &nonce)
        .call(){
            Ok(response)=> match ServerStatusResponse::structify(&response.into_string().unwrap())
                {
                    Ok(result)=>Ok(result),
                    Err(e) =>{
                        Err(e)
                    }
                },
            Err(e)=>{
                Err(S5Error::from_ureq(e))
            }
        }
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
        let client_invite_code = admin_invite(url,admin_invite_code).unwrap();
        assert_eq!(client_invite_code.invite_code.len() , 32);
        // REGISTER USER
        let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
        let keys = XOnlyPair::from_keypair(ec::keypair_from_xprv_str(&seed.xprv).unwrap());
        let nonce = nonce();
        let username = "ishi".to_string() + &nonce[0..5];
        let response = register(url, keys.clone(), &client_invite_code.invite_code, &username).unwrap();
        assert!(response.status);
        // GET ALL USERS
        let identities = get_all(url, keys.clone()).unwrap();
        let user_count = identities.identities.len();
        assert!(user_count>0);
        println!("{:#?}", response);
        // REMOVE ONE USER
        let status = remove(url, keys).unwrap();
        assert!(status.status);
    }
}