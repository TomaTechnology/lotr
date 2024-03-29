use serde::{Deserialize, Serialize};
use bitcoin::secp256k1::{XOnlyPublicKey};
use bdk::bitcoin::util::bip32::ExtendedPrivKey;
use crate::key::encryption::{cc20p1305_encrypt,cc20p1305_decrypt};
use crate::lib::e::{ErrorKind, S5Error};
use crate::key::ec::{XOnlyPair};
use crate::key::child;
use crate::key::encryption;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemberIdentity{
    pub username: String,
    pub pubkey: XOnlyPublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserIdentity{
    pub username: String,
    pub account: u64,
    pub social_root: ExtendedPrivKey,
    pub last_index: u64,
}

impl UserIdentity {
    pub fn new(username: String, account: u64, root: ExtendedPrivKey)->Self{
        let social_path = "m/128h/0h/".to_string() + &account.to_string() + "h";
        let social_root = child::to_path_str(root, &social_path).unwrap().xprv;
        UserIdentity{
            username,
            account,
            social_root,
            last_index: 0
        }
    }
    pub fn stringify(&self) -> Result<String, S5Error> {
        match serde_json::to_string(self) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying UserIdentity"))
            }
        }
    }
    pub fn structify(stringified: &str) -> Result<UserIdentity, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying UserIdentity"))
            }
        }
    }
    pub fn encrypt(&self, password: String)->String{
        cc20p1305_encrypt(&self.stringify().unwrap(), &password).unwrap()
    }
    pub fn decrypt(cipher: String, password: String)->Result<UserIdentity, S5Error>{
        let id = match cc20p1305_decrypt(&cipher, &password){
            Ok(value)=>value,
            Err(e)=>return Err(e)
        };

        Ok(UserIdentity::structify(&id).unwrap())
    }
    fn increment_path(&mut self)->(){
        self.last_index += 1;
        ()
    }
    pub fn to_member_id(&self)->MemberIdentity{
        let pubkey = XOnlyPair::from_xprv(self.clone().social_root).pubkey;
        let username = self.clone().username;
        MemberIdentity{
            username: username,
            pubkey: pubkey
        }
    }
    pub fn to_xonly_pair(&self)->XOnlyPair{
       XOnlyPair::from_xprv(self.clone().social_root)
    }
    pub fn derive_encryption_key(&mut self)->String{
        self.increment_path();
        let enc_source = child::to_path_index(self.social_root, self.last_index).unwrap().xprv.to_string();
        encryption::key_hash256(&enc_source)
    }
}

