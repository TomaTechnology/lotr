use crate::key::child::{ChildKeys};
use serde::{Deserialize, Serialize};
use crate::key::encryption::{cc20p1305_encrypt,cc20p1305_decrypt};
use bdk::bitcoin::util::bip32::ExtendedPrivKey;
use crate::lib::e::{ErrorKind, S5Error};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyStore{
    pub social: ExtendedPrivKey,
    pub money: ExtendedPrivKey,
}

impl KeyStore{
    pub fn new(social_key: ChildKeys, money_key: ChildKeys)->KeyStore{
        KeyStore {
            social: social_key.xprv,
            money: money_key.xprv   
        }
    }

    pub fn stringify(&self) -> Result<String, S5Error> {
        match serde_json::to_string(self) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying KeyStore"))
            }
        }
    }

    pub fn encrypt(&self, password: &str)->String{
        cc20p1305_encrypt(&self.stringify().unwrap(), password).unwrap()
    }

    pub fn structify(stringified: &str) -> Result<KeyStore, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying AllIdentitiesResponse"))
            }
        }
    }
    
    pub fn decrypt(cipher: String, password: &str)->Result<KeyStore, S5Error>{
        Ok(KeyStore::structify(&cc20p1305_decrypt(&cipher, password).unwrap()).unwrap())
    }
}