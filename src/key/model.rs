use crate::key::child::{ChildKeys};
use serde::{Deserialize, Serialize};
use crate::key::encryption::{cc20p1305_encrypt,cc20p1305_decrypt};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyStore{
    pub social: String,
    pub money: String,
}

impl KeyStore{
    pub fn new(social_key: ChildKeys, money_key: ChildKeys)->KeyStore{
        KeyStore {
            social: social_key.xprv,
            money: money_key.xprv   
        }
    }
    pub fn encrypt(self, password: &str)->KeyStore{
        KeyStore{
            social: cc20p1305_encrypt(&self.social, password).unwrap(),
            money: cc20p1305_encrypt(&self.money,password).unwrap(),
        }
    }
    pub fn decrypt(self, password: &str)->KeyStore{
        KeyStore{
            social: cc20p1305_decrypt(&self.social, password).unwrap(),
            money: cc20p1305_decrypt(&self.money,password).unwrap(),
        }
    }
}