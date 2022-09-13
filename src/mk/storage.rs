use crate::lib::sleddb;
use sled::{Db};
use std::str;
use crate::e::{ErrorKind, S5Error};
use crate::mk::child::{ChildKeys};
use serde::{Deserialize, Serialize};
use crate::mk::encryption::{cc20p1305_encrypt,cc20p1305_decrypt};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyStore{
    username: String,
    social: String,
    money: String,
}

impl KeyStore{
    pub fn new(username: &str, social_key: ChildKeys, money_key: ChildKeys)->KeyStore{
        KeyStore {
            username: username.to_string(),
            social: social_key.stringify().unwrap(),
            money: money_key.stringify().unwrap()   
        }
    }
    pub fn encrypt(self, password: &str)->KeyStore{
        KeyStore{
            username: self.username.to_string(),
            social: cc20p1305_encrypt(&self.social, password).unwrap(),
            money: cc20p1305_encrypt(&self.money,password).unwrap(),
        }
    }
    pub fn decrypt(self, password: &str)->KeyStore{
        KeyStore{
            username: self.username.to_string(),
            social: cc20p1305_decrypt(&self.social, password).unwrap(),
            money: cc20p1305_decrypt(&self.money,password).unwrap(),
        }
    }
}

pub fn create(db: Db, key_store: KeyStore)->Result<bool, S5Error>{
    let main_tree = sleddb::get_tree(db, &key_store.username).unwrap();
    // TODO!!! check if tree contains data, do not insert

    let bytes = bincode::serialize(&key_store).unwrap();
    main_tree.insert("master_key", bytes).unwrap();
    Ok(true)
}
pub fn read(db: Db, username: &str, )->Result<KeyStore, S5Error>{
    match sleddb::get_tree(db.clone(), username){
        Ok(tree)=>{
            if tree.contains_key(b"master_key").unwrap() {
            match tree.get("master_key").unwrap() {
                Some(bytes) => {
                    let key_store: KeyStore = bincode::deserialize(&bytes).unwrap();
                    Ok(key_store)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No KeyStore found in mk tree"))
            }
            } else {
            db.drop_tree(&tree.name()).unwrap();
                Err(S5Error::new(ErrorKind::Input, "No master_key index found in mk tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get mk tree"))
        }
    }
}
pub fn delete(db: Db, username: &str)->bool{
    let tree = sleddb::get_tree(db.clone(), username).unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}


#[cfg(test)]
mod tests {
  use super::*;
  use crate::mk::seed;
  use crate::mk::child;
  use bitcoin::network::constants::Network;

  #[test]
  fn test_keystore() {
    let username = "ishi";
    let password = "tricky";
    let seed =  seed::generate(24,"",Network::Bitcoin).unwrap();
    let social_path = "m/128h/0h";
    let social_key = child::to_path_str(&seed.xprv, social_path).unwrap();
    let money_key = child::to_hardened_account(&seed.xprv, child::DerivationPurpose::Native, 0).unwrap();
    let key_store = KeyStore::new(username,social_key.clone(),money_key.clone());
    let encryped = key_store.encrypt(password);
    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
    let status = create(db.clone(),encryped.clone()).unwrap();
    assert!(status);
    let keystore = read(db.clone(), username).unwrap();
    assert_ne!(keystore.social,social_key.stringify().unwrap());
    assert_ne!(keystore.money,money_key.stringify().unwrap());
    assert_eq!(keystore.clone().decrypt(password).social,social_key.stringify().unwrap());
    assert_eq!(keystore.decrypt(password).money,money_key.stringify().unwrap());
    let status = delete(db.clone(), username);
    assert!(status);
    let keystore_error = read(db, username).unwrap_err();
    assert_eq!(keystore_error.message,"No master_key index found in mk tree");
    assert_eq!(keystore_error.kind,ErrorKind::Input.to_string());

  }

}