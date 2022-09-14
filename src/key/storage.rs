use crate::lib::sleddb;
use sled::{Db};
use std::str;
use crate::e::{ErrorKind, S5Error};
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

pub fn create(db: Db, key_store: KeyStore)->Result<bool, S5Error>{
    let main_tree = sleddb::get_tree(db, "0").unwrap();
    // TODO!!! check if tree contains data, do not insert

    let bytes = bincode::serialize(&key_store).unwrap();
    main_tree.insert("keys", bytes).unwrap();
    Ok(true)
}
pub fn read(db: Db)->Result<KeyStore, S5Error>{
    match sleddb::get_tree(db.clone(), "0"){
        Ok(tree)=>{
            if tree.contains_key(b"keys").unwrap() {
            match tree.get("keys").unwrap() {
                Some(bytes) => {
                    let key_store: KeyStore = bincode::deserialize(&bytes).unwrap();
                    Ok(key_store)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No KeyStore found in key tree"))
            }
            } else {
            db.drop_tree(&tree.name()).unwrap();
                Err(S5Error::new(ErrorKind::Input, "No master_key index found in key tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get key tree"))
        }
    }
}
pub fn delete(db: Db)->bool{
    let tree = sleddb::get_tree(db.clone(), "0").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}


#[cfg(test)]
mod tests {
  use super::*;
  use crate::key::seed;
  use crate::key::child;
  use bdk::bitcoin::network::constants::Network;

  #[test]
  fn test_keystore() {
    let password = "tricky";
    let seed =  seed::generate(24,"",Network::Bitcoin).unwrap();
    let social_path = "m/128h/0h";
    let social_key = child::to_path_str(&seed.xprv, social_path).unwrap();
    let money_key = child::to_hardened_account(&seed.xprv, child::DerivationPurpose::Native, 0).unwrap();
    let key_store = KeyStore::new(social_key.clone(),money_key.clone());
    let encryped = key_store.encrypt(password);
    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
    let status = create(db.clone(),encryped.clone()).unwrap();
    assert!(status);
    let keystore = read(db.clone()).unwrap();
    assert_ne!(keystore.social,social_key.xprv);
    assert_ne!(keystore.money,money_key.xprv);
    assert_eq!(keystore.clone().decrypt(password).social,social_key.xprv);
    assert_eq!(keystore.decrypt(password).money,money_key.xprv);
    let status = delete(db.clone());
    assert!(status);
    let keystore_error = read(db).unwrap_err();
    assert_eq!(keystore_error.message,"No master_key index found in key tree");
    assert_eq!(keystore_error.kind,ErrorKind::Input.to_string());

  }

}