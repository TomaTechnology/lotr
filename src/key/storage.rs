use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use std::str;

pub fn create(key_store_cipher: String)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
    let main_tree = sleddb::get_tree(db, "keys").unwrap();
    main_tree.insert("0", key_store_cipher.as_bytes()).unwrap();
    Ok(true)
}
pub fn read()->Result<String, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
    match sleddb::get_tree(db.clone(), "keys"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    Ok(str::from_utf8(&bytes).unwrap().to_string())
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No KeyStore found in key tree"))
            }
            } else {
            db.drop_tree(&tree.name()).unwrap();
                Err(S5Error::new(ErrorKind::Input, "No such index found in key tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get key tree"))
        }
    }
}
pub fn delete()->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
    let tree = sleddb::get_tree(db.clone(), "keys").unwrap();
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
  use crate::key::model::{KeyStore};

  #[test]
  fn test_keystore() {
    let password = "tricky";
    let seed =  seed::generate(24,"",Network::Bitcoin).unwrap();
    let social_path = "m/128h/0h";
    let social_key = child::to_path_str(seed.xprv, social_path).unwrap();
    let money_key = child::to_hardened_account(seed.xprv, child::DerivationPurpose::Native, 0).unwrap();
    let key_store = KeyStore::new(social_key.clone(),money_key.clone());
    let encryped = key_store.encrypt(password);
    let status = create(encryped.clone()).unwrap();
    assert!(status);
    let keystore = KeyStore::decrypt(read().unwrap(),password).unwrap();
    assert_eq!(keystore.social,social_key.xprv);
    assert_eq!(keystore.money,money_key.xprv);
    let status = delete();
    assert!(status);
    let keystore_error = read().is_err();
    assert!(keystore_error);
  }

}