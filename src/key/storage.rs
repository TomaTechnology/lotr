use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::key::model::{KeyStore};

pub fn create(key_store: KeyStore)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
    let main_tree = sleddb::get_tree(db, "keys").unwrap();
    // TODO!!! check if tree contains data, do not insert

    let bytes = bincode::serialize(&key_store).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read()->Result<KeyStore, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
    match sleddb::get_tree(db.clone(), "keys"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
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

  #[test]
  fn test_keystore() {
    let password = "tricky";
    let seed =  seed::generate(24,"",Network::Bitcoin).unwrap();
    let social_path = "m/128h/0h";
    let social_key = child::to_path_str(&seed.xprv, social_path).unwrap();
    let money_key = child::to_hardened_account(&seed.xprv, child::DerivationPurpose::Native, 0).unwrap();
    let key_store = KeyStore::new(social_key.clone(),money_key.clone());
    let encryped = key_store.encrypt(password);
    let status = create(encryped.clone()).unwrap();
    assert!(status);
    let keystore = read().unwrap();
    assert_ne!(keystore.social,social_key.xprv);
    assert_ne!(keystore.money,money_key.xprv);
    assert_eq!(keystore.clone().decrypt(password).social,social_key.xprv);
    assert_eq!(keystore.decrypt(password).money,money_key.xprv);
    let status = delete();
    assert!(status);
    let keystore_error = read().unwrap_err();
    assert_eq!(keystore_error.message,"No master_key index found in key tree");
    assert_eq!(keystore_error.kind,ErrorKind::Input.to_string());

  }

}