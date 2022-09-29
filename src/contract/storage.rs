use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::network::identity::model::{MemberIdentity,UserIdentity};
use bitcoin::secp256k1::{XOnlyPublicKey};
use crate::contract::model::{InheritanceContract};
use std::str;

pub fn store_inheritance_contract(username: String, id: String, password: String, contract:InheritanceContract)->Result<(), S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract,Some(username)).unwrap();
    let main_tree = sleddb::get_tree(db, &id).unwrap();
    // TODO!!! check if tree contains data, do not insert
    main_tree.insert("0", contract.encrypt(password).as_bytes()).unwrap();
    Ok(())
}
pub fn read_inheritance_contract(username: String, id: String, password:String)->Result<InheritanceContract, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract,Some(username)).unwrap();
    match sleddb::get_tree(db.clone(), &id){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let contract:InheritanceContract = InheritanceContract::decrypt(std::str::from_utf8(&bytes).unwrap().to_string(),password).unwrap();
                    Ok(contract)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No InheritanceContract found in contract tree"))
            }
            } else {
            db.drop_tree(&tree.name()).unwrap();
                Err(S5Error::new(ErrorKind::Input, "No index found in contract tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get contract tree"))
        }
    }
}

pub fn delete_inheritance_contract(username: String, id: String)->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract,Some(username)).unwrap();
    let tree = sleddb::get_tree(db.clone(), &id).unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    true
}

pub fn get_contract_indexes(username: String) -> Vec<String>{
    let root = sleddb::get_root(sleddb::LotrDatabase::Contract,Some(username)).unwrap();
    let mut ids: Vec<String> = [].to_vec();
    for key in root.tree_names().iter() {
        let id = str::from_utf8(key).unwrap();
        if id.starts_with("__"){
        }
        else{
            ids.push(id.to_string());
        };
    }
    ids
}

#[cfg(test)]
mod tests {
  use super::*;


  #[test]
  fn test_contract_storage(){

  }
  
}