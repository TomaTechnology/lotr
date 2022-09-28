use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::network::identity::model::{MemberIdentity,UserIdentity};
use bitcoin::secp256k1::{XOnlyPublicKey};
use crate::contract::model::{InheritanceContract};
use std::str;

pub fn store_inheritance_contract(host: String, name: String, password: String, contract:InheritanceContract)->Result<(), S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract,Some(host)).unwrap();
    let main_tree = sleddb::get_tree(db, &name).unwrap();
    // TODO!!! check if tree contains data, do not insert
    main_tree.insert("0", contract.encrypt(password).as_bytes()).unwrap();
    Ok(())
}
pub fn read_inheritance_contract(host: String, name: String, password:String)->Result<InheritanceContract, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract,Some(host)).unwrap();
    match sleddb::get_tree(db.clone(), &name){
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

pub fn delete_inheritance_contract(host: String, name: String)->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract,Some(host)).unwrap();
    let tree = sleddb::get_tree(db.clone(), &name).unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    true
}

#[cfg(test)]
mod tests {
  use super::*;


  #[test]
  fn test_contract_storage(){

  }
  
}