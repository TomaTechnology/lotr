use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::contract::model::{NodeInfo, ContractInfo,PolicyInfo};


pub fn create_contract_info(info: ContractInfo)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract).unwrap();
    let main_tree = sleddb::get_tree(db, "info").unwrap();
    // TODO!!! check if tree contains data, do not insert
    let bytes = bincode::serialize(&info).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_contract_info()->Result<ContractInfo, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract).unwrap();
    match sleddb::get_tree(db.clone(), "info"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let key_store: ContractInfo = bincode::deserialize(&bytes).unwrap();
                    Ok(key_store)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No ContractInfo found in info tree"))
            }
            } else {
            db.drop_tree(&tree.name()).unwrap();
                Err(S5Error::new(ErrorKind::Input, "No index found in info tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get info tree"))
        }
    }
}
// pub fn update_depositor_info(part_info: PolicyInfo)->Result<bool, S5Error>{
//     match read_contract_info(){
//         Ok(mut contract_info)=>{
//             contract_info.depositor = part_info;
//             create_contract_info(contract_info).unwrap();
//             Ok(true)
//         },
//         Err(e)=>{
//             Err(e)
//         }
//     }
// }
// pub fn update_beneficiary_info(part_info: PolicyInfo)->Result<bool, S5Error>{
//     match read_contract_info(){
//         Ok(mut contract_info)=>{
//             contract_info.beneficiary = part_info;
//             create_contract_info(contract_info).unwrap();
//             Ok(true)
//         },
//         Err(e)=>{
//             Err(e)
//         }
//     }
// }
// pub fn update_escrow_info(part_info: PolicyInfo)->Result<bool, S5Error>{
//     match read_contract_info(){
//         Ok(mut contract_info)=>{
//             contract_info.escrow = part_info;
//             create_contract_info(contract_info).unwrap();
//             Ok(true)
//         },
//         Err(e)=>{
//             Err(e)
//         }
//     }
// }
// pub fn update_timelock(timelock: u64)->Result<bool, S5Error>{
//     match read_contract_info(){
//         Ok(mut contract_info)=>{
//             contract_info.timelock = Some(timelock);
//             create_contract_info(contract_info).unwrap();
//             Ok(true)
//         },
//         Err(e)=>{
//             Err(e)
//         }
//     }
// }
// pub fn update_pub_policy(policy: String)->Result<bool, S5Error>{
//     match read_contract_info(){
//         Ok(mut contract_info)=>{
//             contract_info.public_policy = Some(policy);
//             create_contract_info(contract_info).unwrap();
//             Ok(true)
//         },
//         Err(e)=>{
//             Err(e)
//         }
//     }
// }
pub fn delete_contract_info()->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract).unwrap();
    let tree = sleddb::get_tree(db.clone(), "info").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}

#[cfg(test)]
mod tests {
  use super::*;


  #[test]
  fn test_contract_storage(){

  }
  
}