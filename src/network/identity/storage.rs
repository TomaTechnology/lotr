use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::network::identity::model::{MemberIdentity};

pub fn create_members(member_models: Vec<MemberIdentity>)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    let main_tree = sleddb::get_tree(db, "members").unwrap();
    let bytes = bincode::serialize(&member_models).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_all_members()->Result<Vec<MemberIdentity>,S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    match sleddb::get_tree(db.clone(), "members"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let members: Vec<MemberIdentity> = bincode::deserialize(&bytes).unwrap();
                    tree.flush().unwrap();
                    Ok(members)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No AllMembers found in posts tree"))
            }
            } else {
                db.drop_tree(&tree.name()).unwrap();
                tree.flush().unwrap();
                Err(S5Error::new(ErrorKind::Input, "No AllMembers found in members tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get members tree"))
        }
    }

}
pub fn get_username_by_pubkey(mut members: Vec<MemberIdentity>, pubkey: &str)->Result<String,S5Error>{
    members.retain(|val| val.pubkey == pubkey);
    if members.len() == 1 {
        Ok(members[0].username.to_string())
    }
    else if members.len() > 0 {// should never reach here
        Err(S5Error::new(ErrorKind::Input, "Duplicate member found with this pubkey."))
    }
    else  { 
        Err(S5Error::new(ErrorKind::Input, "No member found with this pubkey."))
    }

}
pub fn delete_members()->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    let tree = sleddb::get_tree(db.clone(), "members").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}

pub fn create_my_identity(me: MemberIdentity)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    let main_tree = sleddb::get_tree(db, "me").unwrap();
    let bytes = bincode::serialize(&me).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_my_identity()->Result<MemberIdentity,S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    match sleddb::get_tree(db.clone(), "me"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let me: MemberIdentity = bincode::deserialize(&bytes).unwrap();
                    tree.flush().unwrap();
                    Ok(me)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No MemberIdentity found in posts tree"))
            }
            } else {
                db.drop_tree(&tree.name()).unwrap();
                tree.flush().unwrap();
                Err(S5Error::new(ErrorKind::Input, "No MemberIdentity found in members tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get me tree"))
        }
    }

}
pub fn delete_my_identity()->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    let tree = sleddb::get_tree(db.clone(), "me").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}


#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_identity_store(){
    let me = MemberIdentity{
        username: "ishi".to_string(),
        pubkey: "66a4b6e8b4c544111a6736d4f4195027d23495d947f87aa448c088da477c1b5f".to_string()
    };
    let mem1 = MemberIdentity{
        username: "sushi".to_string(),
        pubkey: "76a4b6e8b4c544111a6736d4f4195027d23495d947f87aa448c088da477c1b5f".to_string()
    };
    let mem2 = MemberIdentity{
        username: "bubble".to_string(),
        pubkey: "86a4b6e8b4c544111a6736d4f4195027d23495d947f87aa448c088da477c1b5f".to_string()
    };
    let status = create_my_identity(me.clone()).unwrap();
    assert!(status);

    let my_identity = read_my_identity().unwrap();
    assert_eq!(my_identity.username,me.username);

    let status = create_members([me,mem1,mem2.clone()].to_vec()).unwrap();
    assert!(status);
    let members = read_all_members().unwrap();
    assert_eq!(members.len(),3);

    let member = get_username_by_pubkey(members,"86a4b6e8b4c544111a6736d4f4195027d23495d947f87aa448c088da477c1b5f").unwrap();    
    assert_eq!(member, mem2.username);

    let status = delete_members();
    assert!(status);
  }
}