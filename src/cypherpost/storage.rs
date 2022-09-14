use crate::lib::sleddb;
use sled::{Db};
use std::str;
use crate::e::{ErrorKind, S5Error};
use crate::cypherpost::model::{PlainPostModel};
use crate::cypherpost::identity::{CypherpostIdentity};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PostStore{
    pub posts: Vec<PlainPostModel>
}

pub fn create_posts(db: Db, post_models: Vec<PlainPostModel>)->Result<bool, S5Error>{
    let main_tree = sleddb::get_tree(db, "posts").unwrap();
    let bytes = bincode::serialize(&post_models).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_posts(db: Db)->Result<PostStore,S5Error>{
    match sleddb::get_tree(db.clone(), "posts"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let posts: PostStore = bincode::deserialize(&bytes).unwrap();
                    tree.flush().unwrap();
                    Ok(posts)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No PostStore found in posts tree"))
            }
            } else {
                db.drop_tree(&tree.name()).unwrap();
                tree.flush().unwrap();
                Err(S5Error::new(ErrorKind::Input, "No PostStore found in posts tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get posts tree"))
        }
    }

}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContactStore{
    pub contacts: Vec<CypherpostIdentity>
}

pub fn create_contacts(db: Db, contact_models: Vec<CypherpostIdentity>)->Result<bool, S5Error>{
    let main_tree = sleddb::get_tree(db, "contacts").unwrap();
    let bytes = bincode::serialize(&contact_models).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_all_contacts(db: Db)->Result<ContactStore,S5Error>{
    match sleddb::get_tree(db.clone(), "contacts"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let contacts: ContactStore = bincode::deserialize(&bytes).unwrap();
                    tree.flush().unwrap();
                    Ok(contacts)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No ContactStore found in posts tree"))
            }
            } else {
                db.drop_tree(&tree.name()).unwrap();
                tree.flush().unwrap();
                Err(S5Error::new(ErrorKind::Input, "No ContactStore found in contacts tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get contacts tree"))
        }
    }

}


#[cfg(test)]
mod tests {
  use super::*;
  use crate::cypherpost::model::{PostKind,PlainPost};

  #[test]
  fn test_posts_store() {
    let example_post  = PlainPost{
        kind: PostKind::Message,
        label: None,
        value: "Yo, I have a secret only for you".to_string()
    };

    let example_model = PlainPostModel{
        id: "s5pvdGwg22tiUp8rsupd4fTrtYMEWS".to_string(),
        edited: false,
        genesis: 192783921384334,
        expiry: 0,
        owner: "builder".to_string(),
        plain_post: example_post,
    };

    let db = sleddb::get_root(sleddb::LotrDatabase::Posts).unwrap();
    let status = create_posts(db.clone(), [example_model.clone()].to_vec()).unwrap();
    assert!(status);

    let models = read_posts(db.clone()).unwrap();
    assert_eq!(models.posts.len(), 1);

  }
  #[test]
  fn test_contact_store(){
    let contact = CypherpostIdentity{
        username: "ishi".to_string(),
        pubkey: "86a4b6e8b4c544111a6736d4f4195027d23495d947f87aa448c088da477c1b5f".to_string()
    };

    let db = sleddb::get_root(sleddb::LotrDatabase::Contacts).unwrap();
    let status = create_contacts(db.clone(), [contact.clone()].to_vec()).unwrap();
    assert!(status);

    let read_contact_result = read_all_contacts(db.clone()).unwrap();
    assert_eq!(read_contact_result.contacts[0].pubkey,contact.pubkey);

  }
}