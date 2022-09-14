use crate::lib::sleddb;
use sled::{Db};
use std::str;
use crate::e::{ErrorKind, S5Error};
use crate::cypherpost::model::{PlainPostModel};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PostStore{
    posts: Vec<PlainPostModel>
}

pub fn create_post(db: Db, post_model: PlainPostModel)->Result<bool, S5Error>{
    match sleddb::get_tree(db.clone(), "0"){
        Ok(tree)=>{
            if tree.contains_key(b"posts").unwrap() {
            match tree.get("posts").unwrap() {
                Some(bytes) => {
                    let mut existing: PostStore = bincode::deserialize(&bytes).unwrap();
                    existing.posts.push(post_model);
                    let bytes = bincode::serialize(&existing).unwrap();
                    tree.insert("posts", bytes).unwrap();
                    tree.flush().unwrap();
                    Ok(true)
                },
                None => {
                    let bytes = bincode::serialize(&[post_model].to_vec()).unwrap();
                    tree.insert("posts", bytes).unwrap();
                    tree.flush().unwrap();
                    Ok(true)
                }
            }
            } else {
                let bytes = bincode::serialize(&[post_model].to_vec()).unwrap();
                tree.insert("posts", bytes).unwrap();
                tree.flush().unwrap();
                Ok(true)
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get posts tree"))
        }
    }
}
pub fn read_all_posts(db: Db)->Result<PostStore,S5Error>{
    match sleddb::get_tree(db.clone(), "0"){
        Ok(tree)=>{
            if tree.contains_key(b"posts").unwrap() {
            match tree.get("posts").unwrap() {
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
                Err(S5Error::new(ErrorKind::Input, "No posts index found in posts tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get key tree"))
        }
    }

}
pub fn delete_post(db: Db, post_id: &str)->bool{
    match sleddb::get_tree(db.clone(), "0"){
        Ok(tree)=>{
            if tree.contains_key(b"posts").unwrap() {
            match tree.get("posts").unwrap() {
                Some(bytes) => {
                    let mut existing: PostStore = bincode::deserialize(&bytes).unwrap();
                    existing.posts.retain(|x| x.id != post_id);
                    let bytes = bincode::serialize(&existing).unwrap();
                    tree.insert("posts", bytes).unwrap();
                    tree.flush().unwrap();

                    return true
                },
                None => {
                    return false
                }
            }
            } else {
                return false
            }
        }
        Err(_)=>{
            return false
        }
    }

}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Contact{
    username: String,
    pubkey: String
}
pub fn create_contact(db: Db, contact: Contact)->Result<bool, S5Error>{
    let main_tree = sleddb::get_tree(db.clone(), &contact.username).unwrap();
    // TODO!!! check if tree contains data, do not insert

    let bytes = bincode::serialize(&contact).unwrap();
    main_tree.insert("contact", bytes).unwrap();

    let main_tree = sleddb::get_tree(db, &contact.pubkey).unwrap();
    // TODO!!! check if tree contains data, do not insert

    let bytes = bincode::serialize(&contact).unwrap();
    main_tree.insert("contact", bytes).unwrap();

    Ok(true)
}
pub fn read_by_username(db: Db, username: &str)->Result<Contact, S5Error>{
    match sleddb::get_tree(db.clone(), username){
        Ok(tree)=>{
            if tree.contains_key(b"contact").unwrap() {
            match tree.get("contact").unwrap() {
                Some(bytes) => {
                    let contact: Contact = bincode::deserialize(&bytes).unwrap();
                    Ok(contact)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No Contact found in contacts tree"))
            }
            } else {
            db.drop_tree(&tree.name()).unwrap();
                Err(S5Error::new(ErrorKind::Input, "No contact index found in contact tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get contact tree"))
        }
    }
}
pub fn delete_by_username(db: Db, username: &str)->bool{
    let tree = sleddb::get_tree(db.clone(), username).unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}

pub fn read_by_pubkey(db: Db, pubkey: &str)->Result<Contact, S5Error>{
    match sleddb::get_tree(db.clone(), pubkey){
        Ok(tree)=>{
            if tree.contains_key(b"contact").unwrap() {
            match tree.get("contact").unwrap() {
                Some(bytes) => {
                    let contact: Contact = bincode::deserialize(&bytes).unwrap();
                    Ok(contact)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No Contact found in contacts tree"))
            }
            } else {
            db.drop_tree(&tree.name()).unwrap();
                Err(S5Error::new(ErrorKind::Input, "No contact index found in contact tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get contact tree"))
        }
    }
}
pub fn delete_by_pubkey(db: Db, pubkey: &str)->bool{
    let tree = sleddb::get_tree(db.clone(), pubkey).unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cypherpost::model::{PostKind,PlainPost};

  #[test]
  fn test_posts_store() {
    let example_post  = PlainPost{
        kind: PostKind::Message,
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
    let status = create_post(db.clone(), example_model.clone()).unwrap();
    assert!(status);

    let models = read_all_posts(db.clone()).unwrap();
    assert_eq!(models.posts.len(), 1);

    let status = delete_post(db, &example_model.id);
    assert!(status);

  }
  #[test]
  fn test_contact_store(){
    let contact = Contact{
        username: "ishi".to_string(),
        pubkey: "86a4b6e8b4c544111a6736d4f4195027d23495d947f87aa448c088da477c1b5f".to_string()
    };

    let db = sleddb::get_root(sleddb::LotrDatabase::Contacts).unwrap();
    let status = create_contact(db.clone(), contact.clone()).unwrap();
    assert!(status);

    let read_contact_result = read_by_username(db.clone(), &contact.username).unwrap();
    assert_eq!(read_contact_result.pubkey,contact.pubkey);

    let read_contact_result = read_by_pubkey(db.clone(), &contact.pubkey).unwrap();
    assert_eq!(read_contact_result.username,contact.username);

    let status = delete_by_username(db, &contact.username);
    assert!(status);
  }
}