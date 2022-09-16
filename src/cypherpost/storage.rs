use crate::lib::sleddb;
use crate::e::{ErrorKind, S5Error};
use crate::cypherpost::model::{PlainPostModel};
use crate::cypherpost::model::{CypherpostIdentity};

use serde::{Deserialize, Serialize};

pub enum ServerKind{
    Standard,
    Websocket
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreferenceStore{
    pub server: String,
    pub last_ds: String
}

impl PreferenceStore {
    pub fn new(server: &str, last_ds: &str)->Self{
        PreferenceStore{
            server: server.to_string(),
            last_ds: last_ds.to_string()
        }
    }
}

pub fn create_prefs(prefs: PreferenceStore)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Chat).unwrap();
    let main_tree = sleddb::get_tree(db, "prefs").unwrap();
    // TODO!!! check if tree contains data, do not insert
    let bytes = bincode::serialize(&prefs).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_prefs()->Result<PreferenceStore, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Chat).unwrap();
    match sleddb::get_tree(db.clone(), "prefs"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let key_store: PreferenceStore = bincode::deserialize(&bytes).unwrap();
                    Ok(key_store)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No PreferenceStore found in preferences tree"))
            }
            } else {
            db.drop_tree(&tree.name()).unwrap();
                Err(S5Error::new(ErrorKind::Input, "No preferences index found in preferences tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get preferences tree"))
        }
    }
}
pub fn delete_prefs()->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Chat).unwrap();
    let tree = sleddb::get_tree(db.clone(), "prefs").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}
pub fn server_url_parse(kind: ServerKind, prefs: PreferenceStore)->String{
    match kind{
        ServerKind::Standard=>{
            if prefs.server.starts_with("local") {
                "http://".to_string() + &prefs.server
            }
            else{
                "https://".to_string() + &prefs.server
            }
        }
        ServerKind::Websocket=>{
            if prefs.server.starts_with("local") {
                "ws://".to_string() + &prefs.server
            }
            else{
                "wss://".to_string() + &prefs.server
            }
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PostStore{
    pub posts: Vec<PlainPostModel>
}

pub fn create_posts(post_models: Vec<PlainPostModel>)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Chat).unwrap();
    let main_tree = sleddb::get_tree(db, "posts").unwrap();
    let bytes = bincode::serialize(&post_models).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_posts()->Result<PostStore,S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Chat).unwrap();
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
pub fn delete_posts()->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Chat).unwrap();
    let tree = sleddb::get_tree(db.clone(), "posts").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContactStore{
    pub contacts: Vec<CypherpostIdentity>
}

pub fn create_contacts(contact_models: Vec<CypherpostIdentity>)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Chat).unwrap();
    let main_tree = sleddb::get_tree(db, "contacts").unwrap();
    let bytes = bincode::serialize(&contact_models).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_all_contacts()->Result<ContactStore,S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Chat).unwrap();
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
pub fn delete_contacts()->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Chat).unwrap();
    let tree = sleddb::get_tree(db.clone(), "contacts").unwrap();
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

    let status = create_posts([example_model.clone()].to_vec()).unwrap();
    assert!(status);

    let models = read_posts().unwrap();
    assert_eq!(models.posts.len(), 1);

    let status = delete_posts();
    assert!(status);

  }
  #[test]
  fn test_contact_store(){
    let contact = CypherpostIdentity{
        username: "ishi".to_string(),
        pubkey: "86a4b6e8b4c544111a6736d4f4195027d23495d947f87aa448c088da477c1b5f".to_string()
    };
    let status = create_contacts([contact.clone()].to_vec()).unwrap();
    assert!(status);
    let read_contact_result = read_all_contacts().unwrap();
    assert_eq!(read_contact_result.contacts[0].pubkey,contact.pubkey);
    let status = delete_contacts();
    assert!(status);
  }
  #[test]
  fn test_preference_store(){
    let prefs = PreferenceStore::new("https://localhost:3021","m/1h/0h");
    let status = create_prefs(prefs.clone()).unwrap();
    assert!(status);
    let read_prefs_result = read_prefs().unwrap();
    assert_eq!(read_prefs_result.server,prefs.server);
    let status = delete_prefs();
    assert!(status);
  }
}