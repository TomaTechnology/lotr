use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::cypherpost::model::{PlainPostModel};
use crate::cypherpost::model::{ServerPreferences,AllPosts, AllContacts,CypherpostIdentity};

pub fn create_prefs(prefs: ServerPreferences)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    let main_tree = sleddb::get_tree(db, "prefs").unwrap();
    // TODO!!! check if tree contains data, do not insert
    let bytes = bincode::serialize(&prefs).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_prefs()->Result<ServerPreferences, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    match sleddb::get_tree(db.clone(), "prefs"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let key_store: ServerPreferences = bincode::deserialize(&bytes).unwrap();
                    Ok(key_store)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No ServerPreferences found in preferences tree"))
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
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    let tree = sleddb::get_tree(db.clone(), "prefs").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}

pub fn create_posts(post_models: Vec<PlainPostModel>)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    let main_tree = sleddb::get_tree(db, "posts").unwrap();
    let bytes = bincode::serialize(&post_models).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_posts()->Result<AllPosts,S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    match sleddb::get_tree(db.clone(), "posts"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let posts: AllPosts = bincode::deserialize(&bytes).unwrap();
                    tree.flush().unwrap();
                    Ok(posts)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No AllPosts found in posts tree"))
            }
            } else {
                db.drop_tree(&tree.name()).unwrap();
                tree.flush().unwrap();
                Err(S5Error::new(ErrorKind::Input, "No AllPosts found in posts tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get posts tree"))
        }
    }

}
pub fn delete_posts()->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    let tree = sleddb::get_tree(db.clone(), "posts").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}


#[cfg(test)]
mod tests {
  use super::*;
  use crate::cypherpost::model::{PostKind,PlainPost,PostItem};

  #[test]
  fn test_posts_store() {
    
    let example_post  = PlainPost::new(
        PostKind::Message,
        None,
        PostItem::new(
            Some("msg".to_string()), "Secret just for me!".to_string()
        )
    );


    let example_model = PlainPostModel{
        id: "s5pvdGwg22tiUp8rsupd4fTrtYMEWS".to_string(),
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
    let prefs = ServerPreferences::new("https://localhost:3021","m/1h/0h");
    let status = create_prefs(prefs.clone()).unwrap();
    assert!(status);
    let read_prefs_result = read_prefs().unwrap();
    assert_eq!(read_prefs_result.server,prefs.server);
    let status = delete_prefs();
    assert!(status);
  }
}