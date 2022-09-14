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

pub fn create(db: Db, post_model: PlainPostModel)->Result<bool, S5Error>{
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
pub fn read_all(db: Db)->Result<PostStore,S5Error>{
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
pub fn delete(db: Db, post_id: &str)->bool{
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


#[cfg(test)]
mod tests {
  use super::*;
  use crate::cypherpost::model::{PostKind,PlainPost};

  #[test]
  fn test_poststore() {
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
    let status = create(db.clone(), example_model.clone()).unwrap();
    assert!(status);

    let models = read_all(db.clone()).unwrap();
    assert_eq!(models.posts.len(), 1);

    let status = delete(db, &example_model.id);
    assert!(status);

  }
}