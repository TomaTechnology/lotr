use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::network::model::{LocalPostModel};

pub fn create_posts(post_models: Vec<LocalPostModel>)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    let main_tree = sleddb::get_tree(db, "posts").unwrap();
    let bytes = bincode::serialize(&post_models).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_posts()->Result<Vec<LocalPostModel>,S5Error>{
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
                Err(S5Error::new(ErrorKind::Input, "No such index found in posts tree"))
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
  

}