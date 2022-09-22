use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::cypherpost::model::{PlainPostModel};
use crate::cypherpost::model::{ServerPreferences,AllPosts, AllContacts,CypherpostIdentity};

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

// MOVED TO PlainPost METHOD
pub fn create_cypherjson(social_root: &str, post: PlainPost)->Result<(String,String),S5Error>{
    let ds = get_and_update_last_ds();
    let enc_source = key::child::to_path_str(social_root, &ds).unwrap().xprv;
    let encryption_key  = key_hash256(&enc_source);
    let cypher_json = cc20p1305_encrypt(&post.stringify().unwrap(), &encryption_key).unwrap();
    Ok((ds,cypher_json))
}

pub fn create_decryption_keys(social_root: &str, derivation_scheme: &str, recipients: Vec<CypherpostIdentity>)->Result<Vec<DecryptionKey>,S5Error>{
    let enc_source = key::child::to_path_str(social_root, &derivation_scheme).unwrap().xprv;
    let encryption_key  = key_hash256(&enc_source);
    let key_pair = ec::keypair_from_xprv_str(&social_root).unwrap();
    let xonly_pair = ec::XOnlyPair::from_keypair(key_pair);// MUST USE TO ENCFORCE PARITY CHECK
    let decryption_keys:Vec<DecryptionKey>  = recipients.into_iter().map(|contact|{
        let shared_secret = ec::compute_shared_secret_str(&xonly_pair.seckey, &contact.pubkey).unwrap();
        let decryption_key = cc20p1305_encrypt(&encryption_key, &shared_secret).unwrap();
        DecryptionKey{
            decryption_key: decryption_key,
            receiver: contact.pubkey
        }
    }).collect();
    Ok(decryption_keys)
}

pub fn decrypt_others_posts(others_posts: Vec<CypherPostModel>, social_root: &str)->Result<Vec<PlainPostModel>,S5Error>{
    Ok(others_posts.into_iter().map(|cypherpost|{
        let my_key_pair = ec::keypair_from_xprv_str(social_root).unwrap();
        let my_xonly_pair = ec::XOnlyPair::from_keypair(my_key_pair);
        let shared_secret = ec::compute_shared_secret_str(&my_xonly_pair.seckey, &cypherpost.owner).unwrap();
        let decryption_key = cc20p1305_decrypt(&cypherpost.decryption_key.unwrap(), &shared_secret).unwrap_or("Bad Key".to_string());
        let plain_json_string = cc20p1305_decrypt(&cypherpost.cypher_json, &decryption_key)
        .unwrap_or(PlainPost::new(PostKind::Message, None, PostItem::new(None, "Decryption Error".to_string())).stringify().unwrap());

        PlainPostModel{
            id: cypherpost.id,
            genesis: cypherpost.genesis,
            expiry: cypherpost.expiry,
            owner: cypherpost.owner,
            plain_post: PlainPost::structify(&plain_json_string).unwrap(),
        }
    }).collect())
}
pub fn decrypt_my_posts(my_posts: Vec<CypherPostModel>, social_root: &str)->Result<Vec<PlainPostModel>,S5Error>{
    Ok(my_posts.into_iter().map(|cypherpost|{
        let decryption_key_root = child::to_path_str(social_root, &cypherpost.derivation_scheme).unwrap();
        let decryption_key = key_hash256(&decryption_key_root.xprv);
        let plain_json_string = cc20p1305_decrypt(&cypherpost.cypher_json, &decryption_key)
        .unwrap_or(PlainPost::new(PostKind::Message, None, PostItem::new(None, "Decryption Error".to_string())).stringify().unwrap());
        
        PlainPostModel{
            id: cypherpost.id,
            genesis: cypherpost.genesis,
            expiry: cypherpost.expiry,
            owner: cypherpost.owner,
            plain_post: PlainPost::structify(&plain_json_string).unwrap(),
        }
    }).collect())
}
pub fn update_and_organize_posts(my_posts: Vec<CypherPostModel>, others_posts: Vec<CypherPostModel>,social_root: &str)->Result<Vec<PlainPostModel>,S5Error>{
    let mut all_posts = decrypt_my_posts(my_posts, social_root).unwrap();
    let mut others_posts = decrypt_others_posts(others_posts, social_root).unwrap();
    all_posts.append(&mut others_posts);
    all_posts.sort_by_key(|post| post.genesis);
    cypherpost::storage::create_posts(all_posts.clone()).unwrap();
    Ok(all_posts)
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