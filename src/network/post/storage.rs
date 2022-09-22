
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
