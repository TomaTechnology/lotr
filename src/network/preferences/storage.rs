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
fn get_and_update_last_ds()->String{
    let mut prefs: ServerPreferences = cypherpost::storage::read_prefs().unwrap_or(ServerPreferences{
        last_ds: "m/1h/0h".to_string(),
        server: "localhost:3021".to_string()
    });
    let last_ds = prefs.last_ds;
    let mut split_ds: Vec<String> = last_ds.replace("h","").replace("'","").split("/").map(|s| s.to_string()).collect();
    let rotator = split_ds.pop().unwrap().parse::<u64>().unwrap() + 1;
    let join: String = split_ds.into_iter().map(|val| {
        if val == "m" { val + "/"} 
        else { val + "h/" }
    }).collect();
    let new_ds = join + &rotator.to_string() + "h";
    
    prefs.last_ds = new_ds.clone();
    cypherpost::storage::create_prefs(prefs).unwrap();
    new_ds

}
pub fn delete_prefs()->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Network).unwrap();
    let tree = sleddb::get_tree(db.clone(), "prefs").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}

#[cfg(test)]
mod tests {
  use super::*;
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