use crate::lib::sleddb;
use crate::e::{ErrorKind, S5Error};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeInfoStore{
    pub url: String,
    pub socks5: u32
}

impl NodeInfoStore {
    pub fn new(url: &str, socks5: u32)->Self{
        NodeInfoStore{
            url: url.to_string(),
            socks5: socks5
        }
    }
}

pub fn create_node_info(prefs: NodeInfoStore)->Result<bool, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract).unwrap();
    let main_tree = sleddb::get_tree(db, "node").unwrap();
    // TODO!!! check if tree contains data, do not insert
    let bytes = bincode::serialize(&prefs).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(true)
}
pub fn read_node_info()->Result<NodeInfoStore, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract).unwrap();
    match sleddb::get_tree(db.clone(), "node"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let key_store: NodeInfoStore = bincode::deserialize(&bytes).unwrap();
                    Ok(key_store)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "No NodeInfoStore found in node tree"))
            }
            } else {
            db.drop_tree(&tree.name()).unwrap();
                Err(S5Error::new(ErrorKind::Input, "No index found in node tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::Internal, "Could not get node tree"))
        }
    }
}
pub fn delete_node_info()->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Contract).unwrap();
    let tree = sleddb::get_tree(db.clone(), "node").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}


#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_node_info_store(){
    let node_info = NodeInfoStore::new("https://electrum.localhost:3021",9090);
    let status = create_node_info(node_info.clone()).unwrap();
    assert!(status);
    let read_node_info_result = read_node_info().unwrap();
    assert_eq!(read_node_info_result.url,node_info.url);
    let status = delete_node_info();
    assert!(status);
  }
}