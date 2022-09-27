use sled::{Db, Tree};
// use std::fmt::Display;
use std::env;
use std::str;

pub const STORAGE_ROOT: &str = ".lotr"; // Database

#[derive(Debug,Clone)]
pub enum LotrDatabase{
    MasterKey,
    Identity,
    Members,
    Network,
    Contract,
    Settings,
    Void,
}

impl LotrDatabase{
    pub fn to_string(&self)->String{
        match self{
            LotrDatabase::MasterKey=>"keys".to_string(),
            LotrDatabase::Identity=>"identity".to_string(),
            LotrDatabase::Members=>"members".to_string(),
            LotrDatabase::Settings=>"settings".to_string(),
            LotrDatabase::Network=>"network".to_string(),
            LotrDatabase::Contract=>"contract".to_string(),
            LotrDatabase::Void=>"void".to_string()
        }
    }

}


/// Retrieves the primary data store @ $HOME/.lotr/$db.
pub fn get_root(db: LotrDatabase, filter: Option<String>) -> Result<Db, String> {
    let db_storage_path: String = if filter.is_none(){
        format!("{}/{}/{}", env::var("HOME").unwrap(), STORAGE_ROOT, &db.to_string())
    }
    else{
        format!("{}/{}/{}/{}", env::var("HOME").unwrap(), STORAGE_ROOT, &db.to_string(), &filter.unwrap())
    };
    match sled::open(db_storage_path.clone()) {
        Ok(db) => Ok(db),
        Err(e) =>{
            println!("{:#?}",e);
            Err(format!("E:DB Open @ {} FAILED.", db_storage_path))
        }
    }
}

/// Retrieves a specific tree from the selected db by its index.
/// Client index is uid.
/// Service index is name.
pub fn get_tree(root: Db, index: &str) -> Result<Tree, String> {
    match root.open_tree(index.as_bytes()) {
        Ok(tree) => Ok(tree),
        Err(_) => Err(format!("E:Tree Open @ {} FAILED.", index)),
    }
}

/// Retrives all tree indexes in a db
pub fn get_indexes(lotr_db: LotrDatabase, filter: Option<String>) -> Vec<String>{
    let root = get_root(lotr_db,filter).unwrap();
    let mut unames: Vec<String> = [].to_vec();
    for key in root.tree_names().iter() {
        
        let index = str::from_utf8(key).unwrap();
        if index == "__sled__default"{
            
        }
        else{
            unames.push(index.to_string());
        }
    }
    unames
}