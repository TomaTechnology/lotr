
use crate::lib::sleddb;
use crate::lib::e::{ErrorKind, S5Error};
use crate::settings::model::{MySettings};

pub fn create(settings: MySettings)->Result<(), S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Settings).unwrap();
    let main_tree = sleddb::get_tree(db, "settings").unwrap();
    // TODO!!! check if tree contains data, do not insert
    let bytes = bincode::serialize(&settings).unwrap();
    main_tree.insert("0", bytes).unwrap();
    Ok(())
}
pub fn read()->Result<MySettings, S5Error>{
    let db = sleddb::get_root(sleddb::LotrDatabase::Settings).unwrap();
    match sleddb::get_tree(db.clone(), "settings"){
        Ok(tree)=>{
            if tree.contains_key(b"0").unwrap() {
            match tree.get("0").unwrap() {
                Some(bytes) => {
                    let key_store: MySettings = bincode::deserialize(&bytes).unwrap();
                    Ok(key_store)
                },
                None => Err(S5Error::new(ErrorKind::Internal, "Error getting value at given index."))
            }
            } else {
            db.drop_tree(&tree.name()).unwrap();
                Err(S5Error::new(ErrorKind::NoResource, "No index found in settings tree"))
            }
        }
        Err(_)=>{
            Err(S5Error::new(ErrorKind::NoResource, "No settings tree."))
        }
    }
}

pub fn delete()->bool{
    let db = sleddb::get_root(sleddb::LotrDatabase::Settings).unwrap();
    let tree = sleddb::get_tree(db.clone(), "settings").unwrap();
    tree.clear().unwrap();
    tree.flush().unwrap();
    db.drop_tree(&tree.name()).unwrap();
    true
}
