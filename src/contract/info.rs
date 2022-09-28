
use serde::{Deserialize, Serialize};
use bdk::database::{MemoryDatabase, SqliteDatabase};
use bdk::TransactionDetails;
use bdk::{SyncOptions,Wallet};
use crate::lib::config::WalletConfig;
use crate::lib::e::{ErrorKind, S5Error};

#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction {
  pub timestamp: u64,
  pub height: u32,
  pub txid: String,
  pub received: u64,
  pub sent: u64,
  pub fee: u64,
}
impl Transaction {
  pub fn from_txdetail(txdetail: TransactionDetails) -> Self {
    Transaction {
      timestamp: match txdetail.confirmation_time.clone() {
        Some(time) => time.timestamp,
        None => 0,
      },
      height: match txdetail.confirmation_time.clone() {
        Some(time) => time.height,
        None => 0,
      },
      txid: txdetail.txid.to_string(),
      received: txdetail.received,
      sent: txdetail.sent,
      fee: txdetail.fee.unwrap_or(0),
    }
  }
}


pub fn sqlite_history(config: WalletConfig) -> Result<Vec<Transaction>, S5Error> {
  if config.db_path.is_none(){
    return Err(S5Error::new(ErrorKind::Input, "SQLite Requires a Db Path."));
  } 
  let wallet = match Wallet::new(
    &config.deposit_desc,
    Some(&config.change_desc),
    config.network,
    SqliteDatabase::new(config.db_path.unwrap()),
  ) {
    Ok(result) => result,
    Err(e) => {
      println!("{:#?}", e);
      return Err(S5Error::new(ErrorKind::Internal, &e.to_string()));
    }
  };

  match wallet.list_transactions(false) {
    Ok(history) => Ok(history
        .iter()
        .map(|txdetail| Transaction::from_txdetail(txdetail.clone()))
        .collect(),
    ),
    Err(e) => Err(S5Error::new(ErrorKind::Internal, &e.to_string())),
  }
}


pub fn sqlite_balance(config: WalletConfig) -> Result<bdk::Balance, S5Error> {
  if config.db_path.is_none(){
    return Err(S5Error::new(ErrorKind::Input, "SQLite Requires a Db Path."));
  } 
  let wallet = match Wallet::new(
    &config.deposit_desc,
    Some(&config.change_desc),
    config.network,
    SqliteDatabase::new(config.db_path.unwrap()),
  ) {
    Ok(result) => result,
    Err(e) => {
      println!("{:#?}", e);
      return Err(S5Error::new(ErrorKind::Internal, &e.to_string()));
    }
  };

  match wallet.get_balance() {
    Ok(balance) => Ok(balance),
    Err(e) => Err(S5Error::new(ErrorKind::Internal, &e.to_string())),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::lib::config::{WalletConfig, DEFAULT_TESTNET_NODE};
  use std::{env, path::Path};
  use std::fs;
  use crate::contract::sync;
  use secp256k1::rand::{thread_rng,Rng};
  
  #[test]
  fn test_sqlite_balance() {
    let xkey = "[db7d25b5/84'/1'/6']tpubDCCh4SuT3pSAQ1qAN86qKEzsLoBeiugoGGQeibmieRUKv8z6fCTTmEXsb9yeueBkUWjGVzJr91bCzeCNShorbBqjZV4WRGjz3CrJsCboXUe";
    let descriptor = format!("wpkh({}/*)", xkey);
    let mut rng = thread_rng();
    let random: u16 = rng.gen();
    let db_path: String = env::var("CARGO_MANIFEST_DIR").unwrap() + &random.to_string() + ".db";
    // TEST UNSYNCED
    let config = WalletConfig::new(&descriptor, DEFAULT_TESTNET_NODE, None,Some(db_path.clone())).unwrap();
    let balance = sqlite_balance(config).unwrap();
    let zero: u64 = 0;
    assert_eq!(balance.confirmed==zero, true);

    // TEST SYNCED
    let config = WalletConfig::new(&descriptor, DEFAULT_TESTNET_NODE, None,Some(db_path.clone())).unwrap();
    let status = sync::sqlite(config);
    assert_eq!(
        (),
        status.unwrap()
    );

    let config = WalletConfig::new(&descriptor, DEFAULT_TESTNET_NODE, None,Some(db_path.clone())).unwrap();
    let balance = sqlite_balance(config).unwrap();
    let zero: u64 = 0;
    assert_eq!(balance.confirmed>=zero, true)
  }

  #[test]
  fn test_sqlite_history() {
    let descriptor = "wpkh([db7d25b5/84'/1'/6']tpubDCCh4SuT3pSAQ1qAN86qKEzsLoBeiugoGGQeibmieRUKv8z6fCTTmEXsb9yeueBkUWjGVzJr91bCzeCNShorbBqjZV4WRGjz3CrJsCboXUe/*)";
    
    let mut rng = thread_rng();
    let random: u16 = rng.gen();
    let db_path: String = env::var("CARGO_MANIFEST_DIR").unwrap() + &random.to_string() + ".db";
    
    let config = WalletConfig::new(&descriptor, DEFAULT_TESTNET_NODE, None,Some(db_path.clone())).unwrap();
    // TEST UNSYNCED
    let history = sqlite_history(config).unwrap();
    assert!((history.len()==0));

    let config = WalletConfig::new(&descriptor, DEFAULT_TESTNET_NODE, None,Some(db_path.clone())).unwrap();
    let status = sync::sqlite(config);
    assert_eq!(
        (),
        status.unwrap()
    );

    // TEST SYNCED
    let config = WalletConfig::new(&descriptor, DEFAULT_TESTNET_NODE, None,Some(db_path.clone())).unwrap();
    let history = sqlite_history(config).unwrap();
    assert!((history.len()>0));

    fs::remove_file(Path::new(&db_path))
    .expect("File delete failed");  
  }
  
}