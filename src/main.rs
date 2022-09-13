#![allow(dead_code)]
use clap::{App, AppSettings, Arg, Command};
extern crate rpassword;    
use rpassword::read_password;
use std::io::Write;
use bitcoin::network::constants::Network;

mod mk;
use crate::mk::seed;
use crate::mk::child;

mod e;
use crate::e::{ErrorKind};

mod lib;
use crate::lib::sleddb;


mod config;

fn main() {
    let matches = App::new("\x1b[0;92mlotr\x1b[0m")
        .about("\x1b[0;94mLeverage Of The Remnants\x1b[0m")
        .version("\x1b[0;1m0.0.1\x1b[0m")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .author("ishi@toma.tech")
        .subcommand(
            Command::new("mk")
                .about("Master Key Ops")
                .display_order(3)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    Command::new("generate")
                    .about("Generate a Master Key.")
                    .display_order(0)
                    .arg(
                        Arg::with_name("username")
                        .takes_value(true)
                        .short('u')
                        .long("username")
                        .help("Give your Master Key a username. Username will be used with cypherpost.")
                    )   
                    .arg_required_else_help(true),  
                )
                .subcommand(
                    Command::new("import")
                    .about("Import a Master Key From an External Device. *SAFER - NO PRINT*")
                    .display_order(1)
                    .arg(
                        Arg::with_name("username")
                        .takes_value(true)
                        .short('u')
                        .long("username")
                        .help("Give your Master Key a username. If already registered on cypherpost - username must match.")
                    )   
                    .arg_required_else_help(true),  
                )
                .subcommand(
                    Command::new("status")
                    .about("Status on whether Master Key exists and its associated username.")
                    .display_order(2)
                )
                .subcommand(
                    Command::new("delete")
                    .about("Delete Master Key from disk.")
                    .display_order(5)
                    .arg(
                        Arg::with_name("username")
                        .takes_value(true)
                        .short('u')
                        .long("username")
                        .help("Choose which Master Key to delete by username.")
                    )   
                )   
        )
        .get_matches();
    
    match matches.subcommand() {

        Some(("mk", service_matches)) => {
            match service_matches.subcommand() {
                    Some(("generate", sub_matches)) => {
                        let matches =  &sub_matches.clone();
                        let username = matches.value_of("username").unwrap();
                        print!("Choose a password to encrypt your key: ");
                        std::io::stdout().flush().unwrap();
                        let password = read_password().unwrap();   
                        let seed = match seed::generate(24, "", Network::Bitcoin) {
                            Ok(master_key) => {
                                master_key
                            },
                            Err(e) => {
                                println!("{:?}", e);
                                panic!("500");
                            },
                        };

                        let social_path = "m/128h/0h";
                        let child_social = match child::to_path_str(&seed.xprv,social_path){
                            Ok(keys)=>keys,
                            Err(e)=>{
                                println!("{:?}", e);
                                panic!("500");
                            }
                        };

                        let child_money = match child::to_hardened_account(&seed.xprv,child::DerivationPurpose::Native,0){
                            Ok(keys)=> keys,
                            Err(e)=>{
                                println!("{:?}", e);
                                panic!("500");
                            }
                        };

                        let key_store = mk::storage::KeyStore::new(username,child_social.clone(),child_money.clone());
                        let encrypted = key_store.encrypt(&password);
                        let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
                        let dup_check = mk::storage::read(db.clone(), username);
                        match dup_check{
                            Ok(_)=>{
                                println!("===============================================");
                                println!("MASTER KEY WITH THIS USERNAME ALREADY EXISTS");
                                println!("===============================================");
                                panic!("409");
                            }
                            Err(e)=>{
                                if e.kind == ErrorKind::Input.to_string(){
                                    println!("Creating new master key database...");
                                }
                                else{
                                    println!("===============================================");
                                    println!("{:#?}",e);
                                    println!("===============================================");
                                    panic!("500");                                }
                            }
                        }
                        let status = mk::storage::create(db.clone(),encrypted.clone()).unwrap();
                        if status == true {
                            println!("===============================================");
                            println!("Master Key Details (Create physical backups!):\n");
                            println!("FingerPrint:{:#?}\nMnemonic:{:#?}", seed.fingerprint, seed.mnemonic);
                            println!("===============================================");
                        }
                        else{
                            println!("===============================================");
                            println!("ERROR STORING MASTER KEY: CONTACT ishi@toma.tech");
                            println!("===============================================");

                        }
                    }
                    Some(("import", sub_matches)) => {
                        let matches = &sub_matches.clone();
                        let username = matches.value_of("username").unwrap();

                        print!("Paste your menmonic seed phrase: ");
                        std::io::stdout().flush().unwrap();
                        let mnemonic = read_password().unwrap();   

                        print!("Choose a password to encrypt your key: ");
                        std::io::stdout().flush().unwrap();
                        let password = read_password().unwrap();   

                        let seed = match seed::import(&mnemonic, "", Network::Bitcoin) {
                            Ok(master_key) => {
                                master_key
                            },
                            Err(e) => {
                                println!("{:?}", e);
                                panic!("500");
                            },
                        };

                        let social_path = "m/128h/0h";
                        let child_social = match child::to_path_str(&seed.xprv,social_path){
                            Ok(keys)=>keys,
                            Err(e)=>{
                                println!("{:?}", e);
                                panic!("500");
                            }
                        };

                        let child_money = match child::to_hardened_account(&seed.xprv,child::DerivationPurpose::Native,0){
                            Ok(keys)=> keys,
                            Err(e)=>{
                                println!("{:?}", e);
                                panic!("500");
                            }
                        };

                        let key_store = mk::storage::KeyStore::new(username,child_social.clone(),child_money.clone());
                        let encrypted = key_store.encrypt(&password);
                        let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
                        let dup_check = mk::storage::read(db.clone(), username);
                        match dup_check{
                            Ok(_)=>{
                                println!("===============================================");
                                println!("MASTER KEY WITH THIS USERNAME ALREADY EXISTS");
                                println!("===============================================");
                                panic!("409");
                            }
                            Err(e)=>{
                                if e.kind == ErrorKind::Input.to_string(){
                                    println!("Creating new master key database...");
                                }
                                else{
                                    println!("===============================================");
                                    println!("{:#?}",e);
                                    println!("===============================================");
                                    panic!("500");                                }
                            }
                        }
                        let status = mk::storage::create(db.clone(),encrypted.clone()).unwrap();
                        if status == true {
                            println!("===============================================");
                            println!("Master Key Details:\n");
                            println!("FingerPrint:{:#?}", seed.fingerprint);
                            println!("===============================================");
                        }
                        else{
                            println!("===============================================");
                            println!("ERROR STORING MASTER KEY: CONTACT ishi@toma.tech");
                            println!("===============================================");

                        }
                    }
                    Some(("status", _sub_matches)) => {
                        let usernames = sleddb::get_indexes(sleddb::LotrDatabase::MasterKey);
                        println!("===============================================");
                        println!("The following master keys are saved:\n{:#?}", usernames);
                        println!("===============================================");
                    }
                    Some(("delete", sub_matches)) => {
                        let matches = &sub_matches.clone();
                        let username = matches.value_of("username").unwrap();
                        let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
                        let dup_check = mk::storage::read(db.clone(), username);
                        match dup_check{
                            Ok(_)=>{
                                ()
                            }
                            Err(e)=>{
                                println!("===============================================");
                                println!("{:#?}",e);
                                println!("===============================================");
                                panic!("500");                                
                            }
                        }

                        let status = mk::storage::delete(db.clone(),username);
                        if status == true{
                            println!("===============================================");
                            println!("Successfully deleted master key record: {:#?}", username);
                            println!("===============================================");
                        }
                        else{
                            println!("===============================================");
                            println!("COULD NOT DELETE MASTER KEY DATABASE!");
                            println!("===============================================");
                            panic!("500");  
                        }

                    }
                _ => unreachable!(),
            }
        }
        None => println!("No subcommand was used. try `lotr help`."), 
        _ => unreachable!(),
    }
}
