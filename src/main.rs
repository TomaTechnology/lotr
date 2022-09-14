#![allow(dead_code)]
use clap::{App, AppSettings, Arg, Command};
extern crate rpassword;    
use rpassword::read_password;
use std::io::Write;
use bitcoin::network::constants::Network;
#[macro_use] extern crate text_io;

mod config;

mod e;
use crate::e::{ErrorKind};

mod lib;
use crate::lib::sleddb;

mod key;
use crate::key::seed;
use crate::key::child;
use crate::key::ec;

mod cypherpost;
use crate::cypherpost::identity;


fn main() {
    let matches = App::new("\x1b[0;92ml✠tr\x1b[0m")
        .about("\x1b[0;94mLeverage ✠f The Remnants\x1b[0m")
        .version("\x1b[0;1m0.0.1\x1b[0m")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .author("ishi@toma.tech")
        .subcommand(
            Command::new("key")
                .about("Master Key Ops")
                .display_order(3)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    Command::new("generate")
                    .about("Generate a Master Key.")
                    .display_order(0)
                )
                .subcommand(
                    Command::new("import")
                    .about("Import a Master Key From an External Device. *SAFER - NO PRINT*")
                    .display_order(1)
                )
                .subcommand(
                    Command::new("status")
                    .about("Status on whether Master Key exists..")
                    .display_order(2)
                )
                .subcommand(
                    Command::new("delete")
                    .about("Delete Master Key from disk.")
                    .display_order(5) 
                )   
        )
        .subcommand(
            Command::new("chat")
                .about("Messaging Ops")
                .display_order(3)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    Command::new("adminvite")
                    .about("Admin command to generate an invite code for contacts.")
                    .display_order(0)
                    .arg(
                        Arg::with_name("server")
                        .takes_value(true)
                        .short('s')
                        .long("server")
                        .help("Base URL of the server to connect to.")
                    )   
                    .arg_required_else_help(true),  
                )
                .subcommand(
                    Command::new("register")
                    .about("Register your key as a given username.")
                    .display_order(0)
                    .arg(
                        Arg::with_name("server")
                        .takes_value(true)
                        .short('s')
                        .long("server")
                        .help("Base URL of the server to connect to.")
                    )
                    .arg(
                        Arg::with_name("username")
                        .takes_value(true)
                        .short('u')
                        .long("username")
                        .help("Username to register as.")
                    )   
                    .arg(
                        Arg::with_name("invite")
                        .takes_value(true)
                        .short('i')
                        .long("invite")
                        .help("Invite code provided by the admin.")
                    )
                    .arg_required_else_help(true),  
                )
                .subcommand(
                    Command::new("unregister")
                    .about("Unregister your key and username.")
                    .display_order(0)
                    .arg(
                        Arg::with_name("server")
                        .takes_value(true)
                        .short('s')
                        .long("server")
                        .help("Base URL of the server to connect to.")
                    )
                    .arg_required_else_help(true),  
                )
                .subcommand(
                    Command::new("contacts")
                    .about("Get all registered contacts.")
                    .display_order(0)
                    .arg(
                        Arg::with_name("server")
                        .takes_value(true)
                        .short('s')
                        .long("server")
                        .help("Base URL of the server to connect to.")
                    )
                    .arg_required_else_help(true),  
                )
                .subcommand(
                    Command::new("sync")
                    .about("Sync all posts.")
                    .display_order(0)
                    .arg(
                        Arg::with_name("server")
                        .takes_value(true)
                        .short('s')
                        .long("server")
                        .help("Base URL of the server to connect to.")
                    )
                    .arg_required_else_help(true),  
                )
                .subcommand(
                    Command::new("post")
                    .about("Create a post.")
                    .display_order(0)
                    .arg(
                        Arg::with_name("server")
                        .takes_value(true)
                        .short('s')
                        .long("server")
                        .help("Base URL of the server to connect to.")
                    )
                    .arg(
                        Arg::with_name("to")
                        .takes_value(true)
                        .short('t')
                        .long("to")
                        .help("Comma separated list of recipients")
                    )
                    .arg_required_else_help(true),  
                )

        )
        .get_matches();
    
    match matches.subcommand() {
        Some(("key", service_matches)) => {
            match service_matches.subcommand() {
                Some(("generate", _)) => {
                    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
                    let dup_check = key::storage::read(db.clone());
                    match dup_check{
                        Ok(_)=>{
                            println!("===============================================");
                            println!("MASTER KEY ALREADY EXISTS");
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
                                panic!("500");                                
                            }
                        }
                    };
                    print!("Choose a password to encrypt your key: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();   
                    print!("Confirm password: ");
                    std::io::stdout().flush().unwrap();
                    let confirm = read_password().unwrap();  
                    if password != confirm{
                        println!("===============================================");
                        println!("PASSWORDS DO NOT MATCH!");
                        println!("===============================================");
                        panic!("400")
                    }
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
                    let key_store = key::storage::KeyStore::new(child_social,child_money);
                    let encrypted = key_store.encrypt(&password);
                    let status = key::storage::create(db,encrypted).unwrap();
                    if status {
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
                Some(("import", _)) => {
                  let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
                    let dup_check = key::storage::read(db.clone());
                    match dup_check{
                        Ok(_)=>{
                            println!("===============================================");
                            println!("MASTER KEY ALREADY EXISTS");
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
                    };

                    print!("Paste your menmonic seed phrase: ");
                    std::io::stdout().flush().unwrap();
                    let mnemonic = read_password().unwrap();   

                    print!("Choose a password to encrypt your key: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();   
                    print!("Confirm password: ");
                    std::io::stdout().flush().unwrap();
                    let confirm = read_password().unwrap();  
                    if password != confirm{
                        println!("===============================================");
                        println!("PASSWORDS DO NOT MATCH!");
                        println!("===============================================");
                        panic!("400")
                    }

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

                    let key_store = key::storage::KeyStore::new(child_social,child_money);
                    let encrypted = key_store.encrypt(&password);
                
                    let status = key::storage::create(db,encrypted).unwrap();
                    if status {
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


                Some(("status", _)) => {
                    let indexes = sleddb::get_indexes(sleddb::LotrDatabase::MasterKey);
                    println!("===============================================");
                    if indexes.len() > 0 {
                        println!("YOUR KEYS ARE SET.");
                    }
                    else {
                        println!("NO KEYS ARE SET.");
                    }
                    println!("===============================================");
                }
                Some(("delete", _)) => {
                    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
                    let dup_check = key::storage::read(db.clone());
                    match dup_check{
                        Ok(_)=>{
                            
                        }
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");                                
                        }
                    }

                    let status = key::storage::delete(db);
                    if status {
                        println!("===============================================");
                        println!("SUCCESSFULLY DELETED KEYS.");
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

        Some(("chat", service_matches)) => {
            match service_matches.subcommand() {
                Some(("adminvite", sub_matches)) => {
                    let matches =  &sub_matches.clone();
                    let server = matches.value_of("server").unwrap();
                    print!("Enter admin secret key: ");
                    std::io::stdout().flush().unwrap();
                    let admin_secret = read_password().unwrap();   
                    match identity::admin_invite(server, &admin_secret){
                        Ok(result)=>{
                            println!("===============================================");
                            println!("INVITE CODE: {}", result.invite_code);
                            println!("===============================================");
                        }
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");                                
                        }
                    }
                }
                Some(("register", sub_matches)) => {
                    let matches =  &sub_matches.clone();
                    let server = matches.value_of("server").unwrap();
                    let username = matches.value_of("username").unwrap();
                    let invite_code = matches.value_of("invite").unwrap();

                    print!("Enter password to decrypt your key: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();

                    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
                    let keys = match key::storage::read(db.clone()){
                        Ok(keys)=>keys.decrypt(&password),
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");   
                        }
                    };

                    let key_pair = ec::keypair_from_xprv_str(&keys.social).unwrap();

                    match identity::register(server, key_pair, invite_code, username){
                        Ok(result)=>{
                            if result.status{
                                println!("===============================================");
                                println!("SUCESSFULLY REGISTERED AS - {}", username);
                                println!("===============================================");
                            }
                            else{
                                println!("===============================================");
                                println!("REGISTRATION FAILED!");
                                println!("===============================================");
                            }
                        }
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");                                
                        }
                    }
                }
                Some(("unregister", sub_matches)) => {
                    let matches =  &sub_matches.clone();
                    let server = matches.value_of("server").unwrap();
                    print!("Enter password to decrypt your key: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();

                    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
                    let keys = match key::storage::read(db.clone()){
                        Ok(keys)=>keys.decrypt(&password),
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");   
                        }
                    };

                    let key_pair = ec::keypair_from_xprv_str(&keys.social).unwrap();
                    match identity::remove(server, key_pair){
                        Ok(result)=>{
                            if result.status{
                                println!("===============================================");
                                println!("SUCESSFULLY UNREGISTERED");
                                println!("===============================================");
                            }
                            else{
                                println!("===============================================");
                                println!("UNREGISTER FAILED!");
                                println!("===============================================");
                            }
                        }
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");                                
                        }
                    }
                }
                Some(("contacts", sub_matches)) => {
                    let matches =  &sub_matches.clone();
                    let server = matches.value_of("server").unwrap();
                    print!("Enter password to decrypt your key: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();

                    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
                    let keys = match key::storage::read(db.clone()){
                        Ok(keys)=>keys.decrypt(&password),
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");   
                        }
                    };

                    let key_pair = ec::keypair_from_xprv_str(&keys.social).unwrap();
                    match identity::get_all(server, key_pair){
                        Ok(result)=>{
                            let db = sleddb::get_root(sleddb::LotrDatabase::Contacts).unwrap();
                            match cypherpost::storage::create_contacts(db,result.clone().identities){
                                Ok(_)=>{
                                    println!("===============================================");
                                    println!("CONTACTS");
                                    println!("===============================================");

                                    for id in result.identities.into_iter()
                                    {
                                        println!("\x1b[0;92m{}\x1b[0m : {}\n", id.username,id.pubkey)
                                    }
                                    println!("===============================================");
                                }
                                Err(e)=>{
                                    println!("===============================================");
                                    println!("{:#?}",e);
                                    println!("===============================================");
                                    panic!("500"); 
                                }
                            }
                        }
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");                                
                        }
                    }
                }
                Some(("post", sub_matches)) => {
                    let matches =  &sub_matches.clone();
                    let to = matches.value_of("to").unwrap();
                    let to: Vec<String> = to.split(",").map(|s| s.to_string()).collect();
                    let server = matches.value_of("server").unwrap();

                    print!("Enter password to decrypt your key: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();
                    let db = sleddb::get_root(sleddb::LotrDatabase::MasterKey).unwrap();
                    let keys = match key::storage::read(db.clone()){
                        Ok(keys)=>keys.decrypt(&password),
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");   
                        }
                    };

                    print!("Type your message: ");
                    let message: String = read!("{}\n");
                    let key_pair = ec::keypair_from_xprv_str(&keys.social).unwrap();
               
                    let db = sleddb::get_root(sleddb::LotrDatabase::Contacts).unwrap();
                    match cypherpost::storage::read_all_contacts(db){
                        Ok(result)=>{
                            let mut contacts: Vec<cypherpost::identity::CypherpostIdentity> = result.contacts;
                            contacts.retain(|x| {
                                to.contains(&x.username)
                            });
                            println!("{:#?}",contacts);
                            
                        }
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500"); 
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        None => println!("No subcommand was used. try `lotr help`."), 
        _ => unreachable!(),
    }
}
