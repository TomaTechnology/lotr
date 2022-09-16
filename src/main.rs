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
use crate::cypherpost::notification;
use tungstenite::{Message};

mod contract;

fn main() {
    let matches = App::new("\x1b[0;92ml✠tr\x1b[0m")
        .about("\x1b[0;94mLeverage ✠f The Remnants\x1b[0m")
        .version("\x1b[0;1m0.0.1\x1b[0m")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .author("ishi@toma.tech")
        .subcommand(
            Command::new("guide")
            .about("Display guide. START HERE!")
            .display_order(0)
        )
        .subcommand(
            Command::new("key")
                .about("Master Key Ops")
                .display_order(1)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    Command::new("generate")
                    .about("Generate a Master Key.")
                    .display_order(0)
                    .arg(
                        Arg::with_name("test")
                        .takes_value(true)
                        .short('t')
                        .id("test")
                        .long("test")
                        .takes_value(false)
                        .help("Use testnet")
                    )
                )
                .subcommand(
                    Command::new("import")
                    .about("Import a Master Key From an External Device. *SAFER - NO PRINT*")
                    .display_order(1)
                    .arg(
                        Arg::with_name("test")
                        .takes_value(true)
                        .short('t')
                        .long("test")
                        .takes_value(false)
                        .help("Use testnet")
                    )
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
                .display_order(2)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    Command::new("prefs")
                    .about("Set your preferences with cypherpost.")
                    .display_order(0)
                    .arg(
                        Arg::with_name("server")
                        .takes_value(true)
                        .short('s')
                        .long("server")
                        .help("Base URL of the server to connect to.")
                        .required(false)
                    )
                    .arg(
                        Arg::with_name("last_ds")
                        .takes_value(true)
                        .short('d')
                        .long("last_ds")
                        .help("Last Derivation Scheme Used. Do not set if this is first time usage. The sceheme starts at m/1h/0h. Only use IF you are recovering an account. If unsure of your last scheme, increment the first path - eg. m/2h/0h or m/3h/0h. This is important to ensure forward secrecy.")
                        .required(false)
                    )    
                )
                .subcommand(
                    Command::new("adminvite")
                    .about("Admin command to generate an invite code for contacts.")
                    .display_order(8)
                )
                .subcommand(
                    Command::new("register")
                    .about("Register your key as a given username.")
                    .display_order(1)
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
                    .display_order(7)

                )
                .subcommand(
                    Command::new("contacts")
                    .about("Get all registered contacts.")
                    .display_order(2)
                )
                .subcommand(
                    Command::new("sync")
                    .about("Sync all posts.")
                    .display_order(4)
                )
                .subcommand(
                    Command::new("post")
                    .about("Create a post.")
                    .display_order(3)
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
        .subcommand(
            Command::new("contract")
                .about("Contract Ops")
                .display_order(2)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    Command::new("init")
                    .about("Initialize a lotr contract")
                    .display_order(0) 
                )
                .subcommand(
                    Command::new("info")
                    .about("Info about contract status and history")
                    .display_order(1)

                )
                .subcommand(
                    Command::new("receive")
                    .about("Get an address to receive funds")
                    .display_order(2)
                    .arg(
                        Arg::with_name("label")
                        .takes_value(true)
                        .short('l')
                        .long("label")
                        .help("Name given to the address")
                    )
                    .arg_required_else_help(true),
                )
                .subcommand(
                    Command::new("build")
                    .about("Build a transactions (psbt)")
                    .display_order(3)
                    .arg(
                        Arg::with_name("label")
                        .takes_value(true)
                        .short('l')
                        .long("label")
                        .help("Name given to the psbt")
                    )
                    .arg_required_else_help(true),
                )
                .subcommand(
                    Command::new("check")
                    .about("Check if a psbt is pending signature")
                    .display_order(4)
                )
                .subcommand(
                    Command::new("sign")
                    .about("Sign a psbt")
                    .display_order(5)
                    .arg(
                        Arg::with_name("label")
                        .takes_value(true)
                        .short('l')
                        .long("label")
                        .help("Name given to the psbt")
                    )
                    .arg_required_else_help(true),
                )
                .subcommand(
                    Command::new("broadcast")
                    .about("Broadcast a finalized psbt")
                    .display_order(6)
                    .arg(
                        Arg::with_name("label")
                        .takes_value(true)
                        .short('l')
                        .long("label")
                        .help("Name given to the psbt")
                    )
                    .arg_required_else_help(true),
                )
                .subcommand(
                    Command::new("backup")
                    .about("Backup your contract")
                    .display_order(7)
                    .arg(
                        Arg::with_name("label")
                        .takes_value(true)
                        .short('l')
                        .long("label")
                        .help("Name given to the psbt")
                    )
                    .arg_required_else_help(true),
                )
                .subcommand(
                    Command::new("recover")
                    .about("Recover a contract from a backup")
                    .display_order(8)
                )

        )
        .get_matches();
    
    match matches.subcommand() {
        Some(("key", service_matches)) => {
            match service_matches.subcommand() {
                Some(("generate", sub_matches)) => {
                    let test = sub_matches.args_present();
                    let dup_check = key::storage::read();
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
                    let network = if test {
                        Network::Bitcoin
                    } else{
                        Network::Testnet
                    };

                    let seed = match seed::generate(24, "", network) {
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
                    let key_store = key::model::KeyStore::new(child_social,child_money);
                    let encrypted = key_store.encrypt(&password);
                    let status = key::storage::create(encrypted).unwrap();
                    if status {
                        println!("===============================================");
                        println!("Master Key Details (Create physical backups!):\n");
                        println!("FingerPrint:{}\nMnemonic:{}", seed.fingerprint, seed.mnemonic);
                        println!("===============================================");
                    }
                    else{
                        println!("===============================================");
                        println!("ERROR STORING MASTER KEY: CONTACT ishi@toma.tech");
                        println!("===============================================");

                    }
                }
                Some(("import", sub_matches)) => {
                    let test = sub_matches.args_present();
                    let dup_check = key::storage::read();
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

                    let network = if test {
                        Network::Bitcoin
                    } else{
                        Network::Testnet
                    };

                    let seed = match seed::import(&mnemonic, "", network) {
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

                    let key_store = key::model::KeyStore::new(child_social,child_money);
                    let encrypted = key_store.encrypt(&password);
                
                    let status = key::storage::create(encrypted).unwrap();
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
                    let dup_check = key::storage::read();
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

                    let status = key::storage::delete();
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
                Some(("prefs", sub_matches)) => {
                    let matches =  &sub_matches.clone();
                    let server = matches.value_of("server");
                    let last_ds = matches.value_of("last_ds");

                    let prefs = match cypherpost::storage::read_prefs(){
                        Ok(mut result)=>{
                            //prefs exist
                            result.server = match server {
                                Some(value)=>{
                                    if value.to_string().starts_with("local") {
                                        value.to_string() + ":3021"
                                    }
                                    else if value.to_string().starts_with("http://"){
                                        value.to_string().replace("http://", "")
                                    }
                                    else if value.to_string().starts_with("https://"){
                                        value.to_string().replace("https://", "")
                                    }
                                    else{
                                        value.to_string()
                                    }
                                    
                                },
                                None=>result.server
                            };
                            result.last_ds = match last_ds{
                                Some(value)=>value.to_string(),
                                None=>result.last_ds
                            };
                            result

                        },
                        Err(_)=>{
                            // no prefs set
                            cypherpost::model::ServerPreferences{
                                server: match server {
                                    Some(value)=>value.to_string(),
                                    None=>"localhost:3021".to_string()
                                },
                                last_ds: match last_ds{
                                    Some(value)=>value.to_string(),
                                    None=>"m/1h/0h".to_string()
                                }
                            }

                        }
                    };
                    match cypherpost::storage::create_prefs(prefs.clone()){
                        Ok(result)=>{
                            if result {
                                println!("===============================================");
                                println!("SUCESSFULLY STORED PREFERENCES.");
                                println!("===============================================");
                                println!("SERVER: {}", prefs.server);
                                println!("LAST DERIVATION SCHEME: {}", prefs.last_ds);
                                println!("===============================================");
                            }
                            else{
                                println!("===============================================");
                                println!("FAILED TO STORE PREFERENCES!");
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
                Some(("adminvite", _)) => {
                    let prefs = match cypherpost::storage::read_prefs(){
                        Ok(value)=>value,
                        Err(e)=>{
                            println!("===============================================");
                            println!("SERVER URL NOT SET!");
                            println!("USE lotr chat prefs --server <SERVER_URL>");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");  
                        } 
                    };
                    let server = prefs.server_url_parse(cypherpost::model::ServerKind::Standard);                    
                    print!("Enter admin secret key: ");
                    std::io::stdout().flush().unwrap();
                    let admin_secret = read_password().unwrap();   
                    match identity::admin_invite(&server, &admin_secret){
                        Ok(invite_code)=>{
                            println!("===============================================");
                            println!("INVITE CODE: {}", invite_code);
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
                    let prefs = match cypherpost::storage::read_prefs(){
                        Ok(value)=>value,
                        Err(e)=>{
                            println!("===============================================");
                            println!("SERVER URL NOT SET!");
                            println!("USE lotr chat prefs --server <SERVER_URL>");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");  
                        } 
                    };
                    let server =prefs.server_url_parse(cypherpost::model::ServerKind::Standard);
                    let username = matches.value_of("username").unwrap();
                    let invite_code = matches.value_of("invite").unwrap();

                    print!("Enter password to decrypt your key: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();

                    let keys = match key::storage::read(){
                        Ok(keys)=>keys.decrypt(&password),
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");   
                        }
                    };

                    let key_pair = ec::keypair_from_xprv_str(&keys.social).unwrap();

                    match identity::register(&server, key_pair, invite_code, username){
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
                Some(("unregister", _)) => {
                    let prefs = match cypherpost::storage::read_prefs(){
                        Ok(value)=>value,
                        Err(e)=>{
                            println!("===============================================");
                            println!("SERVER URL NOT SET!");
                            println!("USE lotr chat prefs --server <SERVER_URL>");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");  
                        } 
                    };      
                    let server = prefs.server_url_parse(cypherpost::model::ServerKind::Standard);

                    print!("Enter password to decrypt your key: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();
                    let keys = match key::storage::read(){
                        Ok(keys)=>keys.decrypt(&password),
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");   
                        }
                    };

                    let key_pair = ec::keypair_from_xprv_str(&keys.social).unwrap();
                    match identity::remove(&server, key_pair){
                        Ok(status)=>{
                            if status{
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
                Some(("contacts", _)) => {
                    let prefs = match cypherpost::storage::read_prefs(){
                        Ok(value)=>value,
                        Err(e)=>{
                            println!("===============================================");
                            println!("SERVER URL NOT SET!");
                            println!("USE lotr chat prefs --server <SERVER_URL>");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");  
                        } 
                    };
                    let server = prefs.server_url_parse(cypherpost::model::ServerKind::Standard);                    
                    print!("Enter password to decrypt your key: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();
                    let keys = match key::storage::read(){
                        Ok(keys)=>keys.decrypt(&password),
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");   
                        }
                    };

                    let key_pair = ec::keypair_from_xprv_str(&keys.social).unwrap();
                    match identity::get_all(&server, key_pair){
                        Ok(identities)=>{
                            match cypherpost::storage::create_contacts(identities.clone()){
                                Ok(_)=>{
                                    println!("===============================================");
                                    println!("CONTACTS");
                                    println!("===============================================");

                                    for id in identities.into_iter()
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
                    let prefs = match cypherpost::storage::read_prefs(){
                        Ok(value)=>value,
                        Err(e)=>{
                            println!("===============================================");
                            println!("SERVER URL NOT SET!");
                            println!("USE lotr chat prefs --server <SERVER_URL>");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");  
                        } 
                    };
                    let server = prefs.server_url_parse(cypherpost::model::ServerKind::Standard);                    

                    print!("Enter password to decrypt your key: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();
                    let keys = match key::storage::read(){
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
                    let post = cypherpost::model::PlainPost{
                        kind: cypherpost::model::PostKind::Message,
                        label: None,
                        value: message
                    };

                    let recipients:Vec<cypherpost::model::CypherpostIdentity> = match cypherpost::storage::read_all_contacts(){
                        Ok(result)=>{
                            let mut contacts: Vec<cypherpost::model::CypherpostIdentity> = result.contacts;
                            contacts.retain(|x| {
                                to.contains(&x.username)
                            });
                            contacts
                        }
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500"); 
                        }
                    };

                    let ds_and_cypherpost = cypherpost::handler::create_cypherjson( &keys.social,post).unwrap();
                    let decryption_keys = cypherpost::handler::create_decryption_keys( &keys.social, &ds_and_cypherpost.0, recipients).unwrap();
                    let result = cypherpost::post::create(&server, key_pair, 0, &ds_and_cypherpost.0, &ds_and_cypherpost.1).unwrap();
                    let post_id = result.id;
                    let result = cypherpost::post::keys(&server, key_pair, &post_id, decryption_keys).unwrap();
                    if result.status {
                        // let my_posts = cypherpost::post::my_posts(&server, key_pair).unwrap().posts;
                        // let others_posts = cypherpost::post::others_posts(&server, key_pair).unwrap().posts;
                        // let all_posts = cypherpost::handler::update_and_organize_posts(my_posts, others_posts, &keys.social).unwrap();
                        println!("===============================================");
                        println!("SUCCESSFULLY POSTED!");
                        println!("===============================================");
                    }
                    let ws_url = prefs.server_url_parse(cypherpost::model::ServerKind::Websocket);
                    let mut socket = notification::sync(&ws_url, key_pair).unwrap();
                    socket.write_message(Message::Text(post_id.into())).unwrap();

                }
                Some(("sync", _)) => {
                    let prefs = match cypherpost::storage::read_prefs(){
                        Ok(value)=>value,
                        Err(e)=>{
                            println!("===============================================");
                            println!("SERVER URL NOT SET!");
                            println!("USE lotr chat prefs --server <SERVER_URL>");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");  
                        } 
                    };
                    let server = prefs.server_url_parse(cypherpost::model::ServerKind::Standard);
                    print!("Enter password to decrypt your key: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();
                    let keys = match key::storage::read(){
                        Ok(keys)=>keys.decrypt(&password),
                        Err(e)=>{
                            println!("===============================================");
                            println!("{:#?}",e);
                            println!("===============================================");
                            panic!("500");   
                        }
                    };

                    let key_pair = ec::keypair_from_xprv_str(&keys.social).unwrap();
                    let ws_url = prefs.server_url_parse(cypherpost::model::ServerKind::Websocket);
                    println!("Establishing connection with cypherpost server...");
                    let mut socket = notification::sync(&ws_url, key_pair).unwrap();
                    println!("===============================================");
                    let my_posts = cypherpost::post::my_posts(&server, key_pair).unwrap().posts;
                    let others_posts = cypherpost::post::others_posts(&server, key_pair).unwrap().posts;
                    let all_posts = cypherpost::handler::update_and_organize_posts(my_posts, others_posts, &keys.social).unwrap();
                    for post in all_posts.into_iter(){
                        println!("\x1b[94;1m{}\x1b[0m :: {}", cypherpost::handler::get_username_by_pubkey(&post.owner).unwrap(), post.plain_post.value);
                    }
                    loop {
                        match socket.read_message(){
                            Ok(msg)=>{
                                if msg.to_string().starts_with("s5p"){
                                    let cypherpost_single = cypherpost::post::single_post(&server, key_pair, &msg.to_string()).unwrap();
                                    if cypherpost_single.clone().post.decryption_key.is_some(){
                                        let plain_post = cypherpost::handler::decrypt_others_posts([cypherpost_single.post].to_vec(), &keys.social).unwrap();
                                        println!("\x1b[94;1m{}\x1b[0m :: {}", cypherpost::handler::get_username_by_pubkey(&plain_post[0].owner).unwrap(), plain_post[0].plain_post.value);
                                    }
                                    else{
                                        let plain_post = cypherpost::handler::decrypt_my_posts([cypherpost_single.post].to_vec(), &keys.social).unwrap();
                                        println!("\x1b[94;1m{}\x1b[0m :: {}", cypherpost::handler::get_username_by_pubkey(&plain_post[0].owner).unwrap(), plain_post[0].plain_post.value);
                                    }
                                }
                                else{
                                    println!(
                                        "{:#?}",msg.to_string()
                                    )
                                }
                            }
                            Err(_)=>{
                                socket = notification::sync(&ws_url, key_pair).unwrap()
                            }
                        }



                    }

                }
                _ => unreachable!(),
            }
        }

        Some(("contract", service_matches))=>{
            match service_matches.subcommand() {
                Some(("init", _)) => {
                }
                Some(("info", _)) => {
                }
                Some(("receive", _)) => {
                }
                Some(("build", _)) => {
                }
                Some(("check", _)) => {
                }
                Some(("sign", _)) => {
                }
                Some(("broadcast", _)) => {
                }
                Some(("backup", _)) => {
                }
                Some(("recover", _)) => {
                }
                _ => unreachable!(),
            }
        }
        Some(("guide", _)) => {
            let title = "Leverage ✠f The Remnants";
            let subtitle = "A bitcoin contact co-ordination tool.";
            let p1 = "The 'lotr' tool contains 3 primary commands: key, chat and contract.";
            let p2 = "Start by creating a key pair using the generate sub-command. This command will print your seed onto the screen.";
            let p3 = "If you want a higher level of security, create your seed on a device like a cold card and use the import sub-command instead which will not print to screen but requires typing your seed. You can confirm you typed the right seed by verifying the fingerprint.";
            let p4 = "Your seed words are not saved to the disk; only root xprvs are saved. So make sure you have physical backups of your mnemonics.";
            let p5 = "You must set a password to encrypt your keys at test. We recommend writing this down too.";
            let p6 = "The next step is to setup preferences for a cypherpost chat server using the prefs sub-command.";
            let p7 = "Initially only set a value for --server. last_ds is only required when you are recovering an old account.\nNOTE: chat commands will not work without a server being set.";
            let p8 = "If you are the admin; use adminvite to generate invite codes for other users.";
            let p9 = "After an admin gives you an invite code, use it with the register sub-command.";
            let p10 = "After registering you can view others on the server using the contacts sub-command.";
            let p11 = "You can then post to other users and sync to get all posts related to you.";
            println!("\x1b[93;1m{}\x1b[0m", title);
            println!("{}", subtitle);
            println!("{}", p1);
            println!("\x1b[92;1mkey\x1b[0m",);
            println!("{}", p2);
            println!("{}", p3);
            println!("{}", p4);
            println!("{}", p5);
            println!("\x1b[92;1mchat\x1b[0m",);
            println!("{}", p6);
            println!("{}", p7);
            println!("{}", p8);
            println!("{}", p9);
            println!("{}", p10);
            println!("{}", p11);
            println!("\x1b[92;1mcontract\x1b[0m",);
            println!("COMING SOON!");
        }


        None => println!("No subcommand was used. try `lotr help`."), 
        _ => unreachable!(),
    }
}

