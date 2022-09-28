#![allow(dead_code)]
#![allow(unused_imports)]
#[macro_use] 
extern crate text_io;

use::std::fs;
use qrcode::{QrCode, Version, EcLevel};
use qrcode::render::unicode;

use clap::{App, AppSettings, Arg, Command};
extern crate rpassword;    
use rpassword::read_password;
use std::io::Write;
use std::fmt::Debug;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{XOnlyPublicKey};

mod lib;
use crate::lib::e::{ErrorKind};
use crate::lib::config::{WalletConfig,DEFAULT_MAINNET_NODE, DEFAULT_TEST_NETWORK, DEFAULT_TESTNET_NODE, DEFAULT_SQLITE};
use crate::lib::sleddb;


mod settings;
use crate::settings::model::{MySettings,ServerKind};
mod key;
use crate::key::ec::{XOnlyPair};
use crate::key::encryption::{nonce};
use crate::key::seed::{self,MasterKeySeed};
use crate::key::child::{self,ChildKeys};

mod network;
use network::identity;
use network::post::{self, model::{Payload,Post,Recipient,DecryptionKey}, dto::{ServerPostRequest, ServerPostModel}};

mod contract;
use crate::contract::model::{ContractKind,InheritanceContract,InheritanceContractPublicData, InheritanceRole,Participant,XPubInfo};

use std::{thread, time};
use tungstenite::{Message};
use tungstenite::protocol::WebSocket;
use tungstenite::stream::MaybeTlsStream;
use std::net::TcpStream;


fn fmt_print(message: &str)->(){
    println!("=========================================================================");
    println!("{}",message);
    println!("=========================================================================");
}
fn fmt_print_struct(message: &str, item: impl Debug)->(){
    println!("=========================================================================");
    println!("{}\n{:#?}",message,item);
    println!("=========================================================================");
}

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");

    let matches = App::new("\x1b[0;92ml✠tr\x1b[0m")
        .about("\x1b[0;94mLeverage ✠f The Remnants\x1b[0m")
        .version("\x1b[0;1mv0.1.3\x1b[0m")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .author("ishi@toma.tech")
        .subcommand(
            Command::new("guide")
            .about("Display guide. START HERE!")
            .display_order(0)
        )
        .subcommand(
            Command::new("setup")
                .about("Configure app settings.")
                .display_order(1) 
        )
        .subcommand(
            Command::new("key")
                .about("Master Key Ops")
                .display_order(2)
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
        )
        .subcommand(
            Command::new("network")
                .about("Network and coordination")
                .display_order(3)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    Command::new("join")
                    .about("Register as a given username.")
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
                    Command::new("aliases")
                    .about("Manage your aliases")
                    .display_order(1) 
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .subcommand(
                        Command::new("list")
                        .about("List your aliases.")
                        .display_order(0) 
                    ) 
                    .subcommand(
                        Command::new("remove")
                        .about("Remove an alias.")
                        .display_order(0) 
                    ) 
                )
                .subcommand(
                    Command::new("members")
                    .about("Get all registered members.")
                    .display_order(2)
                )
                .subcommand(
                    Command::new("sync")
                    .about("Sync all posts.")
                    .display_order(5)
                )
                .subcommand(
                    Command::new("post")
                    .about("Create a post.")
                    .display_order(6)
                )
                .subcommand(
                    Command::new("remove")
                    .about("Remove a post.")
                    .display_order(7)
                )
                .subcommand(
                    Command::new("leave")
                    .about("Unregister your key and username.")
                    .display_order(8)
                )
                .subcommand(
                    Command::new("invite")
                    .about("ADMIN command to generate an invite code for contacts.")
                    .display_order(9)
                )
        )
        .subcommand(
            Command::new("contract")
                .about("Bitcoin Contract/Wallet")
                .display_order(4)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    Command::new("new")
                    .about("Start a new contract")
                    .display_order(0) 
                    .arg(
                        Arg::with_name("kind")
                        .takes_value(true)
                        .short('k')
                        .long("kind")
                        .help("Which kind of contract would you like to create? I(nheritance) or L(oan)")
                    )
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
                    Command::new("info")
                    .about("Info about contract status, balance and history")
                    .display_order(1)
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
                    Command::new("receive")
                    .about("Get an address to receive funds")
                    .display_order(2)
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
                    Command::new("send")
                    .about("Composite build, check, sign and broadcast")
                    .display_order(5)
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
        Some(("setup", _)) => {
            let existing = settings::storage::read();
            if *&existing.is_err() {
                let error = existing.clone().err().unwrap();
                if error.kind == ErrorKind::NoResource.to_string() {
                    // promt new settings
                    fmt_print("CREATING NEW SETTINGS>>>");
                    print!("Set a password to encrypt sensitve data: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();   
                    print!("Confirm password: ");
                    std::io::stdout().flush().unwrap();
                    let confirm = read_password().unwrap();  
                    if password != confirm{
                        fmt_print("PASSWORDS DO NOT MATCH!");
                        return
                    }
                    print!("Enter your network host (default: localhost:3021): ");
                    let mut network_host: String = read!("{}\n");
                    if network_host == "" || network_host == " "{
                        network_host = DEFAULT_TEST_NETWORK.to_string();
                    }
                    print!("Enter your bitcoin node host (default: Blockstream Testnet): ");
                    let mut bitcoin_host: String = read!("{}\n");
                    if bitcoin_host == "" || bitcoin_host == " "{
                        bitcoin_host = DEFAULT_TESTNET_NODE.to_string();
                    }    
                    let my_settings = MySettings::new(network_host, bitcoin_host, password);
                    settings::storage::create(my_settings.clone()).unwrap();
                    fmt_print_struct("CREATED NEW SETTINGS!",my_settings);
                }
                else{
                    println!("INTERNAL ERROR: {}", error.message)
                }
            }
            else {
                // prompt update settings
                fmt_print("UPDATING EXISTING SETTINGS>>>");
                let mut my_settings = existing.unwrap();
                print!("Enter your network host ({}): ",my_settings.clone().network_host);
                let network_host: String = read!("{}\n");
                if network_host == "" || network_host == " "{}
                else{
                    my_settings.network_host = network_host;
                }
                print!("Enter your bitcoin node host ({}): ",my_settings.bitcoin_host);
                let bitcoin_host: String = read!("{}\n");
                if bitcoin_host != "" || bitcoin_host != " "{}
                else{
                    my_settings.bitcoin_host = bitcoin_host;
                }

                settings::storage::create(my_settings.clone()).unwrap();
                fmt_print_struct("UPDATED!",my_settings);
            }
        }
        Some(("key", service_matches)) => {
            match service_matches.subcommand() {
                Some(("generate", sub_matches)) => {
                    let settings = match settings::storage::read(){
                        Ok(value)=>value,
                        Err(e)=>{
                            if e.kind == ErrorKind::NoResource.to_string(){
                                fmt_print("SETTINGS REQUIRED!");
                                return;
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                                return;
                            }
                        } 
                    };
                    let test = sub_matches.args_present();
                    let network = if test {
                        Network::Testnet
                    } else{
                        Network::Bitcoin
                    };
                    print!("Enter your password: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();
                    if !settings.check_password(password.clone()) {
                        fmt_print("BAD PASSWORD");
                        return;

                    }

                    let dup_check = key::storage::read_keys(password.clone(), network);
                    match dup_check{
                        Ok(_)=>{
                            println!("===============================================");
                            println!("MASTER KEY ALREADY EXISTS");
                            println!("===============================================");
                            return;                              
                        }
                        Err(e)=>{
                            if e.kind == ErrorKind::Input.to_string(){
                                println!("Creating new master key database...");
                            }
                            else{
                                println!("===============================================");
                                println!("ERROR::{}",e.message);
                                println!("===============================================");
                                return;                              
                            }
                        }
                    };

                    let seed = match seed::generate(24, "", network) {
                        Ok(master_key) => {
                            master_key
                        },
                        Err(e) => {
                            println!("{:?}", e);
                            return;                              
                        },
                    };

                    match key::storage::create_keys(password.clone(), seed.clone(), network){
                        Ok(_)=>{
                            println!("===============================================");
                            println!("Master Key Details (Create physical backups!):\n");
                            println!("FingerPrint:{}\nMnemonic:{}", seed.fingerprint, seed.mnemonic);
                            println!("===============================================");
                        }
                        Err(_)=>{
                            println!("===============================================");
                            println!("ERROR STORING MASTER KEY: CONTACT ishi@toma.tech");
                            println!("===============================================");
                            return;
                        }
                    };

                }
                Some(("import", sub_matches)) => {
                    let settings = match settings::storage::read(){
                        Ok(value)=>value,
                        Err(e)=>{
                            if e.kind == ErrorKind::NoResource.to_string(){
                                fmt_print("SETTINGS REQUIRED!");
                                return;
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                                return;
                            }
                        } 
                    };
                    let test = sub_matches.args_present();
                    let network = if test {
                        Network::Testnet
                    } else{
                        Network::Bitcoin
                    };
                    print!("Enter your password: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();
                    if !settings.check_password(password.clone()) {
                        fmt_print("BAD PASSWORD");
                        return;

                    }

                    let dup_check = key::storage::read_keys(password.clone(), network);
                    match dup_check{
                        Ok(_)=>{
                            println!("===============================================");
                            println!("MASTER KEY ALREADY EXISTS");
                            println!("===============================================");
                            return;                              
                        }
                        Err(e)=>{
                            if e.kind == ErrorKind::Input.to_string(){
                                println!("Creating new master key database...");
                            }
                            else{
                                println!("===============================================");
                                println!("ERROR::{}",e.message);
                                println!("===============================================");
                                return;                              
                            }
                        }
                    };

                    print!("Paste your menmonic seed phrase: ");
                    std::io::stdout().flush().unwrap();
                    let mnemonic = read_password().unwrap();   

                    let seed = match seed::import(&mnemonic, "", network) {
                        Ok(master_key) => {
                            master_key
                        },
                        Err(e) => {
                            println!("{:?}", e);
                            panic!("500");
                        },
                    };
                    match key::storage::create_keys(password.clone(), seed.clone(), network){
                        Ok(_)=>{
                            println!("===============================================");
                            println!("Master Key Details (Create physical backups!):\n");
                            println!("FingerPrint:{}\nMnemonic:{}", seed.fingerprint, seed.mnemonic);
                            println!("===============================================");
                            return;
                        }
                        Err(_)=>{
                            println!("===============================================");
                            println!("ERROR STORING MASTER KEY: CONTACT ishi@toma.tech");
                            println!("===============================================");
                            return;
                        }
                    }
                }
                Some(("status", _)) => {
                    let bitcoin = Network::Bitcoin;
                    let testnet = Network::Testnet;
                    let indexes = sleddb::get_indexes(sleddb::LotrDatabase::MasterKey,Some(bitcoin.clone().to_string()));
                    println!("===============================================");
                    if indexes.len() > 0 {
                        println!("YOUR {} KEYS ARE SET.", bitcoin.clone().to_string().to_uppercase());
                    }
                    else {
                        println!("NO {} KEYS ARE SET.",bitcoin.clone().to_string().to_uppercase() );
                    }
                    println!("===============================================");

                    let indexes = sleddb::get_indexes(sleddb::LotrDatabase::MasterKey,Some(testnet.clone().to_string()));
                    println!("===============================================");
                    if indexes.len() > 0 {
                        println!("YOUR {} KEYS ARE SET.", testnet.clone().to_string().to_uppercase());
                    }
                    else {
                        println!("NO {} KEYS ARE SET.",testnet.clone().to_string().to_uppercase() );
                    }
                    println!("===============================================");
                }
                Some(("delete", sub_matches)) => {
                    let test = sub_matches.args_present();
                    let network = if test {
                        Network::Testnet
                    } else{
                        Network::Bitcoin
                    };
                   
                    let status = key::storage::delete_keys(network);
                    if status {
                        println!("===============================================");
                        println!("SUCCESSFULLY DELETED {} KEYS.", network.to_string().to_uppercase());
                        println!("===============================================");
                    }
                    else{
                        println!("===============================================");
                        println!("COULD NOT DELETE MASTER KEY!");
                        println!("===============================================");
                        return;
                    }

                }
                _ => unreachable!(),
            }
        }
        Some(("network", service_matches)) => {
            match service_matches.subcommand() {
                Some(("invite", _)) => {
                    let settings = match settings::storage::read(){
                        Ok(value)=>value,
                        Err(e)=>{
                            fmt_print_struct("ERRORED!",e);
                            return;
                        } 
                    };
                    let host = settings.network_url_parse(ServerKind::Standard);                    
                    print!("Enter admin secret key: ");
                    std::io::stdout().flush().unwrap();
                    let admin_secret = read_password().unwrap();
                    match identity::dto::admin_invite(&host, &admin_secret){
                        Ok(invite_code)=>{
                            fmt_print(&format!("INVITE CODE: {}", invite_code));
                        }
                        Err(e)=>{
                            fmt_print_struct("ERRORED!",e);
                        }
                    }     
                }
                Some(("join", sub_matches)) => {
                    let test = sub_matches.args_present();
                    let network = if test {
                        Network::Testnet
                    } else{
                        Network::Bitcoin
                    };
                    let settings = match settings::storage::read(){
                        Ok(value)=>value,
                        Err(e)=>{
                            if e.kind == ErrorKind::NoResource.to_string(){
                                fmt_print("SETTINGS REQUIRED!");
                                return;
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                                return;
                            }
                        } 
                    };
                    let host = settings.network_url_parse(ServerKind::Standard);   
                                     
                    print!("Enter your password: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();   

                    if !settings.check_password(password.clone()) {
                        fmt_print("BAD PASSWORD");
                        return;
                    }

                    let seed = match key::storage::read_keys(password.clone(), network)
                    {
                        Ok(seed)=>{
                            seed                          
                        }
                        Err(_)=>{
                            println!("===============================================");
                            println!("NO KEYS FOUND. USE lotr key generate/import");
                            println!("===============================================");
                            return;                              
                        }
                    };

                    print!("Choose a unique username (12 alphanumeric characters only): ");
                    let username: String = read!("{}\n");

                    print!("Paste your invite code: ");
                    std::io::stdout().flush().unwrap();
                    let invite_code = read_password().unwrap();

                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if existing_users.clone().contains(&username.clone()){
                        fmt_print("USER ALREADY EXISTS");
                        return
                    }
                    if &existing_users.clone().len() > &0 {
                        fmt_print_struct("Existing Local Users:", existing_users.clone());
                    } 

                    let identity = identity::model::UserIdentity::new(username.clone(), existing_users.clone().len() as u64, seed.xprv);
                    let keypair = XOnlyPair::from_xprv(identity.social_root);
                    
                    match identity::dto::register(&host, keypair, &invite_code, &username){
                        Ok(_)=>{
                            identity::storage::create_my_identity(settings.clone().network_host, identity.clone(),password.clone()).unwrap();
                            fmt_print("USER REGISTERED!");
                        }
                        Err(e)=>{
                            if e.kind == ErrorKind::Input.to_string(){
                                fmt_print("BAD INPUTS!\nCheck the username and invite code used!");
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                            }
                        }
                    }  
                }
                Some(("aliases", sub_matches)) => {
                    match sub_matches.subcommand(){
                        Some(("list", _))=>{
                            let settings = match settings::storage::read(){
                                Ok(value)=>value,
                                Err(e)=>{
                                    if e.kind == ErrorKind::NoResource.to_string(){
                                        fmt_print("SETTINGS REQUIRED!");
                                        return;
                                    }
                                    else{
                                        fmt_print_struct("ERRORED!",e);
                                        return;
                                    }
                                } 
                            };
                            let aliases = identity::storage::get_username_indexes(settings.clone().network_host);
                            if &aliases.len() > &0 {
                                fmt_print_struct("Existing aliases:", aliases.clone());
                            }
                            else{
                                fmt_print("You have 0 existing aliases!");
                            }
                        }
                        Some(("remove", _))=>{
                            let settings = match settings::storage::read(){
                                Ok(value)=>value,
                                Err(e)=>{
                                    if e.kind == ErrorKind::NoResource.to_string(){
                                        fmt_print("SETTINGS REQUIRED!");
                                        return;
                                    }
                                    else{
                                        fmt_print_struct("ERRORED!",e);
                                        return;
                                    }
                                } 
                            };
                            let aliases = identity::storage::get_username_indexes(settings.clone().network_host);
                            if &aliases.len() > &0 {
                                fmt_print_struct("Existing aliases:", aliases.clone());
                            }
                            else{
                                fmt_print("You have 0 existing aliases!");
                                return
                            }
                            let settings = match settings::storage::read(){
                                Ok(value)=>value,
                                Err(e)=>{
                                    if e.kind == ErrorKind::NoResource.to_string(){
                                        fmt_print("SETTINGS REQUIRED!");
                                        return;
                                    }
                                    else{
                                        fmt_print_struct("ERRORED!",e);
                                        return;
                                    }
                                } 
                            };
                            let host = settings.network_url_parse(ServerKind::Standard);                    

                            print!("Enter your password: ");
                            std::io::stdout().flush().unwrap();
                            let password = read_password().unwrap();   

                            if !settings.check_password(password.clone()) {
                                fmt_print("BAD PASSWORD");
                                return;

                            }

                            print!("Enter username/alias to remove: ");
                            let username: String = read!("{}\n");
                            if aliases.contains(&username.clone()){
                                let identity = match identity::storage::read_my_identity(settings.clone().network_host,username.clone(), password){
                                    Ok(id)=>id,
                                    Err(e)=>{
                                        fmt_print_struct("ERRORED!",e);
                                        return;
                                    }
                                };
                                match identity::dto::remove(&host, identity.to_xonly_pair()){
                                    Ok(_)=>{
                                        identity::storage::delete_my_identity(settings.clone().network_host,username);
                                        fmt_print("ALIAS REMOVED!");
                                    }
                                    Err(e)=>{
                                        fmt_print_struct("ERRORED!",e);
                                    }
                                }  
                                return
                            }
                            else{
                                return
                            }
        
                        }
                        _ => unreachable!(),
                    }
                }
                Some(("members", _)) => {
                    let settings = match settings::storage::read(){
                        Ok(value)=>value,
                        Err(e)=>{
                            if e.kind == ErrorKind::NoResource.to_string(){
                                fmt_print("SETTINGS REQUIRED!");
                                return;
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                                return;
                            }
                        } 
                    };
                    let host = settings.network_url_parse(ServerKind::Standard);                    
                    print!("Enter your password: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();   

                    if !settings.check_password(password.clone()) {
                        fmt_print("BAD PASSWORD");
                        return;

                    }

                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if existing_users.len() < 1{
                        fmt_print("NO USERS REGISTERED!");
                        return;
                    }
                    print!("Which alias to use ({}): ",existing_users.clone()[0]);
                    let mut username: String = read!("{}\n");
                    if username == "" || username == " "{
                        username = existing_users[0].clone();
                    }
                    else if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }
                    
                    let identity = identity::storage::read_my_identity(settings.clone().network_host,username, password).unwrap();
                    let keypair = XOnlyPair::from_xprv(identity.social_root);
                    match identity::dto::get_all(&host, keypair){
                        Ok(members)=>{
                            network::identity::storage::create_members(settings.clone().network_host,members.clone()).unwrap();
                            println!("===============================================");
                            println!("MEMBERS:");
                            println!("===============================================");
                            for id in members.into_iter()
                            {
                                println!("\x1b[0;92m{}\x1b[0m:{}\n", id.username,id.pubkey.to_string());
                            }
                            println!("===============================================");
                        }
                        Err(e)=>{
                            fmt_print_struct("ERRORED!",e);
                        
                        }
                    }  
                }
                Some(("post", _)) => {
                    let settings = match settings::storage::read(){
                        Ok(value)=>value,
                        Err(e)=>{
                            if e.kind == ErrorKind::NoResource.to_string(){
                                fmt_print("SETTINGS REQUIRED!");
                                return;
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                                return;
                            }
                        } 
                    };
                    let host = settings.network_url_parse(ServerKind::Standard);                    
                    print!("Enter your password: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();   

                    if !settings.check_password(password.clone()) {
                        fmt_print("BAD PASSWORD");
                        return;

                    }

                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if existing_users.len() < 1{
                        fmt_print("NO USERS REGISTERED!");
                        return;
                    }
                    print!("Which alias to use ({}): ",existing_users.clone()[0]);
                    let mut username: String = read!("{}\n");
                    if username == "" || username == " "{
                        username = existing_users[0].clone();
                    }
                    else if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }
                    
                    if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }

                    print!("To (separate multiple recievers by comma): ");
                    let to: String = read!("{}\n");
                    let to: Vec<String> = to.split(",").map(|s| s.to_string().replace(" ", "")).collect();

                    print!("Message: ");
                    let message: String = read!("{}\n");

                    let to: Vec<XOnlyPublicKey> = match network::identity::storage::read_all_members(settings.clone().network_host)
                    {
                        Ok(mut result)=>{
                            result.retain(|x| {
                                to.contains(&x.username)
                            });
                            let xonly_pubs = result.into_iter().map(|item| item.pubkey).collect();
                            xonly_pubs
                        }
                        Err(e)=>{
                            println!("===============================================");
                            println!("ERROR::{}",e.message);
                            println!("===============================================");
                            return;
                        }
                    };

                    let recipient = if to.len() == 1  {
                        Recipient::Direct(to[0])
                    }
                    else {
                        Recipient::Group(key::encryption::nonce())
                    };

                    let mut identity = identity::storage::read_my_identity(settings.clone().network_host,username, password.clone()).unwrap();
                    let keypair = XOnlyPair::from_xprv(identity.social_root);

                    let message_to_share = Payload::Message(message);
                    let post = Post::new(recipient, message_to_share, keypair.clone()); 
                    let encryption_key = identity.derive_encryption_key();
                    let cypher_json = post.to_cypher(encryption_key.clone());
                    let cpost_req = ServerPostRequest::new(0, &identity.last_path,&cypher_json);

                    let post_id = match network::post::dto::create(&host, keypair.clone(),cpost_req){
                        Ok(id)=>{
                            network::identity::storage::create_my_identity(settings.clone().network_host,identity.clone(), password).unwrap();
                            id
                        }
                        Err(e)=>{
                            if e.kind == ErrorKind::Input.to_string(){
                                fmt_print("BAD INPUTS!\nCheck the username and invite code used!");
                                return
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                                return
                            }
                        }
                    };

                    let decryption_keys = DecryptionKey::make_for_many(keypair.clone(),to,encryption_key).unwrap();
                    match network::post::dto::keys(&host, keypair.clone(), &post_id, decryption_keys){
                        Ok(_)=>{
                            fmt_print("SUCCESSFULLY POSTED!");
                            let ws_url = settings.network_url_parse(ServerKind::Websocket);
                            let mut socket = network::notification::dto::sync(&ws_url, keypair).unwrap();
                            let one_sec = time::Duration::from_millis(1000);                            
                            thread::sleep(one_sec);
                            socket.write_message(Message::Text(post_id.into())).unwrap();
                            ()
                        }
                        Err(e)=>{
                            if e.kind == ErrorKind::Input.to_string(){
                                fmt_print("BAD INPUTS!\nCheck the username and invite code used!");
                                return
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                                return
                            }
                        }
                    }

                }
                Some(("sync", _)) => {
                    let settings = match settings::storage::read(){
                        Ok(value)=>value,
                        Err(e)=>{
                            if e.kind == ErrorKind::NoResource.to_string(){
                                fmt_print("SETTINGS REQUIRED!");
                                return;
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                                return;
                            }
                        } 
                    };
                    let ws_host = settings.network_url_parse(ServerKind::Websocket);      
                    let host = settings.network_url_parse(ServerKind::Standard);                    
              
                    print!("Enter your password: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();   

                    if !settings.check_password(password.clone()) {
                        fmt_print("BAD PASSWORD");
                        return;
                    }

                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if existing_users.len() < 1{
                        fmt_print("NO USERS REGISTERED!");
                        return;
                    }
                    print!("Which alias to use ({}): ",existing_users.clone()[0]);
                    let mut username: String = read!("{}\n");
                    if username.clone() == "" || username.clone() == " "{
                        username = existing_users[0].clone();
                    }
                    else if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }
                    
                    if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }
                    let identity = identity::storage::read_my_identity(settings.clone().network_host,username.clone(), password.clone()).unwrap();
                    let keypair = XOnlyPair::from_xprv(identity.social_root);
                    println!("Establishing connection with cypherpost server...");
                    let mut socket = network::notification::dto::sync(&ws_host, keypair.clone()).unwrap();
                    println!("===============================================");
                    let all_posts = network::post::dto::get_all_posts(&host, identity.social_root,None).unwrap();
                    let members = match identity::dto::get_all(&host, keypair.clone()){
                        Ok(members)=>{
                            network::identity::storage::create_members(settings.clone().network_host,members.clone()).unwrap();
                            members
                        }
                        Err(e)=>{
                            fmt_print_struct("ERRORED!",e);
                            return;
                        }
                    };
                    for post in all_posts.into_iter(){
                        match post.clone().post.payload{
                            Payload::Ping=>{
                                println!("\x1b[94;1m{}\x1b[0m :: {}",network::identity::storage::get_username_by_pubkey(members.clone(), post.owner).unwrap(), post.post.payload.to_string())
                            }
                            Payload::ChecksumPong(_)=>{
                                println!("\x1b[94;1m{}\x1b[0m :: {}",network::identity::storage::get_username_by_pubkey(members.clone(), post.owner).unwrap(), post.post.payload.to_string())
                            }
                            Payload::Message(_)=>{
                                println!("\x1b[94;1m{}\x1b[0m :: {}",network::identity::storage::get_username_by_pubkey(members.clone(), post.owner).unwrap(), post.post.payload.to_string())
                            }
                            Payload::StartInheritance(data)=>{
                                let sender = network::identity::storage::get_username_by_pubkey(members.clone(), post.owner).unwrap();
                                println!("\x1b[94;1m{}\x1b[0m :: {}\n({})",sender, data.clone().id,post.clone().id);
                                let network = if data.counter_party.to_full_xkey().contains("xpub"){
                                    Network::Bitcoin
                                }
                                else{
                                    Network::Testnet
                                };
                                if post.owner == keypair.clone().pubkey{
                                    ()
                                }
                                else{
                                    match update_contract(
                                        network.clone(), 
                                        settings.clone(),
                                        host.clone() , 
                                        username.clone(), 
                                        password.clone(), 
                                        data.clone(), 
                                        sender, 
                                        post.owner
                                    ){
                                        Ok(post_id)=>{
                                            let one_sec = time::Duration::from_millis(1000);                            
                                            thread::sleep(one_sec);
                                            socket.write_message(Message::Text(post_id.into())).unwrap();
                                        }
                                        Err(_)=>{
                                            ()
                                        }
                                    };
                                }
                            }

                        }
                    }
                    loop {
                        match socket.read_message(){
                            Ok(msg)=>{
                                if msg.to_string().starts_with("s5p"){
                                    let cypherpost_single = network::post::dto::single_post(&host, keypair.clone(), &msg.to_string()).unwrap();
                                    let post = cypherpost_single.decypher(identity.social_root).unwrap();
                                    match post.clone().post.payload{
                                        Payload::Ping=>{
                                            println!("\x1b[94;1m{}\x1b[0m :: {}",network::identity::storage::get_username_by_pubkey(members.clone(), post.owner).unwrap(), post.post.payload.to_string())
                                        }
                                        Payload::ChecksumPong(_)=>{
                                            println!("\x1b[94;1m{}\x1b[0m :: {}",network::identity::storage::get_username_by_pubkey(members.clone(), post.owner).unwrap(), post.post.payload.to_string())
                                        }
                                        Payload::Message(_)=>{
                                            println!("\x1b[94;1m{}\x1b[0m :: {}",network::identity::storage::get_username_by_pubkey(members.clone(), post.owner).unwrap(), post.post.payload.to_string())
                                        }
                                        Payload::StartInheritance(data)=>{
                                            let sender = network::identity::storage::get_username_by_pubkey(members.clone(), post.owner).unwrap();
                                            println!("\x1b[94;1m{}\x1b[0m :: {}\n({})",sender, data.clone().id,post.clone().id);
                                            let network = if data.counter_party.to_full_xkey().contains("xpub"){
                                                Network::Bitcoin
                                            }
                                            else{
                                                Network::Testnet
                                            };
                                            if post.owner == keypair.clone().pubkey{
                                                ()
                                            }
                                            else{
                                                match update_contract(
                                                    network.clone(), 
                                                    settings.clone(),
                                                    host.clone() , 
                                                    username.clone(), 
                                                    password.clone(), 
                                                    data.clone(), 
                                                    sender, 
                                                    post.owner
                                                ){
                                                    Ok(post_id)=>{
                                                        let one_sec = time::Duration::from_millis(1000);                            
                                                        thread::sleep(one_sec);
                                                        socket.write_message(Message::Text(post_id.into())).unwrap();
                                                    }
                                                    Err(_)=>{
                                                        ()
                                                    }
                                                };
                                            }

                                        }
            
                                    }
                                }
                                else{
                                    println!(
                                        "{:#?}",msg.to_string()
                                    )
                                }
                            }
                            Err(_)=>{
                                socket = network::notification::dto::sync(&ws_host, keypair.clone()).unwrap()
                            }
                        }
                    }
 
                }
                Some(("remove", _)) => {

                    let settings = match settings::storage::read(){
                        Ok(value)=>value,
                        Err(e)=>{
                            if e.kind == ErrorKind::NoResource.to_string(){
                                fmt_print("SETTINGS REQUIRED!");
                                return;
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                                return;
                            }
                        } 
                    };
                    let host = settings.network_url_parse(ServerKind::Standard);   
                                     
                    print!("Enter your password: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();   

                    if !settings.check_password(password.clone()) {
                        fmt_print("BAD PASSWORD");
                        return;
                    }

                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if existing_users.len() < 1{
                        fmt_print("NO USERS REGISTERED!");
                        return;
                    }
                    print!("Which alias to use ({}): ",existing_users.clone()[0]);
                    let mut username: String = read!("{}\n");
                    if username == "" || username == " "{
                        username = existing_users[0].clone();
                    }
                    else if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }
                    
                    if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }

                    print!("Enter post id to delete: ");
                    let post_id: String = read!("{}\n");

                    let identity = identity::storage::read_my_identity(settings.clone().network_host,username.clone(), password.clone()).unwrap();
                    let keypair = XOnlyPair::from_xprv(identity.social_root);

                    match post::dto::remove(&host, keypair, &post_id){
                        Ok(_)=>{
                            fmt_print("POST DELETED!");
                        }
                        Err(e)=>{
                            if e.kind == ErrorKind::Input.to_string(){
                                fmt_print("BAD INPUTS!\nCheck your username &| post_id");
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                            }
                        }
                    }  
                }
                
                _ => unreachable!(),
            }
        }
        Some(("contract", service_matches))=>{
            match service_matches.subcommand() {
                Some(("new", sub_matches)) => {
                    let test = sub_matches.args_present();
                    let network = if test {
                        Network::Testnet
                    } else{
                        Network::Bitcoin
                    };
                
                    let settings = match settings::storage::read(){
                        Ok(value)=>value,
                        Err(e)=>{
                            fmt_print_struct("ERRORED!",e);
                            return;
                        } 
                    };
                    let host = settings.network_url_parse(ServerKind::Standard); 
                    print!("Enter your password: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();   
                    if !settings.check_password(password.clone()) {
                        fmt_print("BAD PASSWORD");
                        return;
                    }

                    let seed = match key::storage::read_keys(password.clone(), network)
                    {
                        Ok(seed)=>{
                            seed                          
                        }
                        Err(_)=>{
                            println!("===============================================");
                            println!("NO KEYS FOUND. USE lotr key generate/import");
                            println!("===============================================");
                            return;                              
                        }
                    };

                    // currently we reuse the same account from seed for all contracts. 
                    // change this in production
                    let child = child::to_hardened_account(seed.clone().xprv, child::DerivationPurpose::Native, 0).unwrap();
                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if existing_users.len() < 1{
                        fmt_print("NO USERS REGISTERED!");
                        return;
                    }
                    print!("Which alias to use ({}): ",existing_users.clone()[0]);
                    let mut username: String = read!("{}\n");
                    if username == "" || username == " "{
                        username = existing_users[0].clone();
                    }
                    else if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }

                    print!("What is your role in this contract (P)arent or (C)hild)?");
                    let role: String = read!("{}\n");   
                    let role = InheritanceRole::from_str(&role).unwrap();

                    print!("Choose an account number?");
                    let account: String = read!("{}\n");   
                    let account = account.parse::<u64>().unwrap();

                    let timelock = 100;
                    let counter_party_alias: String;
                    // get curent block height and add timelock
                    let id = "s5wid".to_string() + &nonce();
                    let xpub_info = XPubInfo::new(
                        child.fingerprint,
                        account,
                        child.xpub
                    );

                    let contract = match role {
                        InheritanceRole::Parent=>{
                            print!("Who is the child (must be a registered username)?");
                            counter_party_alias = read!("{}\n");  
                            InheritanceContract::new_as_parent(
                                username.clone(), 
                                id,
                                child.xprv, 
                                Participant::new(
                                    username.clone(),
                                    Some(xpub_info.clone())
                                ), 
                                counter_party_alias.clone(),
                                timelock
                            )
                        }
                        InheritanceRole::Child=>{
                            print!("Who is the parent (must be a registered username)?");
                            counter_party_alias = read!("{}\n");  
                            InheritanceContract::new_as_child(
                                username.clone(), 
                                id,
                                child.xprv, 
                                Participant::new(
                                    username.clone(),
                                    Some(xpub_info.clone())
                                ), 
                                counter_party_alias.clone(),
                                timelock
                            )
                        }
                    };

                    // SAVE CONTRACT TO DISK
                    contract::storage::store_inheritance_contract(
                        username.clone(),
                        contract.clone().id,password.clone(),
                        contract.clone()
                    ).unwrap();
                    // baesd on contract.role, send message to counter_party_alias with id & XPubInfo

                    let to: Vec<XOnlyPublicKey> = match network::identity::storage::read_all_members(settings.clone().network_host)
                    {
                        Ok(mut result)=>{
                            result.retain(|x| x.username == counter_party_alias);
                            let xonly_pubs = result.into_iter().map(|item| item.pubkey).collect();
                            xonly_pubs
                        }
                        Err(e)=>{
                            fmt_print_struct("ERRORED!", e);
                            return;
                        }
                    };

                    let recipient = Recipient::Group(contract.clone().id);        
                    let mut identity = identity::storage::read_my_identity(settings.clone().network_host,username, password.clone()).unwrap();
                    let keypair = XOnlyPair::from_xprv(identity.social_root);
                    
                    let message_to_share = Payload::StartInheritance(
                        InheritanceContractPublicData::new(
                            contract.name, 
                            contract.id, 
                            contract.role,
                            xpub_info.clone(),
                            contract.timelock
                        )
                    );
                     
                    let post = Post::new(recipient, message_to_share, keypair.clone()); 
                    let encryption_key = identity.derive_encryption_key();
                    let cypher_json = post.to_cypher(encryption_key.clone());
                    let cpost_req = ServerPostRequest::new(0, &identity.last_path,&cypher_json);

                    let post_id = match network::post::dto::create(&host, keypair.clone(),cpost_req){
                        Ok(id)=>{
                            // need to create identity again to update encryption derivation path
                            network::identity::storage::create_my_identity(settings.clone().network_host,identity.clone(), password).unwrap();
                            id
                        }
                        Err(e)=>{
                            if e.kind == ErrorKind::Input.to_string(){
                                fmt_print("BAD INPUTS!\nCheck the username and invite code used!");
                                return
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                                return
                            }
                        }
                    };

                    let decryption_keys = DecryptionKey::make_for_many(keypair.clone(),to,encryption_key).unwrap();
                    match network::post::dto::keys(&host, keypair.clone(), &post_id, decryption_keys){
                        Ok(_)=>{
                            fmt_print("SUCCESSFULLY POSTED CONTRACT PUBLIC DATA!");
                            let ws_url = settings.network_url_parse(ServerKind::Websocket);
                            let mut socket = network::notification::dto::sync(&ws_url, keypair).unwrap();
                            let one_sec = time::Duration::from_millis(1000);                            
                            thread::sleep(one_sec);
                            socket.write_message(Message::Text(post_id.into())).unwrap();
                            ()
                        }
                        Err(e)=>{
                            if e.kind == ErrorKind::Input.to_string(){
                                fmt_print("BAD INPUTS!\nCheck the username and invite code used!");
                                return
                            }
                            else{
                                fmt_print_struct("ERRORED!",e);
                                return
                            }
                        }
                    }

                }
                Some(("info", _)) => {
                    let settings = match settings::storage::read(){
                        Ok(value)=>value,
                        Err(e)=>{
                            fmt_print_struct("ERRORED!",e);
                            return;
                        } 
                    };
                    print!("Enter your password: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();   
                    if !settings.check_password(password.clone()) {
                        fmt_print("BAD PASSWORD");
                        return;
                    }


                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if existing_users.len() < 1{
                        fmt_print("NO USERS REGISTERED!");
                        return;
                    }
                    print!("Which alias to use ({}): ",existing_users.clone()[0]);
                    let mut username: String = read!("{}\n");
                    if username == "" || username == " "{
                        username = existing_users[0].clone();
                    }
                    else if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }

                    print!("Enter your contract id: ");
                    let contract_id: String = read!("{}\n");

                    let contract = contract::storage::read_inheritance_contract(username.clone(),contract_id,password.clone()).unwrap();
                    let is_completed = contract.clone().is_complete();
                    fmt_print_struct("CONTRACT STATUS: ", if is_completed{"ACTIVE"} else {"PENDING"});

                    if !is_completed{
                        return;
                    }

                    let sqlite_path = format!("{}/{}", std::env::var("HOME").unwrap(), DEFAULT_SQLITE);
                    let config = WalletConfig::new(
                        &contract.clone().public_descriptor.unwrap(),
                        DEFAULT_MAINNET_NODE,
                        None,
                        Some(sqlite_path.clone())
                    ).unwrap();
                    contract::sync::sqlite(config).unwrap();

                    let config = WalletConfig::new(
                        &contract.clone().public_descriptor.unwrap(),
                        DEFAULT_MAINNET_NODE,
                        None,
                        Some(sqlite_path.clone())
                    ).unwrap();

                    let balance = contract::info::sqlite_balance(config).unwrap();
                   
                    let config = WalletConfig::new(
                        &contract.clone().public_descriptor.unwrap(),
                        DEFAULT_MAINNET_NODE,
                        None,
                        Some(sqlite_path.clone())
                    ).unwrap();

                    let history = contract::info::sqlite_history(config).unwrap();
                    
                    fmt_print_struct("HISTORY: ", history);
                    fmt_print_struct("", balance);
                    ()


                }
                Some(("receive", _)) => {
                    let settings = match settings::storage::read(){
                        Ok(value)=>value,
                        Err(e)=>{
                            fmt_print_struct("ERRORED!",e);
                            return;
                        } 
                    };
                    print!("Enter your password: ");
                    std::io::stdout().flush().unwrap();
                    let password = read_password().unwrap();   
                    if !settings.check_password(password.clone()) {
                        fmt_print("BAD PASSWORD");
                        return;
                    }


                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if existing_users.len() < 1{
                        fmt_print("NO USERS REGISTERED!");
                        return;
                    }
                    print!("Which alias to use ({}): ",existing_users.clone()[0]);
                    let mut username: String = read!("{}\n");
                    if username == "" || username == " "{
                        username = existing_users[0].clone();
                    }
                    else if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }

                    print!("Enter your contract id: ");
                    let contract_id: String = read!("{}\n");
                    let contract = contract::storage::read_inheritance_contract(username.clone(),contract_id,password.clone()).unwrap();
                    let sqlite_path = format!("{}/{}", std::env::var("HOME").unwrap(), DEFAULT_SQLITE);
                    let config = WalletConfig::new(
                        &contract.clone().public_descriptor.unwrap(),
                        DEFAULT_MAINNET_NODE,
                        None,
                        Some(sqlite_path.clone())
                    ).unwrap();
                    contract::sync::sqlite(config).unwrap();
                    let config = WalletConfig::new_offline(&contract.clone().public_descriptor.unwrap(),Some(sqlite_path.clone())).unwrap();
                    let address = contract::address::sqlite_generate(config).unwrap();

                    let code = QrCode::new(address.address.as_bytes()).unwrap();
                    let image = code.render::<unicode::Dense1x2>()
                        .dark_color(unicode::Dense1x2::Dark)
                        .light_color(unicode::Dense1x2::Dark)
                        .build();
                    println!("{}", image);
                    fmt_print(&address.address);
                }
                Some(("build", _)) => {
                }
                Some(("check", _)) => {
                }
                Some(("sign", _)) => {
                }
                Some(("broadcast", _)) => {
                }
                Some(("send", _))=>{

                }
                Some(("backup", _)) => {
                }
                Some(("recover", _)) => {
                }
                _ => unreachable!(),
            }
        }
        Some(("guide", _)) => {
            let base_path = env!("CARGO_MANIFEST_DIR").to_string() + "/art/wolf.ascii";
            let title = "Leverage ✠f The Remnants";
            let subtitle = "A bitcoin contract co-ordination tool.";
            let contents = fs::read_to_string(&base_path)
                .expect("Should have been able to read the file");
            println!("\x1b[93;1m{}\x1b[0m", title);
            println!("{}", subtitle);
            println!("{contents}");
            println!("098f6bcd4621d373cade4e832627b4f6");
            println!("COMPLETE GUIDE COMING SOON!");
        }
        None => println!("No subcommand was used. try `lotr help`."), 
        _ => unreachable!(),
    }
}



fn new_contract_from_data(
    network: Network, 
    settings: MySettings,
    host: String,
    sender_username: String,
    sender_pubkey: XOnlyPublicKey,
    data: InheritanceContractPublicData, 
    password: String, 
    username: String,
) -> Result<String, String> {
    let seed = match key::storage::read_keys(password.clone(), network)
    {
        Ok(seed)=>{
            seed                          
        }
        Err(_)=>{
            println!("===============================================");
            println!("NO KEYS FOUND. USE lotr key generate/import");
            println!("===============================================");
            return Err("NO KEYS FOUND".to_string())                         
        }
    };
    let child = child::to_hardened_account(seed.clone().xprv, child::DerivationPurpose::Native, 0).unwrap();
    let xpub_info = XPubInfo::new(
        child.clone().fingerprint,
        0,
        child.clone().xpub
    );

    let mut contract = match data.clone().role {
        InheritanceRole::Parent=>{
            InheritanceContract::new_as_child(
                username.clone(), 
                data.clone().id,
                child.xprv, 
                Participant::new(
                    username.clone(),
                    Some(xpub_info.clone())
                ), 
                sender_username.clone(),
                data.clone().timelock
            )
        }
        InheritanceRole::Child=>{
            InheritanceContract::new_as_parent(
                username.clone(), 
                data.clone().id,
                child.xprv, 
                Participant::new(
                    username.clone(),
                    Some(xpub_info.clone())
                ), 
                sender_username.clone(),
                data.clone().timelock
            )
        }
    };

    match data.role{
        InheritanceRole::Parent=>{
            contract.add_parent_xpub(data.counter_party.clone());

        }
        InheritanceRole::Child=>{
            contract.add_child_xpub(data.counter_party.clone());
        }
    }
    contract.update_public_policy();
    contract.compile_public_descriptor().unwrap();
    contract::storage::store_inheritance_contract(username.clone(),contract.clone().id,password.clone(),contract.clone()).unwrap();
    // baesd on contract.role, send message to counter_party_alias with id & XPubInfo
    println!("CONTRACT {} COMPLETED!",contract.id);
    let to: Vec<XOnlyPublicKey> = [sender_pubkey].to_vec();

    let recipient = Recipient::Group(contract.clone().id);        
    let mut identity = identity::storage::read_my_identity(settings.clone().network_host,username.clone(), password.clone()).unwrap();
    let keypair = XOnlyPair::from_xprv(identity.social_root);
    
    let message_to_share = Payload::StartInheritance(
        InheritanceContractPublicData::new(
            data.clone().name,
            data.clone().id,
            contract.role,
            xpub_info.clone(),
            data.timelock
        )
    );

    let post = Post::new(recipient, message_to_share, keypair.clone()); 
    let encryption_key = identity.derive_encryption_key();
    let cypher_json = post.to_cypher(encryption_key.clone());
    let cpost_req = ServerPostRequest::new(0, &identity.last_path,&cypher_json);

    let post_id = match network::post::dto::create(&host, keypair.clone(),cpost_req){
        Ok(id)=>{
            // need to create identity again to update encryption derivation path
            network::identity::storage::create_my_identity(settings.clone().network_host,identity.clone(), password.clone()).unwrap();
            id
        }
        Err(e)=>{
            if e.kind == ErrorKind::Input.to_string(){
                fmt_print("BAD INPUTS!\nCheck the username and invite code used!");
                return Err(e.message)

            }
            else{
                fmt_print_struct("ERRORED!",e.clone());
                return Err(e.message)
            }
        }
    };

    let decryption_keys = DecryptionKey::make_for_many(keypair.clone(),to,encryption_key).unwrap();
    match network::post::dto::keys(&host, keypair.clone(), &post_id, decryption_keys){
        Ok(_)=>{

            Ok(post_id)
        }
        Err(e)=>{
            if e.kind == ErrorKind::Input.to_string(){
                fmt_print("BAD INPUTS!\nCheck the username and invite code used!");
                Err(e.message)
            }
            else{
                fmt_print_struct("ERRORED!",e.clone());
                Err(e.message)
            }
        }
    }
}


fn update_contract(
    network: Network, 
    settings: MySettings,
    host: String,
    username: String, 
    password: String,    
    data: InheritanceContractPublicData, 
    sender_username: String,
    sender_pubkey: XOnlyPublicKey,
    
)->Result<String,()>{
    match contract::storage::read_inheritance_contract(
        username.clone(), 
        data.clone().id, 
        password.clone()
    ){
        Ok(mut contract)=>{
            if contract.clone().is_complete(){
                Err(())
            }
            else {
                if contract.clone().role.to_string() == data.clone().role.to_string() {
                    return Err(());
                }
                match contract.role {
                    InheritanceRole::Parent=>{
                        contract.add_child_xpub(data.counter_party)
                    },
                    InheritanceRole::Child=>{
                        contract.add_parent_xpub(data.counter_party)
                    },
                };
                contract.timelock = data.timelock;
                if contract.is_ready(){
                    contract.update_public_policy();
                }
                if contract.clone().is_complete(){
                    println!("CONTRACT {} COMPLETED!",contract.id);
                    contract.compile_public_descriptor().unwrap();
                }
                contract::storage::store_inheritance_contract(username.clone(),data.id,password.clone(),contract).unwrap();
                Err(())
            }
        }
        Err(_)=>{
            println!("Creating new contract with {}...",sender_username.clone());
            let post_id = new_contract_from_data(
                network.clone(),
                settings.clone(),
                host.clone(),
                sender_username.clone(),
                sender_pubkey.clone(),
                data.clone(),
                password.clone(),
                username.clone(),
            ).unwrap();
            
            Ok(post_id)
        }
    }
}