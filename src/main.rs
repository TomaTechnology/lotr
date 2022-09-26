#![allow(dead_code)]
#![allow(unused_imports)]
#[macro_use] 
extern crate text_io;

use::std::fs;

use clap::{App, AppSettings, Arg, Command};
extern crate rpassword;    
use rpassword::read_password;
use std::io::Write;
use std::fmt::Debug;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{XOnlyPublicKey};

mod lib;
use crate::lib::e::{ErrorKind};
use crate::lib::config::{DEFAULT_TEST_NETWORK, DEFAULT_TESTNET_NODE};

mod key;
use crate::key::ec::{XOnlyPair};
mod network;
use network::identity;
use network::post::{self, model::{Payload,Post,Recipient,DecryptionKey}, dto::{ServerPostRequest, ServerPostModel}};

mod settings;
use crate::settings::model::{MySettings,ServerKind};
use std::{thread, time};
use tungstenite::{Message};

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
            Command::new("settings")
                .about("Configure app settings.")
                .display_order(1) 
        )
        .subcommand(
            Command::new("network")
                .about("Network and coordination")
                .display_order(2)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    Command::new("join")
                    .about("Register as a given username.")
                    .display_order(0) 
                )                
                .subcommand(
                    Command::new("aliases")
                    .about("Manage your aliases")
                    .display_order(1) 
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
                    Command::new("announce")
                    .about("Make a public announcement.")
                    .display_order(3)
                )
                .subcommand(
                    Command::new("badges")
                    .about("Get announcements and create a graph of badges.")
                    .display_order(4)
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
                    Command::new("leave")
                    .about("Unregister your key and username.")
                    .display_order(7)
                )
                .subcommand(
                    Command::new("invite")
                    .about("ADMIN command to generate an invite code for contacts.")
                    .display_order(8)
                )
        )
        .subcommand(
            Command::new("contract")
                .about("Bitcoin Contract/Wallet")
                .display_order(3)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    Command::new("create")
                    .about("Create a new contract")
                    .display_order(0) 
                )
                .subcommand(
                    Command::new("update")
                    .about("Manually update a contract")
                    .display_order(0) 
                )
                .subcommand(
                    Command::new("info")
                    .about("Info about contract status, balance and history")
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
        Some(("settings", _)) => {
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
                    my_settings.clone().network_host = network_host;
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
                Some(("join", _)) => {
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

                    print!("Choose a unique username (12 alphanumeric characters only): ");
                    let username: String = read!("{}\n");

                    print!("Paste your invite code: ");
                    std::io::stdout().flush().unwrap();
                    let invite_code = read_password().unwrap();

                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if existing_users.contains(&username.clone()){
                        fmt_print("USER ALREADY EXISTS");
                        return
                    }
                    if &existing_users.len() > &0 {
                        fmt_print_struct("Existing Local Users:", existing_users.clone());
                    } 

                    let seed = key::seed::generate(24, "", Network::Bitcoin).unwrap();
                    let identity = identity::model::UserIdentity::new(username.clone(), seed.xprv);
                    let keypair = XOnlyPair::from_xprv(identity.social_root);
                    
                    match identity::dto::register(&host, keypair, &invite_code, &username){
                        Ok(_)=>{
                            identity::storage::create_my_identity(settings.clone().network_host, identity.clone(),password).unwrap();
                            println!("WRITE DOWN YOUR MASTER KEY DATA!\n\nMnemonic: {}\n\nFingerprint: {}", seed.mnemonic.to_string(),seed.fingerprint);
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

                    print!("Which alias to use (username): ");
                    let username: String = read!("{}\n");

                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if !existing_users.contains(&username.clone()){
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
                Some(("announce", _)) => {
                    
                }
                Some(("badges", _)) => {
                    
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

                    print!("Which alias to use (username): ");
                    let username: String = read!("{}\n");

                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }

                    print!("To (multiple,recipients,serpated,by,a,comma): ");
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
                    println!("{:#?}",to);

                    let recipient = if to.len() == 1  {
                        Recipient::Direct(to[0])
                    }
                    else {
                        Recipient::Group(key::encryption::nonce())
                    };

                    println!("{:#?}",recipient);
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
                    println!("{:#?}",decryption_keys);
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

                    print!("Which alias to use (username): ");
                    let username: String = read!("{}\n");

                    let existing_users = identity::storage::get_username_indexes(settings.clone().network_host);
                    if !existing_users.contains(&username.clone()){
                        fmt_print("ALIAS IS NOT REGISTERED!");
                        return
                    }
                    let identity = identity::storage::read_my_identity(settings.clone().network_host,username, password.clone()).unwrap();
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
                        println!("\x1b[94;1m{}\x1b[0m :: {}",network::identity::storage::get_username_by_pubkey(members.clone(), post.owner).unwrap(), post.post.payload.to_string())
                    }
                    loop {
                        match socket.read_message(){
                            Ok(msg)=>{
                                if msg.to_string().starts_with("s5p"){
                                    let cypherpost_single = network::post::dto::single_post(&host, keypair.clone(), &msg.to_string()).unwrap();
                                    let post = cypherpost_single.decypher(identity.social_root).unwrap();
                                    println!("\x1b[94;1m{}\x1b[0m :: {}", network::identity::storage::get_username_by_pubkey(members.clone(), post.owner).unwrap(), post.post.payload.to_string());
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
                _ => unreachable!(),
            }
        }

        Some(("contract", service_matches))=>{
            match service_matches.subcommand() {
                Some(("create", _)) => {
                }
                Some(("update", _)) => {
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

