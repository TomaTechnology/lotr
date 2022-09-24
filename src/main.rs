#![allow(dead_code)]
use clap::{App, AppSettings, Arg, Command};
extern crate rpassword;    
use rpassword::read_password;
use std::io::Write;
use bitcoin::network::constants::Network;



mod lib;
use crate::lib::sleddb;
use crate::lib::e::{ErrorKind};

mod key;
use crate::key::seed;
use crate::key::child;
use crate::key::ec;

mod network;
use crate::network::identity;
use crate::network::post;
use crate::network::notification;
use crate::network::badge;

use tungstenite::{Message};


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
                .setting(AppSettings::SubcommandRequiredElseHelp)
 
        )
        .subcommand(
            Command::new("network")
                .about("Network and coordination")
                .display_order(2)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    Command::new("join")
                    .about("Register your key as a given username.")
                    .display_order(1) 
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
        }

        Some(("network", service_matches)) => {
            match service_matches.subcommand() {
                Some(("invite", _)) => {
                    
                }
                Some(("join", _)) => {
                   
                }
                Some(("leave", _)) => {
                    
                }
                Some(("members", _)) => {
                    
                }
                Some(("announce", _)) => {
                    
                }
                Some(("badges", _)) => {
                    
                }
                Some(("post", _)) => {
              
                }
                Some(("sync", _)) => {
                    
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
            let title = "Leverage ✠f The Remnants";
            let subtitle = "A bitcoin contract co-ordination tool.";
            let p1 = "The 'lotr' tool contains 3 primary commands: key, network and contract.";
           
            let p2 = "Start by creating a key pair using the generate sub-command.\n";
            let p3 = "Your keys are encrypted on your system with a password you set. This password will be required for many critical operations.\n";

            let p6 = "The next step is to setup preferences. Primarily set the url for a cypherpost network server; using the prefs sub-command.\n";
            let p8 = "If you are the admin; use invite to generate invite codes for other users. Ask an admin for an invite code if not.\n";
            let p9 = "After you aquire an invite code, use it with the join sub-command.\n";
            let p10 = "After joining you can view others on the server using the members sub-command.\n";
            let p11 = "You can then use the sync sub-command to open a message stream and the post sub-command to message other members.\n";

            println!("\x1b[93;1m{}\x1b[0m", title);
            println!("{}", subtitle);
            println!("{}", p1);
            println!("\x1b[92;1mkey\x1b[0m",);
            println!("{}", p2);
            println!("{}", p3);
            println!("\x1b[92;1mnetwork\x1b[0m",);
            println!("{}", p6);
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

