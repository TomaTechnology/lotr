#![allow(dead_code)]
use clap::{App, AppSettings, Arg, SubCommand};

fn main() {
    let matches = App::new("\x1b[0;92mlevrem\x1b[0m")
        .about("\x1b[0;94mLeverage Of The Remnants\x1b[0m")
        .version("\x1b[0;1m0.0.1\x1b[0m")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .author("ishi@toma.tech")
        .subcommand(
            App::new("mk")
                .about("Master Key Ops")
                .display_order(3)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    App::new("generate")
                    .about("List all running services.")
                    .display_order(0)
                    .arg(
                        Arg::with_name("username")
                        .short("u")
                        .help("Give your Master Key a username. Username will be used with cypherpost.")
                    )
                )
                .subcommand(
                    App::new("import")
                    .about("Main cyphernode commands.")
                    .display_order(1)
                    .arg(
                        Arg::with_name("mnemonic")
                        .short("m")
                        .help("24 word mnemonic seed phrase.")
                    )
                )
                .subcommand(
                    App::new("status")
                    .about("Status on whether Master Key exists and its associated username.")
                    .display_order(2)
                )
                .subcommand(
                    App::new("seal")
                    .about("Encrypt derived wallet xprv path of Master Key.")
                    .display_order(3)
                    .arg(
                        Arg::with_name("password")
                        .short("p")
                        .help("Use a strong password to encrypt your Master Key wallet path at rest.")
                    )
                )
                .subcommand(
                    App::new("unseal")
                    .about("Decrypt derived wallet xprv path of Master Key.")
                    .display_order(3)
                    .arg(
                        Arg::with_name("password")
                        .short("p")
                        .help("Use a strong password to encrypt your Master Key wallet path at rest.")
                    )
                )
                .subcommand(
                    App::new("delete")
                    .about("Delete Master Key from disk.")
                    .display_order(5)
                )   
        )
        .get_matches();
    
    match matches.subcommand() {

        ("mk", Some(service_matches)) => {
            match service_matches.subcommand() {
                    ("generate", Some(_)) => {
                        println!("Generating a Master Key...")
                    }
                    ("import", Some(_)) => {
                        println!("Importing a Master Key...")
                    }
                    ("status", Some(_)) => {
                        println!("Fetching Master Key status...")
                    }
                    ("seal", Some(_)) => {
                        println!("Sealing Master Key wallet path...")
                    }
                    ("unseal", Some(_)) => {
                        println!("Unsealing Master Key wallet path...")
                    }
                    ("delete", Some(_)) => {
                        println!("Deleting Master Key...")
                    }
                _ => unreachable!(),
            }
        }
        ("",None) => println!("No subcommand was used. try `lotr help`."), 
        _ => unreachable!(),
    }
}
