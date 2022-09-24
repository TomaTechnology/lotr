use bitcoin::secp256k1::{XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use crate::lib::e::{S5Error,ErrorKind};
use crate::lib::config::{DEFAULT_TEST_NETWORK, DEFAULT_TESTNET_NODE};
use crate::key::encryption::{key_hash256};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ServerKind{
    Standard,
    Websocket
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MySettings{
    pub network_host: String,
    pub bitcoin_host: String,
    pub p256: String,
    pub muted: Option<Vec<XOnlyPublicKey>>,
}
impl MySettings{
    pub fn new(network_host: String, bitcoin_host: String, password: String)->Self{
        MySettings{
            network_host,
            bitcoin_host,
            p256: key_hash256(&password),
            muted: None
        }
    }
    pub fn default(password: String)->Self{
        MySettings{
            network_host: DEFAULT_TEST_NETWORK.to_string(),
            bitcoin_host: DEFAULT_TESTNET_NODE.to_string(),
            p256: key_hash256(&password),
            muted: None
        }
    }
    pub fn network_url_parse(&self, kind: ServerKind)->String{
        match kind{
            ServerKind::Standard=>{
                if self.network_host.starts_with("local") {
                    "http://".to_string() + &self.network_host
                }
                else{
                    "https://".to_string() + &self.network_host
                }
            }
            ServerKind::Websocket=>{
                if self.network_host.starts_with("local") {
                    "ws://".to_string() + &self.network_host
                }
                else{
                    "wss://".to_string() + &self.network_host
                }
            }
        }
    }
    pub fn mute(&mut self, member: XOnlyPublicKey)->(){
        if self.clone().muted.is_some(){
            self.clone().muted.unwrap().push(member)
        }
        else{
            self.muted  = Some([member].to_vec());
        }
        ()
    }
    pub fn check_password(&self, password: String)->bool{
        self.p256 == key_hash256(&password)
    }
}