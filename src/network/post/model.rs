use crate::key::encryption::{self,key_hash256};
use crate::key::child;
use crate::key::ec::{XOnlyPair,xonly_to_public_key};
use bdk::bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{XOnlyPublicKey};
use bdk::bitcoin::util::bip32::ExtendedPrivKey;
use serde::{Deserialize, Serialize};
use crate::lib::e::{S5Error,ErrorKind};
use crate::network::identity::model::{MemberIdentity};
use crate::lib::config::{DEFAULT_TEST_NETWORK, DEFAULT_MAIN_NETWORK, DEFAULT_MAINNET_NODE, DEFAULT_TESTNET_NODE};
use bdk::bitcoin::network::constants::Network;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalPostModel {
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: XOnlyPublicKey,
    pub post: Post,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Post {
    pub to: Recipient,
    pub payload: Payload,
    pub checksum: String,
    pub signature : Signature,
}

impl Post{
    pub fn new(
        to: Recipient, 
        payload: Payload, 
        keypair: XOnlyPair
    )->Self{
        let checksum_message = to.to_string() + ":" + &payload.to_string();
        let checksum = key_hash256(&checksum_message);
        Post {
            to,
            payload,
            checksum:checksum.clone(),
            signature: keypair.schnorr_sign(&checksum).unwrap(),
        }
    }
    pub fn stringify(&self) -> Result<String, S5Error> {
        match serde_json::to_string(self) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying Post"))
            }
        }
    }

    pub fn structify(stringified: &str) -> Result<Post, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying Post"))
            }
        }
    }
    pub fn to_cypher(&self, social_root: ExtendedPrivKey, derivation: &str)->String{
        let enc_source = child::to_path_str(social_root, derivation).unwrap().xprv.to_string();
        let encryption_key  = encryption::key_hash256(&enc_source);
        let cypher = encryption::cc20p1305_encrypt(&self.stringify().unwrap(), &encryption_key).unwrap();
        cypher
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Recipient {
    Direct(XOnlyPublicKey),
    Group(String),
}
impl Recipient {
    pub fn to_string(&self)->String{
        match self{
            Recipient::Direct(pubkey)=>pubkey.to_string(),
            Recipient::Group(id)=>id.to_string()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Payload {
    Ping, // All contracts start with a ping
    ChecksumPong(String), // All pings responded with pong and checksum proof.
    Message(String),
    Preferences(AppPreferences),
    // Comment(Comment), // comment on another post
    // PolicyXpub(PolicyXpub),
    // Address(WalletAddress),
    // Psbt(WalletPsbt),
    // Jitsi(String),
}
impl Payload {
    pub fn to_string(&self)->String{
        match self{
            Payload::Ping=>"Ping".to_string(),
            Payload::ChecksumPong(checksum)=>checksum.to_string(),
            Payload::Message(text)=>text.to_string(),
            Payload::Preferences(prefs)=>prefs.stringify().unwrap()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppPreferences {
    bitcoin_host: String,
    network_host: String,
    socks5: Option<u32>,
    last_derivation_path: String,
    muted: Vec<String>, 
}

impl AppPreferences {
    pub fn default(network: Network)->Self{
        match network {
            Network::Bitcoin=>AppPreferences{
                bitcoin_host: DEFAULT_MAINNET_NODE.to_string(),
                network_host: DEFAULT_MAIN_NETWORK.to_string(),
                socks5: None,
                last_derivation_path: "m/1h/0h".to_string(),
                muted: [].to_vec()
            },
            _=>AppPreferences{
                bitcoin_host: DEFAULT_TESTNET_NODE.to_string(),
                network_host: DEFAULT_TEST_NETWORK.to_string(),
                socks5: None,
                last_derivation_path: "m/1h/0h".to_string(),
                muted: [].to_vec()
            }
        }
    }
    pub fn stringify(&self) -> Result<String, S5Error> {
        match serde_json::to_string(self) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying AppPreferences"))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecryptionKey{
   pub decryption_key: String,
   pub receiver: XOnlyPublicKey
}
impl DecryptionKey{
    pub fn new(decryption_key: &str,receiver: XOnlyPublicKey)->DecryptionKey{
        DecryptionKey {
            decryption_key: decryption_key.to_string(),
            receiver
        }
    }

    pub fn make_for_many(recipients: Vec<XOnlyPublicKey>,social_root: ExtendedPrivKey, derivation_scheme: &str)->Result<Vec<DecryptionKey>,S5Error>{
        let enc_source = child::to_path_str(social_root, &derivation_scheme).unwrap().xprv.to_string();
        let encryption_key  = key_hash256(&enc_source);
        let xonly_pair = XOnlyPair::from_xprv(social_root);
        Ok(
            recipients.into_iter().map(|recipient|{
                let shared_secret = xonly_pair.compute_shared_secret(xonly_to_public_key(recipient)).unwrap();
                let decryption_key = encryption::cc20p1305_encrypt(&encryption_key, &shared_secret).unwrap();
                DecryptionKey{
                    decryption_key: decryption_key,
                    receiver: recipient
                }
            }).collect()
        )
    }
}

