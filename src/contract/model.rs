use serde::{Deserialize, Serialize};
use crate::key::encryption::{nonce};
use crate::contract::policy::{self, ScriptType};
use crate::contract::address;
use bitcoin::util::bip32::{DerivationPath, ExtendedPubKey,ExtendedPrivKey, Fingerprint, ChildNumber};
use std::marker::Copy;
use std::str::FromStr;
use crate::lib::e::{ErrorKind, S5Error};
use crate::key::encryption::{cc20p1305_encrypt,cc20p1305_decrypt};

pub const LOAN : &str = "thresh(1, thresh(2,D,B,E), thresh(2,thresh(1,D,B),after(T)))";
pub const TRADE : &str = "thresh(1, thresh(2,B,S,E), thresh(2,S,after(T)))";
pub const INHERIT : &str = "thresh(1,pk(PARENT),thresh(2,pk(CHILD),after(TIMELOCK)))";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ContractKind{
    Inherit,
    Trade,
    Loan
}
impl ContractKind {
    pub fn from_str(s: &str) -> ContractKind{
        if s.to_lowercase().starts_with("i"){
            ContractKind::Inherit
        }
        else if s.to_lowercase().starts_with("t"){
            ContractKind::Trade
        }else if s.to_lowercase().starts_with("l"){
            ContractKind::Loan
        }
        else{
            ContractKind::Inherit
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum InheritanceRole{
    Parent,
    Child
}
impl InheritanceRole {
    pub fn from_str(s: &str) -> Result<InheritanceRole,String>{
        if s.to_lowercase().starts_with("p"){
            Ok(InheritanceRole::Parent)
        }
        else if s.to_lowercase().starts_with("c"){
            Ok(InheritanceRole::Child)
        }
        else {
            Err("Bad String to representation of InheritanceRole".to_string())
        }
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InheritanceContract{
    pub name : String, 
    pub id: String,
    pub role: InheritanceRole,
    pub xprv: ExtendedPrivKey,
    pub parent: Participant,
    pub child : Participant,
    pub timelock: u64,
    pub public_policy: Option<String>,
    pub public_descriptor: Option<String>,
}

impl InheritanceContract{
    pub fn new_as_parent(name: String, xprv: ExtendedPrivKey, parent: Participant, child_name: String, timelock: u64)->Self{
        InheritanceContract{
            name,
            id: "s5w".to_string() + &nonce(),
            role: InheritanceRole::Parent,
            xprv,
            parent,
            child: Participant::new(child_name,None),
            timelock,
            public_policy: None,
            public_descriptor: None
        }
    }
    pub fn new_as_child(name: String,xprv: ExtendedPrivKey, child: Participant, parent_name: String, timelock: u64)->Self{
        InheritanceContract{
            name,
            id: "s5w".to_string() + &nonce(),
            role: InheritanceRole::Child,
            xprv,
            parent:Participant::new(parent_name,None) ,
            child,
            timelock,
            public_policy: None,
            public_descriptor: None
        }
    }
    pub fn add_parent_xpub(&mut self, xpub: XPubInfo)->(){
        match self.parent.key {
            Some(_) => {
                ()
            }
            None => {
                self.parent.key = Some(xpub);
                ()
            }
        }
    }
    pub fn add_child_xpub(&mut self, xpub: XPubInfo)->(){
        match self.child.key {
            Some(_) => {
                ()
            }
            None => {
                self.child.key = Some(xpub);
                ()
            }
        }
    }
    pub fn is_ready(&self)->bool{
        self.parent.key.is_some() && self.child.key.is_some()
    }

    pub fn update_public_policy(&mut self)->Result<(), bool>{
        if self.is_ready() && self.public_policy.is_none(){
            let policy = INHERIT.clone().to_string()
                .replace("PARENT", &self.clone().parent.key.unwrap().to_full_xkey())
                .replace("CHILD", &self.clone().child.key.unwrap().to_full_xkey())
                .replace("TIMELOCK", &self.timelock.to_string());
            self.public_policy = Some(policy.to_string());
            Ok(())
        }
        else {
            Err(false)
        }
    }
    pub fn is_complete(&self)->bool{
        self.public_policy.is_some()
    }

    pub fn compile_public_descriptor(&mut self)->Result<(),bool>{
        if self.clone().is_complete(){
            let desc = policy::compile(&self.clone().public_policy.unwrap(), ScriptType::WSH).unwrap();
            self.public_descriptor = Some(desc);
            Ok(())
        }
        else{
            Err(false)
        }
    }
    pub fn stringify(&self) -> Result<String, S5Error> {
        match serde_json::to_string(self) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying InheritanceContract"))
            }
        }
    }
    pub fn structify(stringified: &str) -> Result<InheritanceContract, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying InheritanceContract"))
            }
        }
    }
    pub fn encrypt(&self, password: String)->String{
        cc20p1305_encrypt(&self.stringify().unwrap(), &password).unwrap()
    }
    pub fn decrypt(cipher: String, password: String)->Result<InheritanceContract, S5Error>{
        let id = match cc20p1305_decrypt(&cipher, &password){
            Ok(value)=>value,
            Err(e)=>return Err(e)
        };

        Ok(InheritanceContract::structify(&id).unwrap())
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Participant{
    pub name: String,
    pub key: Option<XPubInfo>,
}
impl Participant {
    pub fn new(name: String, key: Option<XPubInfo>)->Self{
        Participant{
            name,
            key,
        }
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct XPubInfo{
    fingerprint: String,
    account: u64,
    xpub: ExtendedPubKey,
}
impl XPubInfo {
    pub fn new(fingerprint: String, account: u64,xpub: ExtendedPubKey)->Self{
        XPubInfo{
            fingerprint,
            account,
            xpub,
        }
    }
    pub fn to_full_xkey(&self)->String{
        format!("[{}/84h/0h/{}h]{}/*",self.fingerprint,self.account.to_string(),self.xpub.to_string())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::identity::dto::{admin_invite,register,get_all};
    use crate::key::ec;
    use crate::key::seed;
    use crate::key::child;
    use crate::network::post::model::{Post,Payload,Recipient};
    use bdk::bitcoin::network::constants::Network;
    use crate::lib::config::{WalletConfig,DEFAULT_SQLITE};
    use std::env;

    #[test]
    fn test_inheritance(){
        let seed1 = seed::generate(24, "", Network::Bitcoin).unwrap();
        let account = 0;
        let child1 = child::to_hardened_account(seed1.xprv, child::DerivationPurpose::Native, account).unwrap();
        let ishi_xpub = XPubInfo::new(
            seed1.fingerprint,
            account,
            child1.xpub
        );

        let mut contract_parent = InheritanceContract::new_as_parent(
            "GotYourBack".to_string(), 
            seed1.xprv,
            Participant::new(
                "ishi".to_string(),
                Some(ishi_xpub.clone())
            ), 
            "sushi".to_string(), 
            687872,
        );
        assert!(contract_parent.parent.key.is_some());
        assert!(contract_parent.child.key.is_none());
        assert!(contract_parent.public_policy.is_none());

        let seed2 = seed::generate(24, "", Network::Bitcoin).unwrap();
        let account = 0;
        let child2 = child::to_hardened_account(seed2.xprv, child::DerivationPurpose::Native, account).unwrap();
        let sushi_xpub = XPubInfo::new(
            seed2.fingerprint,
            account,
            child2.xpub
        );

        let mut contract_child = InheritanceContract::new_as_child(
            "GotYourBack".to_string(),
            seed2.xprv,
            Participant::new(
                "sushi".to_string(),
                Some(sushi_xpub.clone())
            ), 
            "ishi".to_string(), 
            687872,
        );

        contract_child.add_parent_xpub(ishi_xpub.clone());
        contract_parent.add_child_xpub(sushi_xpub.clone());

        assert_eq!(contract_child.clone().child.name, contract_parent.clone().child.name);
        assert_eq!(contract_child.clone().child.key.unwrap().xpub, contract_parent.clone().child.key.unwrap().xpub);
        assert_eq!(contract_child.clone().child.key.unwrap().fingerprint, contract_parent.clone().child.key.unwrap().fingerprint);
        assert_eq!(contract_child.clone().child.key.unwrap().account, contract_parent.clone().child.key.unwrap().account);
        assert_eq!(contract_child.clone().parent.name, contract_parent.clone().parent.name);
        assert_eq!(contract_child.clone().parent.key.unwrap().xpub, contract_parent.clone().parent.key.unwrap().xpub);
        assert_eq!(contract_child.clone().parent.key.unwrap().fingerprint, contract_parent.clone().parent.key.unwrap().fingerprint);
        assert_eq!(contract_child.clone().parent.key.unwrap().account, contract_parent.clone().parent.key.unwrap().account);

        assert!(contract_child.is_ready());
        assert!(contract_parent.is_ready());

        contract_child.update_public_policy().unwrap();
        contract_parent.update_public_policy().unwrap();
        contract_child.compile_public_descriptor().unwrap();
        contract_parent.compile_public_descriptor().unwrap();

        assert_eq!(contract_parent.clone().public_descriptor.unwrap(),contract_child.clone().public_descriptor.unwrap());

        // REQUIRES ONLINE
        // let sqlite_path: String =
        // format!("{}/{}", env::var("HOME").unwrap(), DEFAULT_SQLITE);

        // let child_config = WalletConfig::new_offline(&contract_child.clone().public_descriptor.unwrap(),None).unwrap();
        // let parent_config = WalletConfig::new_offline(&contract_parent.clone().public_descriptor.unwrap(),None).unwrap();
        // let child_address = address::generate(child_config, 0).unwrap().address;
        // let parent_address = address::generate(parent_config, 0).unwrap().address;
        // assert_eq!(child_address,parent_address);

    }
}