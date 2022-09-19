use serde::{Deserialize, Serialize};

pub const CONTRACT : &str = "thresh(1, thresh(2,D,B,E), thresh(2,I,after(T)))";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeInfo{
    pub url: String,
    pub socks5: u32
}

impl NodeInfo {
    pub fn new(url: &str, socks5: u32)->Self{
        NodeInfo{
            url: url.to_string(),
            socks5: socks5
        }
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PolicyInfo{
    name: String,
    thresh: usize,
    conditions: Option<Vec<String>>,
}
impl PolicyInfo {
    pub fn new(name: &str, thresh: usize, conditions: Option<Vec<String>>)->Self{
        PolicyInfo{
            name: name.to_string(),
            thresh: thresh,
            conditions: conditions,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContractInfo{
    pub name: String,
    pub depositor: PolicyInfo,
    pub beneficiary: PolicyInfo,
    pub escrow: PolicyInfo,
    pub insurance: PolicyInfo,
    pub timelock: Option<u64>,
    pub public_policy: Option<String>
}

impl ContractInfo {
    pub fn new(name: &str, depositor: &str, beneficiary: &str, escrow: &str, insurance: &str)->Self{
        ContractInfo{
            name: name.to_string(),
            depositor: PolicyInfo::new(depositor, 1,None),
            beneficiary: PolicyInfo::new(beneficiary,1,None),
            escrow: PolicyInfo::new(escrow,1,None),
            insurance: PolicyInfo::new(insurance,1,None),
            timelock: None,
            public_policy: None
        }
    }
    pub fn push_depositor_xpub(&mut self, xpub: &str)->Self{
        match self.depositor.conditions {
            Some(ref mut conditions) => {
                if conditions.len() > self.depositor.thresh {
                    self.clone()
                }
                else {
                    conditions.push(xpub.to_string());
                    self.clone()
                }
            }
            None => {
                self.depositor.conditions = Some(vec![xpub.to_string()]);
                self.clone()
            }
        }
    }
    pub fn push_beneficiary_xpub(&mut self, xpub: &str)->Self{
        
        match self.clone().beneficiary.conditions{
            Some(ref mut conditions) => {
                if conditions.len() > self.clone().beneficiary.thresh {
                    self.clone()
                }
                else {
                    conditions.push(xpub.to_string());
                    self.clone()
                }
            }
            None => {
                self.beneficiary.conditions = Some(vec![xpub.to_string()]);
                self.clone()
            }
        }
    }

    pub fn update_timelock(&mut self, timelock: u64)->Self{
        self.timelock= Some(timelock);
        self.clone()
    }
    pub fn is_ready(&self)->bool{
        self.depositor.conditions.is_some() && 
            self.beneficiary.conditions.is_some() && 
            self.escrow.conditions.is_some() && 
            self.insurance.conditions.is_some() && 
            self.timelock.is_some()
    }
    pub fn update_public_policy(&mut self)->Result<Self, bool>{
        if self.is_ready(){
            let policy = CONTRACT.clone().to_string()
                .replace("B", &self.clone().depositor.conditions.unwrap().pop().unwrap())
                .replace("F", &self.clone().beneficiary.conditions.unwrap().pop().unwrap())
                .replace("E", &self.clone().escrow.conditions.unwrap().pop().unwrap())
                .replace("I", &self.clone().insurance.conditions.unwrap().pop().unwrap())
                .replace("T", &self.timelock.unwrap().to_string());
            self.public_policy = Some(policy.to_string());
            Ok(self.clone())
        }
        else {
            Err(false)
        }
    }
    pub fn is_complete(&self)->bool{
        self.public_policy.is_some()
    }
}