use serde::{Deserialize, Serialize};

const CONTRACT : &str = "thresh(1, thresh(2,B,F,E), thresh(2,thresh(1,B1,F1), after(T)))";

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
pub struct ContractInfo{
    pub name: String,
    pub builder: ParticipantInfo,
    pub facilitator: ParticipantInfo,
    pub escrow: ParticipantInfo,
    pub timelock: Option<u64>,
    pub public_policy: Option<String>
}
impl ContractInfo {
    pub fn new(name: &str, builder: &str, facilitator: &str, escrow: &str)->Self{
        ContractInfo{
            name: name.to_string(),
            builder: ParticipantInfo::new(builder),
            facilitator: ParticipantInfo::new(facilitator),
            escrow: ParticipantInfo::new(escrow),
            timelock: None,
            public_policy: None
        }
    }
    pub fn update_builder_xpub(&mut self, xpub: &str)->Self{
        self.builder.update_xpub(xpub.to_string());
        self.clone()
    }
    pub fn update_builder_ms_xpub(&mut self, xpub: &str)->Self{
        self.builder.update_ms_xpub(xpub.to_string());
        self.clone()
    }
    pub fn update_facilitator_xpub(&mut self, xpub: &str)->Self{
        self.facilitator.update_xpub(xpub.to_string());
        self.clone()
    }
    pub fn update_facilitator_ms_xpub(&mut self, xpub: &str)->Self{
        self.facilitator.update_xpub(xpub.to_string());
        self.clone()
    }
    pub fn update_escrow_xpub(&mut self, xpub: &str)->Self{
        self.escrow.update_xpub(xpub.to_string());
        self.clone()
    }
    pub fn update_timelock(&mut self, timelock: u64)->Self{
        self.timelock= Some(timelock);
        self.clone()
    }
    pub fn is_ready(&self)->bool{
        self.builder.xpub.is_some() && 
        self.builder.ms_xpub.is_some() &&
        self.facilitator.xpub.is_some() && 
        self.facilitator.ms_xpub.is_some() &&
        self.escrow.xpub.is_some() && 
        self.timelock.is_some()
    }
    pub fn update_public_policy(&mut self)->Result<Self, bool>{
        if self.is_ready(){
            let policy = CONTRACT.clone().to_string()
                .replace("B", &self.clone().builder.xpub.unwrap())
                .replace("F", &self.clone().facilitator.xpub.unwrap())
                .replace("E", &self.clone().escrow.xpub.unwrap())
                .replace("B1", &self.clone().builder.ms_xpub.unwrap())
                .replace("F1", &self.clone().facilitator.ms_xpub.unwrap())
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantInfo{
    name: String,
    xpub: Option<String>,
    ms_xpub: Option<String>
}
impl ParticipantInfo {
    pub fn new(name: &str)->Self{
        ParticipantInfo{
            name: name.to_string(),
            xpub: None,
            ms_xpub: None
        }
    }
    pub fn update_xpub(&mut self, xpub: String)->Self{
        self.xpub = Some(xpub);
        self.clone()
    }
    pub fn update_ms_xpub(&mut self, ms_xpub: String)->Self{
        self.ms_xpub = Some(ms_xpub);
        self.clone()
    }
}
