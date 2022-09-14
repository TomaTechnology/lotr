use serde::{Deserialize, Serialize};
use crate::e::{S5Error,ErrorKind};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CypherPostModel{
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: String,
    pub cypher_json: String,
    pub derivation_scheme: String,
    pub edited : bool,
    pub decryption_key: Option<String>
}


#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum PostKind{
    Message,
    Pubkey,
    AddressIndex,
    Psbt
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlainPost{
    pub kind: PostKind,
    pub label: Option<String>,
    pub value: String,
}
impl PlainPost{
    pub fn stringify(&self) -> Result<String, S5Error> {
        match serde_json::to_string(self) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying PlainPost"))
            }
        }
    }
    pub fn structify(stringified: &str) -> Result<PlainPost, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying PlainPost"))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlainPostModel{
    pub id: String,
    pub genesis: u64,
    pub expiry: u64,
    pub owner: String,
    pub plain_post: PlainPost,
    pub edited : bool
}
impl PlainPostModel{
    pub fn stringify(&self) -> Result<String, S5Error> {
        match serde_json::to_string(self) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying PlainPostModel"))
            }
        }
    }
    pub fn structify(stringified: &str) -> Result<PlainPostModel, S5Error> {
        match serde_json::from_str(stringified) {
            Ok(result) => Ok(result),
            Err(_) => {
                Err(S5Error::new(ErrorKind::Internal, "Error stringifying PlainPostModel"))
            }
        }
    }

}

pub fn get_posts_by_kind(mut posts: Vec<PlainPostModel>, kind: PostKind)->Vec<PlainPostModel>{
    posts.retain(|x| x.plain_post.kind == kind);
    posts
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LotrContract{
    pub builder: String,
    pub facilitator: String,
    pub escrow: String,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cypherpost_models(){
        let example  = PlainPost{
            kind: PostKind::Message,
            label: None,
            value: "Yo, I have a secret only for you".to_string()
        };

        let stringified = example.stringify().unwrap();
        println!("{:#?}",stringified);
    }
    
}
