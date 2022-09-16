use tungstenite::{connect};
use tungstenite::protocol::WebSocket;
use tungstenite::stream::MaybeTlsStream;
use std::net::TcpStream;
use http::{Request};
use crate::cypherpost::handler::{HttpHeader,HttpMethod,APIEndPoint, sign_request};
use secp256k1::rand::{thread_rng,Rng};
use secp256k1::{KeyPair};

pub fn sync(url: &str, key_pair: KeyPair)->Result<WebSocket<MaybeTlsStream<TcpStream>>,String>{
    let full_url = url.to_string() + &APIEndPoint::Notifications.to_string();
    let mut rng = thread_rng();
    let random = rng.gen::<u64>();
    let random_string = random.to_string();
    let signature = sign_request(key_pair, HttpMethod::Get, APIEndPoint::Notifications, &random_string).unwrap();
    
    let request = Request::builder()
        // .method("GET")
        .uri(full_url)
        .header(&HttpHeader::Signature.to_string(), &signature)
        .header(&HttpHeader::Pubkey.to_string(), &key_pair.public_key().to_string())
        .header(&HttpHeader::Nonce.to_string(), &random_string)
        .body(())
        .unwrap();
    let (socket, _) = connect(
        request
    ).expect("Can't connect");
    Ok(socket)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::ec;
    use crate::key::seed;
    use bitcoin::network::constants::Network;
    use crate::cypherpost::identity::{admin_invite,register,get_all,remove};
    use tungstenite::{Message};

    #[test] #[ignore]
    fn test_notifications_flow(){
        // FIRST INVITE THE GUY
        let url = "http://localhost:3021";
        // ADMIN INVITE
        let admin_invite_code = "098f6bcd4621d373cade4e832627b4f6";
        let client_invite_code = admin_invite(url,admin_invite_code).unwrap();
        assert_eq!(client_invite_code.len() , 32);
        // REGISTER USER
        let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
        let key_pair = ec::keypair_from_xprv_str(&seed.xprv).unwrap();
        let mut rng = thread_rng();
        let random = rng.gen::<u64>();
        let random_string = random.to_string();
        let username = "ishi".to_string() + &random_string[0..5];
        let response = register(url, key_pair, &client_invite_code, &username).unwrap();
        assert!(response.status);
        // GET ALL USERS
        let identities = get_all(url, key_pair).unwrap();
        let user_count = identities.len();
        assert!(user_count>0);
        let ws_url = "ws://localhost:3021";
        let mut socket = sync(ws_url, key_pair).unwrap();
        socket.write_message(Message::Text("connection".into())).unwrap();
        // loop {
        //     let msg = socket.read_message().expect("Error reading message");
        //     println!("{}", msg);
        // }
        // REMOVE THE GUY
        let status = remove(url, key_pair).unwrap();
        assert!(status);

        
     
    }
    
}

