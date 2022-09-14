use std::{str};
use crate::e::{ErrorKind, S5Error};

use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, NewAead};
use bdk::bitcoin::secp256k1::rand::{thread_rng,Rng};
// use hex::encode;
use sha2::{Sha256, Digest};

pub fn key_hash256(key: &str)->String{
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

pub fn cc20p1305_encrypt(plaintext:&str, key: &str)->Result<String,S5Error>{
    let formatted = key_hash256(key);
    let shortened = formatted.as_str()[..32].as_bytes();
    let encryption_key = Key::from_slice(shortened);
    let aead = XChaCha20Poly1305::new(encryption_key);
    let mut rng = thread_rng();
    let random = rng.gen::<u64>();
    let mut random_string = random.to_string();
    random_string.pop();
    random_string.pop();
    let random_bytes = random_string.as_bytes();
    let nonce = &base64::encode(random_bytes); 
    let nonce = XNonce::from_slice(nonce.as_bytes()); 
    let ciphertext = aead.encrypt(nonce, plaintext.as_bytes()).expect("encryption failure!");
    Ok(format!("{}:{}",base64::encode(nonce),base64::encode(&ciphertext)))
}
pub fn cc20p1305_decrypt(ciphertext:&str, key: &str)->Result<String,S5Error>{
    let formatted = key_hash256(key);
    let shortened = formatted.as_str()[..32].as_bytes();
    let encryption_key = Key::from_slice(shortened);
    let aead = XChaCha20Poly1305::new(encryption_key);
    let iter:Vec<&str> = ciphertext.split(':').collect();
    let nonce_slice = &base64::decode(&iter[0].as_bytes()).unwrap();
    let nonce = XNonce::from_slice(nonce_slice); // 24-bytes; unique
    let ciphertext_bytes: &[u8] = &base64::decode(&iter[1].as_bytes()).unwrap();
    let plaintext = aead.decrypt(nonce, ciphertext_bytes).expect("decryption failure!");
    match str::from_utf8(&plaintext){
        Ok(message)=>Ok(message.to_string()),
        Err(_)=> Err(S5Error::new(ErrorKind::Input, "Bad Text"))
    }
}


#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_key_hash256(){
    let simple_key = "mynameisishi";
    let strong_key = key_hash256(simple_key);
    let expected_key = "d673e4616d7222186345d12005fd0f439d276cc92751517dfe822685d496da77";
    assert_eq!(&strong_key,expected_key);
  }
  // test with external data sources
  #[test]
  fn test_encryption() {
    let message = "thresh(2,wpkh([fingerprint/h/d/path]xpub/*),*,*))";
    let key_str = "a simple key for me to remember"; 
    let ciphertext = cc20p1305_encrypt(message, key_str).unwrap();
    let plaintext = cc20p1305_decrypt(&ciphertext, key_str).unwrap();
    assert_eq!(&plaintext, message);
  }
}
