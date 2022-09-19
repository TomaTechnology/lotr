use serde::{Deserialize, Serialize};
use std::str::{FromStr};
use bdk::bitcoin::hashes::sha256;
use bdk::bitcoin::secp256k1::schnorr::Signature;
use bdk::bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::{ecdh::SharedSecret, KeyPair, Message, PublicKey, SecretKey, XOnlyPublicKey};
use bdk::bitcoin::util::bip32::ExtendedPrivKey;

use crate::lib::e::{ErrorKind, S5Error};

/// FFI Output
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct XOnlyPair {
  pub seckey: String,
  pub pubkey: String,
}
impl XOnlyPair {
  pub fn from_keypair(keypair: KeyPair) -> XOnlyPair {
    let keypair = enforce_even_parity(keypair);
    return XOnlyPair {
      seckey: hex::encode(keypair.secret_bytes()).to_string(),
      pubkey: keypair.public_key().to_string(),
    };
  }
}

pub fn keypair_from_xprv_str(xprv: &str) -> Result<KeyPair, S5Error> {
  let secp = Secp256k1::new();
  let xprv = match ExtendedPrivKey::from_str(xprv) {
    Ok(result) => result,
    Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD XPRV STRING")),
  };
  let key_pair = match KeyPair::from_seckey_str(&secp, &hex::encode(xprv.private_key.secret_bytes())) {
    Ok(kp) => kp,
    Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
  };

  Ok(key_pair)
}
pub fn keypair_from_seckey_str(seckey: &str) -> Result<KeyPair, S5Error> {
  let secp = Secp256k1::new();
  let key_pair = match KeyPair::from_seckey_str(&secp, seckey) {
    Ok(kp) => kp,
    Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
  };

  Ok(key_pair)
}

/// Generate a ecdsa shared secret
pub fn compute_shared_secret_str(
  seckey: &str, 
  pubkey: &str
) -> Result<String, S5Error> {
  let secret_key = match SecretKey::from_str(seckey) {
    Ok(result) => result,
    Err(_) =>  return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
  };

  let public_key = if pubkey.clone().len() == 64 {
    "02".to_string() + pubkey.clone()
  } else if pubkey.clone().len() == 66 {
    pubkey.to_string()
  } else {
     return Err(S5Error::new(ErrorKind::Key, "BAD PUBKEY STRING"));
  };

  let pubkey = match PublicKey::from_str(&public_key) {
    Ok(result) => result,
    Err(_) =>  return Err(S5Error::new(ErrorKind::Key, "BAD PUBKEY STRING")),
  };

  let shared_secret = SharedSecret::new(&pubkey, &secret_key);
  let shared_secret_hex = hex::encode(&(shared_secret.secret_bytes()));
  Ok(shared_secret_hex)
}

pub fn signature_from_str(sig_str: &str) -> Result<Signature, S5Error> {
  match Signature::from_str(sig_str) {
    Ok(sig) => return Ok(sig),
    Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
  }
}

pub fn schnorr_sign(message: &str, key_pair: KeyPair) -> Result<Signature, S5Error> {
  let message = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());
  let signature = key_pair.sign_schnorr(message);
  Ok(signature)
}

pub fn schnorr_verify(signature: &str,message: &str, pubkey: &str) -> Result<bool, S5Error> {
  let message = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());

  let signature = match signature_from_str(signature) {
    Ok(result) => result,
    Err(_) =>  return Err(S5Error::new(ErrorKind::Key, "BAD SIGNATURE STRING")),
  };

  let pubkey = match XOnlyPublicKey::from_str(pubkey) {
    Ok(result) => result,
    Err(_) =>  return Err(S5Error::new(ErrorKind::Key, "BAD PUBKEY STRING")),
  };

  let result = match signature.verify(&message, &pubkey) {
    Ok(()) => true,
    Err(e) => {
      println!("{}", e);
      return Err(S5Error::new(ErrorKind::Key, "BAD SIGNATURE"));
    }
  };
  return Ok(result);
}

pub fn enforce_even_parity(key_pair: KeyPair)->KeyPair{
  let secp = Secp256k1::new();
  let public_key = PublicKey::from_keypair(&key_pair);
  let parity = public_key.to_string().remove(1);
  if parity == '3' {
    let mut seckey = SecretKey::from_keypair(&key_pair);
    seckey.negate_assign();
    let key_pair = KeyPair::from_secret_key(&secp, seckey); 
    key_pair
  }
  else{
    key_pair
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::key::seed;
  use bdk::bitcoin::network::constants::Network;

  #[test]
  fn test_from_xprv_str() {
    let xprv= "xprv9ym1fn2sRJ6Am4z3cJkM4NoxFsaeNdSyFQvE5CqzqqterM5nZdKUStQghQWBupjAgJZEgAWCSQWuFgqbvdGwg22tiUp8rsupd4fTrtYMEWS";
    let key_pair = keypair_from_xprv_str(xprv).unwrap();
    let expected_pubkey = "86a4b6e8b4c544111a6736d4f4195027d23495d947f87aa448c088da477c1b5f";
    assert_eq!(expected_pubkey, key_pair.public_key().to_string());
  }
  #[test]
  fn test_schnorr_sigs() {
    let message = "stackmate 1646056571433";
    let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
    let key_pair = keypair_from_xprv_str(&seed.xprv).unwrap();

    let signature = schnorr_sign(message, key_pair).unwrap();
    let signature = signature_from_str(&signature.to_string()).unwrap();
    let check_sig = schnorr_verify(&signature.to_string(),message, &key_pair.public_key().to_string()).unwrap();
    // println!("{:#?}",signature.to_string());
    assert!(check_sig);
  }

  #[test]
  fn test_shared_secret() {
    let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
    let key_pair = enforce_even_parity(keypair_from_xprv_str(&seed.xprv).unwrap());    
    let alice_pair = XOnlyPair::from_keypair(key_pair.clone());

    let seed = seed::generate(24, "", Network::Bitcoin).unwrap();
    let key_pair = enforce_even_parity(keypair_from_xprv_str(&seed.xprv).unwrap());
    let bob_pair = XOnlyPair::from_keypair(key_pair.clone());

    // Alice only has Bob's XOnlyPubkey string
    let alice_shared_secret =
      compute_shared_secret_str(&alice_pair.seckey, &bob_pair.pubkey).unwrap();

    // Bob only has Alice's XOnlyPubkey string
    let bob_shared_secret =
      compute_shared_secret_str(&bob_pair.seckey, &alice_pair.pubkey).unwrap();
    assert_eq!(alice_shared_secret, bob_shared_secret);
  }
}