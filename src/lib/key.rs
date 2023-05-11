use std::fs::{File};
use std::io::{Error, Write};
use rand::thread_rng;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use serde_json::to_vec;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub key: String,
    pub initial_value: String,
}

impl Secret {
    pub fn new(out_path: &str) -> Result<(), Error> {
        let out_path = out_path.trim();
        let mut key = [0u8; 16];
        thread_rng().fill_bytes(&mut key[..]);

        let mut initial_value = [0u8; 16];
        thread_rng().fill_bytes(&mut initial_value[..]);

        let secret = Secret {
            key: base64::encode(key),
            initial_value: base64::encode(initial_value),
        };

        let secret_bytes = to_vec(&secret).map_err(|e| Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut file = File::create(out_path).map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;

        file.write_all(&secret_bytes).map_err(|e| Error::new(std::io::ErrorKind::Other, e))
    }

    pub fn decode_key(&self) -> Vec<u8> {
        base64::decode(&self.key).unwrap()
    }////passphrase key

    pub fn decode_initial_value(&self) -> Vec<u8> {
        base64::decode(&self.initial_value).unwrap()
    }//randomize key to aviod relation bruteforce
}

// A block cipher encryption is a type of encryption algorithm that operates on fixed-size blocks of data, 
//typically 64 or 128 bits in size. It takes a block of plaintext as input and applies a series of 
//mathematical transformations to produce a block of ciphertext. The same key is used to both encrypt and decrypt the data.