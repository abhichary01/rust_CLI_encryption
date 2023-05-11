use block_modes::BlockMode;
use aes::Aes128;
use block_modes::{block_padding::Pkcs7, Cbc};
use std::fs::{read, write};
use std::str;

pub type AES = Cbc<Aes128, Pkcs7>;

use crate::lib::util::EncryptedFile;

use super::key::Secret;

pub fn decrypt(encrypted_file_path: &str, secret: &str) -> Result<(), String> {
    let encrypted_file_path = encrypted_file_path.trim();
    let secret = secret.trim();
    let encrypted_content = read(encrypted_file_path.clone()).unwrap();
    let secret = read(secret).unwrap();

    let secret: Result<Secret, serde_json::Error> = serde_json::from_slice(&secret);

    match secret {
        Ok(secret) => match AES::new_from_slices(&secret.decode_key(), &&secret.decode_initial_value()) {
            Ok(cipher) => {
                let mut buffer = base64::decode(encrypted_content).unwrap();
                let decrypted_data = cipher.decrypt(&mut buffer).unwrap();

                write(encrypted_file_path, str::from_utf8(decrypted_data).unwrap()).unwrap();

                // Remove the object with the given file path from the `encrypted_files_json` vector
                let mut encrypted_files_json = read("encrypted_files.json").unwrap();
                let encrypted_files: Vec<EncryptedFile> = serde_json::from_str(&String::from_utf8_lossy(&encrypted_files_json)).unwrap();
                let mut new_encrypted_files: Vec<EncryptedFile> = Vec::new();
                for file in encrypted_files {
                    if file.file_path != encrypted_file_path {
                        new_encrypted_files.push(file);
                    }
                }
                encrypted_files_json = serde_json::to_string(&new_encrypted_files).unwrap().into();
                write("encrypted_files.json", &encrypted_files_json).unwrap();

                Ok(())
            }
            Err(err) => return Err(err.to_string()),
        },
        Err(err) => return Err(err.to_string()),
    }
}
