use std::fs::{read, write};
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};
use aes::Aes128;
use block_modes::{block_padding::Pkcs7, Cbc};
use block_modes::BlockMode;
use serde_json::{from_str, to_string};

use super::key::Secret;
use super::util::EncryptedFile;

pub type AES = Cbc<Aes128, Pkcs7>;

pub fn encrypt(file_paths: &[&str], key_path: &str) -> Result<(), String> {
    let key_path = key_path.trim();
    let mut encrypted_files = Vec::new();

    // Read the existing contents of the encrypted_files.json file
    let existing_contents = match read("encrypted_files.json") {
        Ok(contents) => String::from_utf8(contents).unwrap_or_default(),
        Err(_) => return Err("Unable to read file".to_string()),
    };

    // Deserialize the existing contents into a vector of EncryptedFile objects
    if !existing_contents.is_empty() {
        match from_str::<Vec<EncryptedFile>>(&existing_contents) {
            Ok(existing_files) => encrypted_files.extend(existing_files),
            Err(_) => return Err("Unable to parse existing encrypted files".to_string()),
        }
    }

    for file_path in file_paths {
        let file_path = file_path.trim();
        let to_encrypt = read(file_path.clone()).unwrap();
        let secret = read(key_path.clone()).unwrap();
        let secret: Result<Secret, serde_json::Error> = serde_json::from_slice(&secret);

        match secret {
            Ok(secret) => {
                let cipher = match AES::new_from_slices(&secret.decode_key(), &secret.decode_initial_value()) {
                    Ok(cipher) => cipher,
                    Err(err) => return Err(err.to_string()),
                };

                let pos = to_encrypt.len();
                let mut buffer = vec![0u8; pos + pos];
                buffer[..pos].copy_from_slice(&to_encrypt);
                let encrypted_data = cipher.encrypt(&mut buffer, pos).unwrap();

                let encoded_data = base64::encode(encrypted_data);
                write(file_path, encoded_data).unwrap();

                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let encrypted_file = EncryptedFile {
                    file_path: file_path.to_string(),
                    timestamp: timestamp,
                };
                encrypted_files.push(encrypted_file);
            }
            Err(err) => return Err(err.to_string()),
        }
    }

    // Serialize the vector of EncryptedFile objects to JSON
    let encrypted_files_json = to_string(&encrypted_files).unwrap();

    // Write the JSON to the encrypted_files.json file
    write("encrypted_files.json", encrypted_files_json).unwrap();

    Ok(())
}


