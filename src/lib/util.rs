use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, self, Read};
use bcrypt;
use serde_derive::{Serialize, Deserialize};

use crate::key::Secret;
use crate::encryption;
use crate::decryption;
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedFile {
    pub file_path: String,
    pub timestamp: u64,
}
pub fn get_user(username: &str) -> Option<User> {
    let file = match File::open("users.json") {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening file: {}", e);
            return None;
        }
    };
    let reader = BufReader::new(file);
    let users: Vec<User> = match serde_json::from_reader(reader) {
        Ok(users) => users,
        Err(e) => {
            eprintln!("Error deserializing JSON: {}", e);
            return None;
        }
    };
    users.into_iter().find(|user| user.username == username)
}

pub fn register() {
    let mut username = String::new();
    let mut password = String::new();
    let mut confirm_password = String::new();

    println!("Enter username:");
    io::stdin().read_line(&mut username).expect("Failed to read username");

    println!("Enter password:");
    io::stdin().read_line(&mut password).expect("Failed to read password");

    println!("Confirm password:");
    io::stdin().read_line(&mut confirm_password).expect("Failed to read confirm password");

    if password.trim() != confirm_password.trim() {
        println!("Passwords do not match");
        return;
    }

    let hashed_password = bcrypt::hash(password.trim(), 12).expect("Failed to hash password");

    let new_user = User {
        username: username.trim().to_string(),
        password: hashed_password,
    };

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .read(true)
        .open("users.json")
        .expect("Failed to open users.json");

    let mut users: Vec<User> = serde_json::from_reader(BufReader::new(&file))
        .unwrap_or_else(|_| {
            println!("Failed to read users.json, creating new vector");
            vec![]
        });

    users.push(new_user);

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("users.json")
        .expect("Failed to open users.json");

    serde_json::to_writer_pretty(BufWriter::new(file), &users)
        .expect("Failed to write users to file");

    println!("User registered successfully");
}

fn generate_key(){
    let mut key_path = String::new();
    println!("Enter path to generate key:");
    io::stdin().read_line(&mut key_path).expect("Failed to read path");
    match Secret::new(&key_path) {
        Ok(()) => println!("Secret generated Successfully"),
        Err(e) => println!("Secret Generation Error: {}", e),
    };

}

fn encrypt_file() {
    let mut file_paths = String::new();
    println!("Enter paths to files to encrypt separated by commas:");
    io::stdin().read_line(&mut file_paths).expect("Failed to read file paths");

    let file_paths: Vec<&str> = file_paths.trim().split(',').collect();

    let mut key_path = String::new();
    println!("Enter path to key:");
    io::stdin().read_line(&mut key_path).expect("Failed to read path");

    match encryption::encrypt(&file_paths, &key_path.trim()) {
        Ok(()) => println!("Files encrypted successfully"),
        Err(e) => println!("Encryption Error: {}", e),
    };
}

fn decrypt_file() {
    let mut file_paths = String::new();
    println!("Enter path(s) to file(s) to decrypt (comma separated):");
    io::stdin().read_line(&mut file_paths).expect("Failed to read file path(s)");

    let file_paths: Vec<&str> = file_paths.trim().split(',').collect();

    let mut key_path = String::new();
    println!("Enter path to key:");
    io::stdin().read_line(&mut key_path).expect("Failed to read path");

    for file_path in file_paths {
        match decryption::decrypt(&file_path, &key_path) {
            Ok(()) => println!("File {} decrypted Successfully", file_path),
            Err(e) => println!("Decryption Error for file {}: {}", file_path, e),
        };
    }
}

fn get_file_paths() -> () {
    let mut file = match File::open("encrypted_files.json") {
        Ok(file) => file,
        Err(_) => {
            println!("Unable to open file");
            return ();
        },
    };

    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_) => (),
        Err(_) => {
            println!("Unable to read file");
            return ();
        },
    };

    let encrypted_files: Vec<EncryptedFile> = match serde_json::from_str(&contents) {
        Ok(encrypted_files) => encrypted_files,
        Err(_) => {
            println!("Unable to parse file contents");
            return ();
        },
    };

    let file_paths: Vec<String> = encrypted_files.iter().map(|f| f.file_path.clone()).collect();

    for path in file_paths {
        println!("{}", path);
    }
}

pub fn login() {
    let mut username = String::new();
    let mut password = String::new();

    println!("Enter username:");
    io::stdin().read_line(&mut username).expect("Failed to read username");

    println!("Enter password:");
    io::stdin().read_line(&mut password).expect("Failed to read password");

    let user = match get_user(&username.trim()) {
        Some(user) => user,
        None => {
            println!("User not found");
            return;
        }
    };

    if bcrypt::verify(&password.trim(), &user.password).unwrap_or(false) {
        println!("Login successful\n\n");
        println!("Enter action you want to perform\n\nAvailable commands select number to choose:\n\t1.Generate key\n\t2.Encrypt a file or files\n\t3.Decrypt a file or files\n\t4.Show all encrypted files");

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .unwrap();
        let command = input.trim();

        match command {
            "Generate" | "generate" | "1" => generate_key(),
            "Encrypt" | "encrypt" | "2" => encrypt_file(),
            "Decrypt" | "decrypt" | "3" => decrypt_file(),
            "show all" | "showall" | "Show All" | "4" => get_file_paths(),
            _ => println!("Unknown command: {}", command),
        }
    } else {
        println!("Incorrect password");
    }
}
