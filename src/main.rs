#![allow(special_module_name)]
use std::io::{self};
mod lib;
use lib::util;
use lib::key;
use lib::encryption;
use lib::decryption;

fn main() {
    println!("Enter action you want to perform\nAvailable commands select number to choose:\n\t1.Register\n\t2.Login\n\t3.Forgot Password");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let command = input.trim();

    match command {
        "Register" | "register" | "1" => util::register(),
        "Login" | "login" | "2" => util::login(),
        "forgot password" | "forgotpassword" | "Forgot Password" | "3" => println!("Not in scope will ask recovery key or recovery questions"),
        _ => println!("Unknown command: {}", command),
    }
}
