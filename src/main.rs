use bcrypt::{hash, verify, DEFAULT_COST};
use regex::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::{fmt::format, fs::OpenOptions};

use rand::{self, distributions::Alphanumeric, Rng};

mod tests;

enum Algorithm {
    bcrypt,
    hashshish,
}

// Algorithm that will be used.
const STD_ALGORITHM: Algorithm = Algorithm::hashshish;

fn main() {
    if !Path::new("users.txt").exists() {
        File::create("users.txt").unwrap(); // ensure file exists
    }

    loop {
        let mut choice: String = String::new();
        println!("1. Create user");
        println!("2. Login");
        println!("3. Delete user");
        std::io::stdin().read_line(&mut choice).unwrap();

        match choice.chars().next().unwrap() {
            '1' => make_user_get_input(),
            '2' => login_get_input(),
            '3' => delete_user_get_input(),
            _ => {}
        };
    }
}

fn make_user_get_input() {
    let mut username = String::new();
    println!("Username:");
    std::io::stdin().read_line(&mut username).unwrap();
    let mut password = String::new();
    println!("Password:");
    std::io::stdin().read_line(&mut password).unwrap();

    make_user(username, password);
}

fn make_user(username: String, password: String) -> bool {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open("users.txt")
        .unwrap();

    if let Some(hasished_password) = hash_password(&password.trim(), None, STD_ALGORITHM) {
        write!(file, "{};{hasished_password}|", username.trim()).ok();
    } else {
        println!("Failed to make account, cant hash password");
        return false;
    }

    return true;
}

fn login_get_input() {
        // Get username from user
        let mut username = String::new();
        println!("Username:");
        std::io::stdin().read_line(&mut username).unwrap();
        username = username.trim().to_owned();
    
        // Get password from user
        let mut password = String::new();
        println!("Password:");
        std::io::stdin().read_line(&mut password).unwrap();
        password = password.trim().to_owned();

        login(username, password);
}

fn login(username: String, password: String) -> bool {
    // Load file
    let mut file = File::open("users.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let re = Regex::new(r"\$(?<salt>[a-zA-Z0-9]*)\$(?<password>[0-9]*)").unwrap();

    // Compare all users to password and username
    for user in contents.split("|") {
        if user == "" {
            continue;
        } // Dont run if user is empty
        let mut items = user.split(";").into_iter();
        let this_username = items.next().unwrap().trim();
        let this_password = items.next().unwrap().trim();

        let salt: String = re.captures(this_password).unwrap()["salt"].to_owned();

        if check_password(&password, this_password, Some(salt.into_bytes()))
            && username == this_username.to_owned()
        {
            println!("Login success");
            return true;
        }
    }
    return false;
}

fn hash_password(input: &str, salt: Option<Vec<u8>>, algorithm: Algorithm) -> Option<String> {
    match algorithm {
        Algorithm::bcrypt => {
            return bcrypt_hash(input);
        }
        Algorithm::hashshish => {
            return Some(hashshish(&input, salt));
        }
    }
}

fn check_password(input: &str, other: &str, salt: Option<Vec<u8>>) -> bool {
    return hashshish(&input, salt) == other || verify(input, other).unwrap();
}

// https://shorturl.at/altwQ
fn hashshish(input: &str, mut salt: Option<Vec<u8>>) -> String {
    if salt == None { // When first hashing a new password, we generate a random salt. This is inspired by the way Bcrypt does it.
        salt = Some(
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .collect(),
        );
    }

    let mut output_n: u128 = 0;
    let mut salt_iter: usize = 0;

    let mut bytes = input.bytes().collect::<Vec<u8>>();

    while let Some(x) = bytes.pop() { // Some math, this is not very safe but it works.
        output_n += x as u128
            * salt.as_ref().unwrap()[salt_iter % salt.as_ref().unwrap().len()] as u128
            * 256;
        salt_iter += 1
    }

    return format!( // The password is formatted into "${salt}${hash}".
        "${}${}",
        salt.unwrap()
            .into_iter()
            .map(char::from)
            .collect::<String>(),
        output_n % 0xFFFFFFFF
    );
}

pub fn bcrypt_hash(password: &str) -> Option<String> {
    if let Ok(hashed) = hash(password, DEFAULT_COST) {
        return Some(hashed);
    } else {
        return None;
    }
}

pub fn delete_user_get_input() {
    let mut username = String::new();
    println!("Username:");
    std::io::stdin().read_line(&mut username).unwrap();
    username = username.trim().to_owned();

    delete_user(username);
}

pub fn delete_user(username: String) -> bool {
    let mut file = File::open("users.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let re = Regex::new(&r"%s;[^|]*\|".replace("%s", &username)).unwrap();

    let contents = re.replace_all(&contents, "");

    let mut file = OpenOptions::new()
        .write(true)
        .open("users.txt")
        .unwrap();

    write!(file, "{contents}").unwrap();

    return true;
}