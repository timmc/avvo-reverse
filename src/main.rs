use hex;
use sha1::{Sha1, Digest};
use std::env;
use std::fs;
use std::process;

struct Input {
    // From record file
    email: Vec<u8>,
    seqid: Vec<u8>,
    hex1: Vec<u8>,
    hex2: Vec<u8>,
    // From password file
    password: Vec<u8>,
}

fn load(record_path: &String, password_path: &String) -> Input {
    let record_raw = fs::read_to_string(record_path).expect("Couldn't read record file");
    let password_raw = fs::read_to_string(password_path).expect("Couldn't read password file");

    let record_parts: Vec<&str> = record_raw.split(',').collect();
    return Input {
        email: record_parts[0].as_bytes().to_owned(),
        seqid: record_parts[1].as_bytes().to_owned(),
        hex1: record_parts[2].as_bytes().to_owned(),
        hex2: record_parts[3].as_bytes().to_owned(),
        password: password_raw.split('\n').next().expect("Password split had zero items").as_bytes().to_owned(),
    };
}

fn delims() -> Vec<Vec<u8>> {
    let mut delimiters: Vec<Vec<u8>> = Vec::new();

    // Start with the empty "delimiter"
    delimiters.push(Vec::new());

    // Add all non-alpanumeric printable ASCII
    for c in "`-=[]\\;',./~!@#$%^&*()_+{}|:\"<>? ".chars() {
        delimiters.push(c.to_string().as_bytes().to_owned());
    }

    // Add in some likely other delims
    for other in vec!["::", "||"] {
        delimiters.push(other.as_bytes().to_owned());
    }

    return delimiters;
}

fn hash(data: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    return hasher.finalize().as_slice().to_owned();
}

fn crack(input: Input) {
    let bytes1 = hex::decode(input.hex1).expect("First hex chunk unreadable");
    let bytes2 = hex::decode(input.hex2).expect("Second hex chunk unreadable");

    let delimiters = delims();

    let pass_hash = hash(&input.password);
    let eq_check = pass_hash == bytes2;
    println!("{} matches? {}", hex::encode(pass_hash), eq_check);

}

fn run(record_path: &String, password_path: &String) {
    let input = load(record_path, password_path);
    crack(input);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match &args[..] {
        [_, record_path, password_path] => run(record_path, password_path),
        _ => {
            println!("Usage: cargo run <record_file> <password_file>");
            process::exit(1);
        }
    }
}
