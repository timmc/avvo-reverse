use hex;
use itertools::Itertools;
use sha1::{Sha1, Digest};
use std::ascii;
use std::env;
use std::fs;
use std::iter;
use std::process;

struct Input {
    // From record file
    email: Vec<u8>,
    seqid: Vec<u8>,
    hex1: Vec<u8>,
    hex2: Vec<u8>,
    // Precomputed from record
    bytes1: Vec<u8>,
    bytes2: Vec<u8>,
    // From password file
    password: Vec<u8>,
}

fn load(record_path: &String, password_path: &String) -> Input {
    let record_raw = fs::read_to_string(record_path).expect("Couldn't read record file");
    let password_raw = fs::read_to_string(password_path).expect("Couldn't read password file");

    let record_parts: Vec<&str> = record_raw.split(',').collect();
    let hex1 = record_parts[2].as_bytes().to_owned();
    let hex2 = record_parts[3].as_bytes().to_owned();
    let bytes1 = hex::decode(&hex1).expect("First hex chunk unreadable");
    let bytes2 = hex::decode(&hex2).expect("Second hex chunk unreadable");

    return Input {
        email: record_parts[0].as_bytes().to_owned(),
        seqid: record_parts[1].as_bytes().to_owned(),
        hex1: hex1,
        hex2: hex2,
        bytes1: bytes1,
        bytes2: bytes2,
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

fn hash(data: &Vec<&Vec<u8>>) -> Vec<u8> {
    let mut hasher = Sha1::new();
    for piece in data {
        hasher.update(piece);
    }
    return hasher.finalize().to_vec();
}

fn printable_bytes(bs: &Vec<u8>) -> String {
    let mut ret = Vec::new();
    for b in bs {
        for c in ascii::escape_default(*b) {
            ret.push(c);
        }
    }
    return String::from_utf8(ret).unwrap();
}

fn printable_parts(parts: &Vec<&Vec<u8>>) -> String {
    let mut ret = String::new();
    for part in parts {
        ret += &printable_bytes(&part);
    }
    return ret;
}

fn check_guess(input: &Input, parts: &Vec<&Vec<u8>>) {
    let hashed = hash(&parts);

    if hashed == input.bytes1 {
        println!("{} matches first hash!", printable_parts(&parts));
        process::exit(0);
    }

    if hashed == input.bytes2 {
        println!("{} matches second hash!", printable_parts(&parts));
        process::exit(0);
    }

    //println!("No match for {}", printable_parts(&parts));
}

fn check_permutations(input: &Input, parts: &Vec<&Vec<u8>>) {
    let delimiters = delims();
    for perm_refs in parts.iter().permutations(parts.len()) {
        let perm = perm_refs.into_iter().map(|xs| *xs).collect();
        println!("      Permutation: {}", printable_parts(&perm));

        // Allows leading and trailing delimiter
        for delims_choice in iter::repeat(&delimiters).take(perm.len() + 1).multi_cartesian_product() {
            let guess: Vec<&Vec<u8>> = delims_choice.iter().interleave(perm.iter())
                .map(|bs| *bs).collect();
            check_guess(&input, &guess)
        }
    }
}

fn check_with_password_xform(input: &Input, xform: &dyn Fn(&Vec<u8>) -> Vec<u8>) {
    let password_variant = xform(&input.password);
    let combos: Vec<Vec<&Vec<u8>>> = vec![
        vec![&password_variant],
        vec![&password_variant, &input.email],
        vec![&password_variant, &input.seqid],
        vec![&password_variant, &input.email, &input.seqid],
    ];
    let salts = vec![&input.hex1, &input.hex2, &input.bytes1, &input.bytes2];

    for combo in combos {
        println!("  Combination: {}", printable_parts(&combo));
        println!("    Unsalted");
        check_permutations(&input, &combo);
        for salt in salts.iter() {
            println!("    With salt: {}", printable_bytes(&salt));
            let mut with_salt = combo.clone();
            with_salt.push(&salt);
            check_permutations(&input, &with_salt);
        }
    }
}

fn crack(input: Input) {
    println!("Variant: plain");
    check_with_password_xform(&input, &|p| p.clone());

    println!("Variant: SHA1");
    check_with_password_xform(&input, &|p| {
        let mut hasher = Sha1::new();
        hasher.update(&p);
        hasher.finalize().to_vec()
    });
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
