/// Attempt to reverse-engineer Avvo.com's hash algorithm, given a leaked
/// record and a known password.
///
/// Sample for validation of hash checker:
///
/// $ cat ~/tmp/ram/sample-record.txt
/// some@email,1199546,3e6139dd5bba6c8617c112abdb026a648e9bf592,8e1d0e47d92636c1673580f8c2d25985721654f5,NULL
///
/// $ cat ~/tmp/ram/sample-password.txt
/// hello
///
/// $ avvo-reverse ~/tmp/ram/sample-record.txt ~/tmp/ram/sample-password.txt
/// FOUND! Matched second hash with SHA-1: input=b'|hello:some@email/1199546::3e6139dd5bba6c8617c112abdb026a648e9bf592|'

use generic_array::{GenericArray};
use generic_array::typenum::U20;
use hmac_sha1_compact::HMAC;
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

    Input {
        email: record_parts[0].as_bytes().to_owned(),
        seqid: record_parts[1].as_bytes().to_owned(),
        hex1,
        hex2,
        bytes1,
        bytes2,
        password: password_raw.split('\n').next().expect("Password split had zero items").as_bytes().to_owned(),
    }
}

fn delims() -> Vec<Vec<u8>> {
    // Start with the empty "delimiter"
    let mut delimiters: Vec<Vec<u8>> = vec![Vec::new()];

    // Add all non-alpanumeric printable ASCII
    for c in "`-=[]\\;',./~!@#$%^&*()_+{}|:\"<>? ".chars() {
        delimiters.push(c.to_string().as_bytes().to_owned());
    }

    // Add in some likely other delims
    for other in &["::", "||", "--"] {
        delimiters.push(other.as_bytes().to_owned());
    }

    delimiters
}

fn printable_bytes(bs: &[u8]) -> String {
    let mut ret = Vec::new();
    for b in bs {
        for c in ascii::escape_default(*b) {
            ret.push(c);
        }
    }
    String::from_utf8(ret).unwrap()
}

fn printable_parts(parts: &Vec<&[u8]>) -> String {
    let mut ret = String::new();
    for part in parts {
        ret += &printable_bytes(part);
    }
    ret
}

/// At least three orders of magnitude slower (e.g. 2.5 hours rather than 6 seconds)
const ALLOW_OUTER_DELIMS: bool = true;

fn check_permutations(parts: &[&[u8]], target: &GenericArray<u8, U20>) -> u32 {
    let delimiters: Vec<Vec<u8>> = delims();

    let mut ct = 0;
    let mut hasher = Sha1::new();

    let parts_len = parts.len();

    for perm in parts.iter().permutations(parts_len) {
        let perm = perm.into_iter().copied().collect();
        println!("      Permutation: {}", printable_parts(&perm));

        let delim_count = if ALLOW_OUTER_DELIMS { perm.len() + 1 } else { perm.len() - 1 };
        for delims_choice in iter::repeat(&delimiters).take(delim_count).multi_cartesian_product() {
            let mut delims_choice_iter = delims_choice.iter();

            for (piece_num, piece) in perm.iter().enumerate() {
                if ALLOW_OUTER_DELIMS || piece_num > 0 {
                    hasher.update(delims_choice_iter.next().unwrap());
                }
                hasher.update(piece);
            }
            if ALLOW_OUTER_DELIMS {
                hasher.update(delims_choice_iter.next().unwrap());
            }

            if hasher.finalize_reset() == *target {
                let guess_perms: Vec<&[u8]> = perm;
                let guess_delims: Vec<&[u8]> = delims_choice.into_iter().map(|x| x.as_slice()).collect();
                let (stream1, stream2) = if ALLOW_OUTER_DELIMS {
                    (guess_delims, guess_perms)
                } else {
                    (guess_perms, guess_delims)
                };
                let guess: Vec<&[u8]> = stream1.into_iter().interleave(stream2).collect();
                println!("FOUND! Matched hash {} with SHA-1 of {}",
                         printable_bytes(target), printable_parts(&guess));
                process::exit(0);
            }

            ct += 1;
        }
    }
    ct
}

fn check_with_password_xform(input: &Input, xform: &dyn Fn(&Vec<u8>) -> Vec<u8>) {
    let password_variant = xform(&input.password);
    let combos: Vec<Vec<&[u8]>> = vec![
        vec![&password_variant],
        vec![&password_variant, &input.email],
        vec![&password_variant, &input.seqid],
        vec![&password_variant, &input.email, &input.seqid],
    ];
    let salts_and_targets = vec![
        (&input.hex1, &input.bytes2),
        (&input.hex2, &input.bytes1),
        (&input.bytes1, &input.bytes2),
        (&input.bytes2, &input.bytes1),
    ];
    let mut ct = 0;

    for combo in combos {
        println!("  Combination: {}", printable_parts(&combo));
        println!("    Unsalted");
        ct += check_permutations(&combo, GenericArray::from_slice(&input.bytes1));
        ct += check_permutations(&combo, GenericArray::from_slice(&input.bytes2));
        for (salt, target) in salts_and_targets.iter() {
            println!("    With salt: {}", printable_bytes(salt));
            let mut salted_combo = combo.clone();
            salted_combo.push(salt);
            ct += check_permutations(&salted_combo, GenericArray::from_slice(target));
        }
    }
    println!("Checked with transform: {}", ct);
}

fn check_hmac(input: &Input, key: &[u8], maybe_mac: &[u8]) {
    let mac = HMAC::mac(&input.password, key).to_vec();
    if mac == maybe_mac {
        println!("FOUND! Matched hash {} with HMAC using key {}",
                 printable_bytes(maybe_mac), printable_bytes(key));
        process::exit(0);
    }
}

fn crack(input: Input) {
    println!("HMAC-SHA1");
    check_hmac(&input, &input.bytes1, &input.bytes2);
    check_hmac(&input, &input.hex1, &input.bytes2);
    check_hmac(&input, &input.bytes2, &input.bytes1);
    check_hmac(&input, &input.hex2, &input.bytes1);

    println!("SHA-1: Plain password");
    check_with_password_xform(&input, &|p| p.clone());

    println!("SHA-1: Prehash password with SHA-1");
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
            println!("Usage: avvo-reverse <record_file> <password_file>");
            println!("It is strongly recommended that you build with --release flag for performance.");
            process::exit(1);
        }
    }
}
