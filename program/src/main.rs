#![no_main]
sp1_zkvm::entrypoint!(main);

use std::fs::File;
use std::io::{BufReader, Write};
use std::error::Error;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use base64;
use mailparse::{parse_mail, MailHeaderMap};
use sp1_sdk::{utils, ProverClient, SP1Stdin};

#[derive(Deserialize, Serialize)]
struct DkimData {
    original_email: String,
    selector: String,
    domain: String,
    dkim_signature: String,
    decoded_body: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DkimResult {
    Pass,
    Neutral(String),
    Fail(String),
    PermError(String),
    TempError(String),
    None,
}

fn parse_dkim_signature(dkim_signature: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let mut sig_map = HashMap::new();
    for part in dkim_signature.split(';') {
        let mut kv = part.split('=');
        if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
            sig_map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(sig_map)
}

fn fetch_public_key(selector: &str, domain: &str) -> Result<String, Box<dyn Error>> {
    let query = format!("{}._domainkey.{}", selector, domain);
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let server = "8.8.8.8:53"; // Google's public DNS server
    let mut buf = [0u8; 512];
    let len = {
        let mut req = vec![];
        req.write_all(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;
        for label in query.split('.') {
            req.write_all(&[label.len() as u8])?;
            req.write_all(label.as_bytes())?;
        }
        req.write_all(&[0x00, 0x00, 0x01, 0x00, 0x01])?;
        socket.send_to(&req, server)?;
        socket.recv(&mut buf)?
    };
    let response_bytes = &buf[12..len];
    let response = String::from_utf8_lossy(response_bytes);
    println!("DNS Response Bytes: {:?}", response_bytes);
    println!("DNS Response: {}", response);
    if response.is_empty() {
        return Err("Public key not found".into());
    }
    Ok(response.to_string())
}

fn verify_dkim_signature(
    dkim_signature: &HashMap<String, String>,
    public_key: &str,
    original_email: &str,
) -> Result<bool, Box<dyn Error>> {
    let body_hash = dkim_signature.get("bh").ok_or("Missing body hash")?;
    let signature = dkim_signature.get("b").ok_or("Missing signature")?;
    let computed_body_hash = base64::encode(Sha256::digest(original_email.as_bytes()));
    println!("Body Hash (Rust): {:?}", body_hash);
    println!("Computed Body Hash (Rust): {:?}", computed_body_hash);
    println!("Signature (Rust): {:?}", signature);
    println!("Public Key (Rust): {:?}", public_key);
    Ok(body_hash == &computed_body_hash && signature == public_key)
}

fn verify_dkim(dkim_data: DkimData) -> Result<(), Box<dyn Error>> {
    let parsed = parse_mail(dkim_data.original_email.as_bytes())?;
    println!("Parsed Email Headers: {:?}", parsed.headers);

    let subject = parsed.headers.get_first_value("Subject").unwrap_or_else(|| Some("No Subject".to_string()));
    let body = dkim_data.decoded_body;

    println!("Subject: {:?}", subject);
    println!("Body: {:?}", body);

    let dkim_signature = parse_dkim_signature(&dkim_data.dkim_signature)?;

    let public_key = fetch_public_key(&dkim_data.selector, &dkim_data.domain)?;

    let is_valid = verify_dkim_signature(&dkim_signature, &public_key, &dkim_data.original_email)?;

    println!("DKIM signature valid: {}", is_valid);

    sp1_zkvm::io::commit(&is_valid.to_string());

    Ok(())
}

fn main() {
    match run() {
        Ok(_) => println!("Program executed successfully."),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let file = File::open("../data/dkim_data.json")?;
    let reader = BufReader::new(file);
    let dkim_data: DkimData = serde_json::from_reader(reader)?;

    println!("Original Email Content:\n{}", dkim_data.original_email);
    println!("Decoded Body Content:\n{}", dkim_data.decoded_body);
    println!("Selector: {:?}", dkim_data.selector);
    println!("Domain: {:?}", dkim_data.domain);

    verify_dkim(dkim_data)?;

    Ok(())
}
