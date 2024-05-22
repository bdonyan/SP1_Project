use std::fs::File;
use std::io::BufReader;
use serde::{Deserialize, Serialize};
use lettre::message::{Message, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::SmtpTransport;
use lettre::transport::smtp::client::Tls;
use lettre::transport::Transport;

#[derive(Serialize, Deserialize)]
struct DkimData {
    original_email: String,
    dkim_header: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read DKIM data from JSON
    let file = File::open("../data/dkim_data.json")?;
    let reader = BufReader::new(file);
    let dkim_data: DkimData = serde_json::from_reader(reader)?;

    // Verify DKIM signature using the original email content
    match verify_dkim(&dkim_data) {
        Ok(true) => println!("DKIM signature is valid!"),
        Ok(false) => println!("DKIM signature is invalid!"),
        Err(e) => println!("Verification failed: {}", e),
    }

    Ok(())
}

fn verify_dkim(dkim_data: &DkimData) -> Result<bool, Box<dyn std::error::Error>> {
    // Use the original email content directly
    let email_message = dkim_data.original_email.as_bytes();

    // Parse the DKIM header
    let dkim_header = dkim_data.dkim_header.as_deref().ok_or("No DKIM header found")?;

    // Create a DKIM verifier
    let verifier = lettre::message::header::dkim::DkimHeader::from_raw(dkim_header)?;

    // Parse the email message
    let message = Message::parse(email_message)?;

    // Verify the DKIM signature
    let is_valid = verifier.verify(&message)?;

    // Check if the signature is valid
    Ok(is_valid)
}
