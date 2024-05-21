use mail_auth::{AuthenticatedMessage, DkimResult, Resolver};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

#[derive(Serialize, Deserialize)]
struct DkimData {
    dkim_signature: String,
    signed_headers: HashMap<String, String>,
    body: String,
    original_email: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read DKIM data from JSON file
    let file = File::open("../data/dkim_data.json")?;
    let reader = BufReader::new(file);
    let dkim_data: DkimData = serde_json::from_reader(reader)?;

    // Verify the DKIM signature using the original email content
    match verify_dkim(&dkim_data).await {
        Ok(true) => println!("DKIM signature is valid!"),
        Ok(false) => println!("DKIM signature is invalid!"),
        Err(e) => println!("Verification failed: {}", e),
    }

    Ok(())
}

async fn verify_dkim(dkim_data: &DkimData) -> Result<bool, Box<dyn std::error::Error>> {
    // Create a resolver using Google's DNS
    let resolver = Resolver::new_google().map_err(|e| format!("Failed to create DNS resolver: {}", e))?;

    // Use the original email content directly
    let email_message = dkim_data.original_email.as_bytes();

    // Debug: Print the email content
    // println!("Email Content:\n{}", String::from_utf8_lossy(email_message));

    // Parse the authenticated message
    let authenticated_message = AuthenticatedMessage::parse(email_message)
        .ok_or("Failed to parse authenticated message")?;

    // Debug: Print the authenticated message
    // println!("Authenticated Message:\n{:?}", authenticated_message);

    // Validate the DKIM signature asynchronously
    let result = resolver.verify_dkim(&authenticated_message).await;

    // Debug: Print the verification result
    // println!("Verification Result:\n{:?}", result);

    // Check if all signatures passed verification
    let all_signatures_passed = result.iter().all(|s| s.result() == &DkimResult::Pass);

    sp1_zkvm::io::commit(&all_signatures_passed);

    // Return the result
    Ok(all_signatures_passed)
}
