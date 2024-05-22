use std::fs::File;
use std::io::BufReader;
use std::error::Error;
use mail_auth::{AuthenticatedMessage, DkimResult, Resolver};
use serde::Deserialize;
use mailparse::{parse_mail, MailHeaderMap};
use tokio::runtime::Runtime;

#[derive(Deserialize)]
struct DkimData {
    original_email: String,
    selector: String,
    domain: String,
    decoded_body: String,
}

fn verify_dkim(dkim_data: DkimData) -> Result<(), Box<dyn Error>> {
    // Parse the email using mailparse
    let parsed = parse_mail(dkim_data.original_email.as_bytes())?;
    println!("Parsed Email Headers: {:?}", parsed.headers);

    // Extract the subject and body
    let subject = parsed.headers.get_first_value("Subject").unwrap_or_else(|| "No Subject".to_string());
    let body = dkim_data.decoded_body;

    println!("Subject: {:?}", subject);
    println!("Body: {:?}", body);

    // Create a resolver
    let resolver = Resolver::new_google().unwrap();

    // Parse the authenticated message
    let authenticated_message = AuthenticatedMessage::parse(dkim_data.original_email.as_bytes()).unwrap();

    // Validate the DKIM signature synchronously
    let runtime = Runtime::new().unwrap();
    let result = runtime.block_on(resolver.verify_dkim(&authenticated_message));

    // Check if all signatures passed verification
    if result.iter().all(|s| s.result() == &DkimResult::Pass) {
        println!("DKIM signature is valid.");
    } else {
        println!("DKIM signature verification failed.");
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let file = File::open("../data/dkim_data.json")?;
    let reader = BufReader::new(file);
    let dkim_data: DkimData = serde_json::from_reader(reader)?;

    // Print the email content to debug
    println!("Original Email Content:\n{}", dkim_data.original_email);
    println!("Decoded Body Content:\n{}", dkim_data.decoded_body);

    // Print the selector and domain to debug
    println!("Selector: {:?}", dkim_data.selector);
    println!("Domain: {:?}", dkim_data.domain);

    // Verify DKIM
    verify_dkim(dkim_data)?;

    Ok(())
}
