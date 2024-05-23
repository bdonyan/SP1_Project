use sp1_sdk::{utils, ProverClient, SP1Stdin};
use std::fs::File;
use std::io::{BufReader, Write};
use std::error::Error;
use serde::{Deserialize, Serialize};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Serialize, Deserialize)]
struct DkimData {
    original_email: String,
    selector: String,
    domain: String,
    dkim_signature: String,
    decoded_body: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    // Setup logging.
    utils::setup_logger();

    // Open the DKIM data file.
    let file = File::open("../data/dkim_data.json").expect("Failed to open DKIM data file");
    let reader = BufReader::new(file);
    let dkim_data: DkimData = serde_json::from_reader(reader).expect("Failed to parse DKIM data");

    // Create an input stream and write DKIM data to it.
    let mut stdin = SP1Stdin::new();
    stdin.write(&dkim_data);

    // Generate the proof for the given program and input.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).expect("Failed to generate proof");

    println!("generated proof");

    // Read and verify the output.
    let is_valid = proof.public_values.read::<String>().expect("Failed to read public value");
    println!("DKIM signature valid: {}", is_valid);

    // Verify proof and public values.
    client.verify(&proof, &vk).expect("Verification failed");

    // Save the proof.
    proof.save("proof-with-dkim.json").expect("Saving proof failed");

    println!("successfully generated and verified proof for the program!");

    Ok(())
}
