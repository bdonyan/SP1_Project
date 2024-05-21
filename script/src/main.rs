use sp1_sdk::{utils, ProverClient, SP1Stdin};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Serialize, Deserialize)]
struct DkimData {
    dkim_signature: String,
    signed_headers: HashMap<String, String>,
    body: String,
    original_email: String,
}

fn main() {
    utils::setup_logger();

    // Read DKIM data from JSON file
    let file = File::open("../data/dkim_data.json").expect("Failed to open file");
    let reader = BufReader::new(file);
    let dkim_data: DkimData = serde_json::from_reader(reader).expect("Failed to parse JSON");

    // Serialize the DKIM data to bytes
    let dkim_data_bytes = serde_json::to_vec(&dkim_data).expect("Failed to serialize DKIM data");

    let mut stdin = SP1Stdin::new();
    stdin.write(&dkim_data_bytes);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).expect("Proof generation failed");

    println!("generated proof");

    let all_signatures_passed: bool = proof.public_values.read().expect("Failed to read public values");
    println!("All signatures passed: {}", all_signatures_passed);

    client.verify(&proof, &vk).expect("Verification failed");

    proof.save("proof-with-pis.json").expect("Saving proof failed");

    println!("successfully generated and verified proof for the program!");
}
