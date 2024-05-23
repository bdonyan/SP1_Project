# DKIM Verifier with Zero-Knowledge Proofs

## Overview
This project implements a DKIM (DomainKeys Identified Mail) verifier in Rust, utilizing zero-knowledge proofs (ZKPs) for secure and private verification of email signatures. By leveraging the SP1 ZKVM, we ensure the integrity and authenticity of email messages without exposing the content.

## Features
- Parses and verifies DKIM signatures from email headers.
- Generates zero-knowledge proofs for the DKIM verification process.
- Verifies proofs to ensure the DKIM verification was performed correctly.

## Prerequisites
- Rust (nightly)
- Go (version 1.22 or later)
- SP1 toolchain (installed via `sp1up`)

## Installation
1. **Clone the Repository**:
    ```bash
    git clone https://github.com/bdonyan/SP1_Project
    cd dkim-verifier-zkp
    ```

2. **Install Dependencies**:
    ```bash
    cd program
    cargo build
    cd ../script
    cargo build
    ```

3. **Install SP1 Toolchain**:
    ```bash
    curl -L https://sp1.succinct.xyz | bash
    sp1up
    ```

## Usage
1. **Build the DKIM Verifier**:
    ```bash
    cd program
    cargo prove build
    ```

2. **Generate and Verify Proofs**:
    ```bash
    cd script
    RUST_LOG=info cargo run --release
    ```

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact
For any questions or issues, please open an issue on GitHub or contact the project maintainer at [branyan@seas.upenn.edu](mailto:your.email@example.com).
