# Secure Handshake Protocol (SHP) - Phase 1

## Project Overview

This project implements the **Secure Handshake Protocol (SHP)** for mutual authentication and cryptographic configuration exchange between a client and a server. SHP ensures authentication, confidentiality, integrity, and message replay protection during client-server communications. The implementation uses Java and incorporates the Bouncy Castle cryptographic library for robust cryptographic operations.

### Key Features
- **Mutual Authentication**: Using ECDSA digital signatures.
- **Confidentiality**: Through Password-Based Encryption (PBE) and ECIES.
- **Integrity**: Ensured with HMAC and protected nonces.
- **Replay Protection**: Using unique nonces and sequence checks.

The protocol operates over a TCP connection and exchanges five message types between the client and server.

---

## Folder Structure

```
project-root/
├── lib/
│   └── bcprov-jdk18on-1.79.jar   # Bouncy Castle library
├── src/
│   ├── SHPClient.java            # Client implementation
│   ├── SHPServer.java            # Server implementation
│   ├── TestClient.java           # Test class for the client
│   └── TestServer.java           # Test class for the server
├── out/                          # Compiled class files (generated during execution)
├── TestImpl.sh                   # Bash script to compile and test the project
├── testStreaming.sh              # Bash script to compile and test Streaming service using SHP
├── testTFTP.sh                   # Bash script to compile and test TFTP service using SHP
├── WorkingTools/                 # Directory with the different test benches
├── userdatabase.txt              # User's database file according to the specification
└── README.md                     # Project documentation
```

---

## Test Scripts

This project includes a Bash script to compile the source files and execute the test classes:

- **`TestImpl.sh`**:
    - Compiles all Java source files in the `src` directory.
    - Includes the Bouncy Castle library (`lib/bcprov-jdk18on-1.79.jar`) in the compilation process.
    - Starts the `TestServer` and then the `TestClient` to demonstrate the SHP handshake process.
- 
- **`testStreaming.sh`**:
    - Uses the `WorkingTools/StreamingService` testbench.
    - Compiles all Java source files in the `hjStreamServer` and `hjUDPproxy` directories.
    - Includes the Bouncy Castle library (`lib/bcprov-jdk18on-1.79.jar`) in the compilation process.
    - Starts the `hjUDPProxy` and then the `hjStreamServer` to demonstrate the SHP handshake process on a streaming application.
- **`testTFTP.sh`**:
    - Uses the `WorkingTools/TFTP` testbench.
    - Compiles all Java source files in the `TFTPClient` and `TFTPServer` directories.
    - Includes the Bouncy Castle library (`lib/bcprov-jdk18on-1.79.jar`) in the compilation process.
    - Starts the `TFTPServer` and then the `TFTPClient` to demonstrate the SHP handshake process on file transfer application.

### How to Run the Tests

1. Ensure you have Java installed and available in your system's PATH.
2. Make the `run.sh` script executable:
   ```bash
   chmod +x TestImpl.sh
   ```
3. Execute the script:
   ```bash
   ./TestImpl.sh
   ```

This will:
- Start the server (`TestServer`) in the background.
- Run the client (`TestClient`) to initiate and complete the handshake protocol.
- Terminate the server automatically after the test.

---

## SHP Implementation

### Message Types
1. **Message Type 1**: The client sends its user ID.
2. **Message Type 2**: The server responds with three secure nonces.
3. **Message Type 3**: The client sends encrypted and signed authentication data.
4. **Message Type 4**: The server sends cryptographic configurations and confirms the client's request.
5. **Message Type 5**: The client acknowledges the server's configurations and finalizes the handshake.

### Key Classes
- **`SHPClient`**: Implements the client-side logic for initiating and completing the handshake protocol.
- **`SHPServer`**: Implements the server-side logic for responding to client messages and establishing cryptographic configurations.
- **`TestClient`**: Demonstrates the client-side SHP workflow.
- **`TestServer`**: Demonstrates the server-side SHP workflow.

---

## Dependencies

- **Bouncy Castle Cryptographic Library**:
    - File: `lib/bcprov-jdk18on-1.79.jar`
    - Download: [Bouncy Castle Website](https://www.bouncycastle.org/)
- **Java Development Kit (JDK)**:
    - Version: 11 or later recommended

---

Feel free to reach out if you encounter issues or have questions about the project!
