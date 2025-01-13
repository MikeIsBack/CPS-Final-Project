# Authentication of IoT Device and IoT Server Using Secure Vaults

This repository contains a simulation of an authentication protocol between an IoT device and an IoT server using secure vaults. The implementation showcases a secure and efficient mechanism for mutual authentication through cryptographic operations, session management, and a shared vault.

## Overview

The project demonstrates a method for establishing secure communication between an IoT device and a server. A shared vault is used as the central storage for cryptographic keys, and its state is updated after each authentication session to enhance security. The server and device exchange challenge indices to generate a combined key, which is then used for authentication and updating the vault.

## Key Features

* Centralized vault management to maintain shared state between the IoT server and device
* Cryptographic operations using AES-128 for secure key management and vault updates
* Session-based mutual authentication with support for updating shared vaults after each session
* A modular and extensible design for cryptographic and session operations

## Flow of the Simulation

The simulation consists of three key steps:

1. **Vault Initialization**
   * A shared vault is initialized and stored in a centralized file (`vault.pkl`)
   * The vault contains randomly generated cryptographic keys

2. **Session-Based Authentication**
   * The IoT device generates random challenge indices and sends them to the server
   * The server computes a combined key using the shared vault and challenge indices
   * Both the server and the device update the vault using the combined key after each session

3. **Vault Updates**
   * After each session, the vault is updated using XOR operations with the combined key
   * The updated vault is saved to ensure synchronization between the device and server

## File Structure

### Configuration Files

* `constants.py`: Contains global configuration constants, including vault size, key size, network settings, and session duration

### Vault Management

* `vault.py`: Handles operations related to the shared vault, including initialization, loading, saving, and updating the vault
* `initialize_vault.py`: Initializes the shared vault and saves it to a file. Run this file to create the initial vault before starting the server or device

### Utility Functions

* `utils.py`: Contains cryptographic and utility functions, including:
  * Vault initialization
  * AES encryption and decryption
  * Generating combined keys from challenge indices

### Session Management

* `session.py`: Manages session timing, including start, end, and active session checks

### Server and Device Implementation

* `server.py`: Simulates the IoT server that:
  * Receives challenge indices from the device
  * Computes the combined key
  * Sends the combined key back to the device
  * Updates the shared vault after each session

* `client.py`: Simulates the IoT device that:
  * Generates random challenge indices
  * Sends the indices to the server
  * Receives the combined key from the server
  * Updates the shared vault after each session

## Installation and Usage

### Prerequisites

* Python 3.7 or above
* Required Python libraries:
  * `cryptography`
  * `pickle`

Install dependencies using pip:
```bash
pip install cryptography
```

### Running the Simulation

1. Initialize the Vault:
```bash
python initialize_vault.py
```

2. Start the Server:
```bash
python server.py
```

3. Start the Device:
```bash
python client.py
```

The server and client will perform three authentication sessions, updating the vault after each session.
