# Authentication of IoT Device and IoT Server Using Secure Vaults

This repository contains a simulation of an authentication protocol between an IoT device and an IoT server using secure vaults. The implementation showcases a secure and efficient mechanism for mutual authentication through cryptographic operations, session management, and a shared vault.

## Overview

The project demonstrates a method for establishing secure communication between an IoT device and a server. A shared vault is used as the central storage for cryptographic keys, and its state is updated after each authentication session to enhance security. The server and device exchange challenge indices to generate a combined key, which is then used for authentication and updating the vault.

## Protocol Flow

The authentication protocol consists of a four-message exchange (M1-M4) in each session:

1. **M1: Initial Contact**
   * Device sends its Device ID and Session ID to the server
   * Format: `(device_id, session_id)`

2. **M2: Server Challenge**
   * Server generates random challenge indices (C1) and nonce (r1)
   * Server sends `(C1, r1)` to the device
   * C1 determines which vault keys to combine for k1

3. **M3: Device Response and Challenge**
   * Device generates:
     - Random timestamp t1
     - Challenge indices C2
     - Nonce r2
   * Device computes k1 by XORing vault keys specified by C1
   * Device encrypts `(r1, t1, C2, r2)` using k1
   * Device sends encrypted data to server

4. **M4: Server Response**
   * Server verifies r1 from device response
   * Server computes k2 using C2 indices
   * Server generates timestamp t2
   * Server encrypts `(r2, t2)` using k2
   * Server sends encrypted response to device

After each successful session:
* Both parties compute a combined key from k1 and k2
* The vault is updated by XORing each key with the combined key
* The updated vault is saved for the next session

## File Structure

### Configuration
* `constants.py`: Defines system constants
  - Vault configuration (size, key length)
  - Network settings
  - Session parameters
  - Cryptographic settings

### Core Components
* `vault.py`: Manages the shared vault
  - Initialization
  - Loading/saving operations
  - Vault update mechanisms

* `initialize_vault.py`: Initializes the shared vault

* `utils.py`: Provides cryptographic and utility functions
  - AES encryption/decryption
  - Key combination operations
  - Data padding/unpadding
  - Random index generation

### Implementation
* `server.py`: Server-side implementation
  - Handles multiple authentication sessions
  - Manages challenge generation
  - Processes device responses
  - Updates vault state

* `device.py`: Client-side implementation
  - Initiates authentication sessions
  - Responds to server challenges
  - Generates counter-challenges
  - Synchronizes vault updates

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
