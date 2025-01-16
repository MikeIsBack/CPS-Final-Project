# Vault management: handles vault initialization, loading and updates.

import os, pickle
from constants import AES_KEY_SIZE

import hmac
import hashlib

VAULT_FILE = "vault.pkl"  # Centralized storage for the vault

def initialize_shared_vault(size):
    """Initialize and store a shared vault in a file."""
    vault = [os.urandom(AES_KEY_SIZE) for _ in range(size)] 
    # Initialize the vault consisting of n keys (dictated by size) of m bits each (dictated by AES_KEY_SIZE)
    with open(VAULT_FILE, "wb") as f:
        pickle.dump(vault, f)

def load_vault():
    """Load the shared vault from the file."""
    with open(VAULT_FILE, "rb") as f:
        return pickle.load(f)

def save_vault(vault):
    """Save the updated vault to the file."""
    with open(VAULT_FILE, "wb") as f:
        pickle.dump(vault, f)

# def update_vault(vault, combined_key):
#     """Update the vault by XORing each key in the vault with the combined key."""
#     combined_key_bytes = combined_key.to_bytes(AES_KEY_SIZE, 'big')
#     updated_vault = [ # Performs the XOR operation for each byte in the vault's keys
#         bytes(k ^ c for k, c in zip(key, combined_key_bytes))
#         for key in vault
#     ]
#     save_vault(updated_vault)
#     return updated_vault

def update_vault(vault, exchanged_data):
    """
    Update the secure vault using the HMAC-based method.

    Parameters:
    - vault: Current secure vault (list of byte keys).
    - exchanged_data: Data exchanged between the server and the IoT device (bytes).

    Returns:
    - Updated secure vault (list of byte keys).
    """
    # Step 1: Compute HMAC
    h = hmac.new(exchanged_data, b''.join(vault), hashlib.sha256).digest()
    h = h[:AES_KEY_SIZE]  # Truncate HMAC output to match AES-128 key size
    
    # Step 2: Pad the vault if necessary
    vault_bytes = b''.join(vault)
    if len(vault_bytes) % AES_KEY_SIZE != 0:
        padding_size = AES_KEY_SIZE - (len(vault_bytes) % AES_KEY_SIZE)
        vault_bytes += b'\x00' * padding_size

    # Step 3: Divide the vault into partitions and update
    partitions = [
        vault_bytes[i:i + AES_KEY_SIZE]
        for i in range(0, len(vault_bytes), AES_KEY_SIZE)
    ]

    updated_vault = []
    for i, partition in enumerate(partitions):
        # Generate XOR mask (h ⊕ i)
        xor_h_i = bytes(b ^ (i % 256) for b in h)
        # Update partition by XORing with the adjusted HMAC output
        updated_partition = bytes(p ^ h_i for p, h_i in zip(partition, xor_h_i))
        updated_vault.append(updated_partition)

    # Reassemble the vault with correct key sizes (AES_KEY_SIZE)
    new_vault = [
        updated_vault[i][:AES_KEY_SIZE] for i in range(len(vault))
    ]

    # Save the updated vault
    save_vault(new_vault)
    return new_vault

