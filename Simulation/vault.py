# Vault management: handles vault initialization, loading and updates.

import os, pickle
from constants import AES_KEY_SIZE

VAULT_FILE = "vault.pkl"  # Centralized storage for the vault

def initialize_shared_vault(size):
    """Initialize and store a shared vault in a file."""
    vault = [os.urandom(AES_KEY_SIZE) for _ in range(size)]
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

def update_vault(vault, combined_key):
    """Update the vault by XORing each key in the vault with the combined key."""
    combined_key_bytes = combined_key.to_bytes(AES_KEY_SIZE, 'big')
    updated_vault = [
        bytes(k ^ c for k, c in zip(key, combined_key_bytes))
        for key in vault
    ]
    save_vault(updated_vault)
    return updated_vault
