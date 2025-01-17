# Vault management: handles vault initialization, loading and updates.

import os, pickle, hmac, hashlib
from constants import AES_KEY_SIZE, AES_KEY_SIZES

VAULT_FILE = "vault.pkl"  # Centralized storage for the vault

def initialize_shared_vault(size, key_size=AES_KEY_SIZE):
    """Initialize and store a shared vault in a file."""
    if key_size not in AES_KEY_SIZES:
        raise ValueError(f"Invalid key size. Must be one of {AES_KEY_SIZES}.")
    vault = [os.urandom(key_size) for _ in range(size)]
    with open(VAULT_FILE, "wb") as f:
        pickle.dump({"key_size": key_size, "vault": vault}, f)

def load_vault():
    """Load the shared vault from the file."""
    with open(VAULT_FILE, "rb") as f:
        data = pickle.load(f)
    return data["vault"], data["key_size"]

def save_vault(vault, key_size):
    """Save the updated vault and key size to the file."""
    with open(VAULT_FILE, "wb") as f:
        pickle.dump({"vault": vault, "key_size": key_size}, f)

def update_vault(vault, exchanged_data, key_size=AES_KEY_SIZE):
    """Update the secure vault using the HMAC-based method."""
    if key_size not in AES_KEY_SIZES:
        raise ValueError(f"Invalid key size. Must be one of {AES_KEY_SIZES}.")

    # Compute HMAC
    h = hmac.new(exchanged_data, b''.join(vault), hashlib.sha256).digest()
    h = h[:key_size]

    # Pad the vault if necessary
    vault_bytes = b''.join(vault)
    if len(vault_bytes) % key_size != 0:
        padding_size = key_size - (len(vault_bytes) % key_size)
        vault_bytes += b'\x00' * padding_size

    # Divide the vault into partitions and update
    partitions = [vault_bytes[i:i + key_size] for i in range(0, len(vault_bytes), key_size)]

    updated_vault = []
    for i, partition in enumerate(partitions):
        xor_h_i = bytes(b ^ (i % 256) for b in h)
        updated_partition = bytes(p ^ h_i for p, h_i in zip(partition, xor_h_i))
        updated_vault.append(updated_partition)

    # Reassemble the vault with correct key sizes
    new_vault = [updated_vault[i][:key_size] for i in range(len(vault))]

    save_vault(new_vault, key_size)
    return new_vault
