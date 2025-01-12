# Utility functions: provides cryptographic and utility functions

import os
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def initialize_vault(size, key_size):
    """Initialize a secure vault with random keys."""
    return [os.urandom(key_size) for _ in range(size)]

def encrypt(key, plaintext):
    """Encrypt plaintext using AES in ECB mode."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def decrypt(key, ciphertext):
    """Decrypt ciphertext using AES in ECB mode."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def get_combined_key(vault, indices):
    """Generate a combined key by XORing selected keys from the vault."""
    combined_key = int.from_bytes(vault[indices[0]], 'big')
    for index in indices[1:]:
        combined_key ^= int.from_bytes(vault[index], 'big')
    return combined_key
