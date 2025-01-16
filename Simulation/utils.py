# Utility: provides cryptographic and utility functions

import random
from constants import AES_KEY_SIZE
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pad_data(data):
    """Pad data to make it a multiple of the block size."""
    padder = padding.PKCS7(AES_KEY_SIZE * 8).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(data):
    """Unpad data to remove padding added during encryption."""
    unpadder = padding.PKCS7(AES_KEY_SIZE * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()

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

def generate_random_indices(vault_size):
    """Generate a list of distinct random indices."""
    count = random.randint(2, vault_size-1) # was (2,vault_size)
    return random.sample(range(vault_size), count)

def xor_keys(vault, indices):
    """XOR the keys in the vault at the specified indices."""
    result = int.from_bytes(vault[indices[0]], 'big')
    for index in indices[1:]:
        result ^= int.from_bytes(vault[index], 'big')
    return result.to_bytes(len(vault[0]), 'big')
