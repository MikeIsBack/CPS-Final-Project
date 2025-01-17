# Configuration and constants: defines shared settings for the vault, network, and timing.

# Vault Settings
VAULT_SIZE = 4         # Number of keys in the vault
AES_KEY_SIZE = 16      # Default length of each key in bytes (AES-128)
AES_KEY_SIZES = [16, 32]  # Possible key sizes for AES (128-bit, 256-bit)

# Network Settings
SERVER_HOST = 'localhost'
SERVER_PORT = 5000
