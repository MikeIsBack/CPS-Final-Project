# Configuration and constants: defines shared settings for the vault, network, and timing.

# Vault Settings
VAULT_SIZE = 4         # Number of keys in the vault
AES_KEY_SIZE = 16      # Length of each key in bytes (AES-128)
HASH_SIZE = 256        # Using SHA-256 (output size = 256 bits)

# Session Settings
SESSION_DURATION = 10  # Session duration in seconds

# Network Settings
SERVER_HOST = 'localhost'
SERVER_PORT = 5000
