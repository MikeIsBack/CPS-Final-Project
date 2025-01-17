from constants import VAULT_SIZE
from vault import initialize_shared_vault
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize the secure vault.")
    parser.add_argument("--key-size", type=int, choices=[16, 32], default=16,
                        help="Key size in bytes (16 for AES-128, 32 for AES-256).")
    args = parser.parse_args()

    initialize_shared_vault(VAULT_SIZE, key_size=args.key_size)
    print(f"Shared vault initialized with key size {args.key_size * 8} bits.")
