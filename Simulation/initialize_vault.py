from constants import VAULT_SIZE
from vault import initialize_shared_vault

if __name__ == "__main__":
    initialize_shared_vault(VAULT_SIZE)
    print("Shared vault initialized.")
