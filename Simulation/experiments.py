import os, time, itertools
from constants import AES_KEY_SIZE
from vault import load_vault

def generate_random_vault(size, key_size):
    """Generate a random vault with the specified size and key length."""
    return [os.urandom(key_size) for _ in range(size)]

def brute_force_vault(actual_vault, key_size, vault_size):
    """Perform a brute force attack to guess the vault content."""
    print(f"Starting brute force vault prediction...")
    attempts = 0
    start_time = time.time()

    # Since key_space = 256^(key_size * vault_size) is enormous, we simulate random guess instead of linearly trying all the combinations
    while True:
        attempts += 1
        guessed_vault = generate_random_vault(vault_size, key_size)

        if guessed_vault == actual_vault:
            break

        if attempts % 100000 == 0:
            print(f"Attempts: {attempts} - Still guessing...")

    elapsed_time = time.time() - start_time
    return attempts, elapsed_time

def brute_force_vault_key_by_key(actual_vault, key_size):
    """Perform a brute force attack to guess the vault content key by key."""
    print(f"Starting brute force attack (key-by-key)...")
    attempts = 0
    start_time = time.time()

    guessed_vault = []

    for key_index, actual_key in enumerate(actual_vault):
        print(f"Guessing key {key_index + 1} of {len(actual_vault)}...")
        key_found = False

        # Iterate over all possible combinations for the current key
        for candidate_key in itertools.product(range(256), repeat=key_size):
            attempts += 1
            candidate_key_bytes = bytes(candidate_key)

            # Check if the candidate key matches the actual key
            if candidate_key_bytes == actual_key:
                print(f"Key {key_index + 1} guessed correctly after {attempts} attempts.")
                guessed_vault.append(candidate_key_bytes)
                key_found = True
                break

        if not key_found:
            print(f"Failed to guess key {key_index + 1} (unexpected behavior).")
            break

    elapsed_time = time.time() - start_time
    return attempts, elapsed_time

if __name__ == "__main__":
    actual_vault = load_vault()

    attempts, elapsed_time = brute_force_vault_key_by_key(actual_vault, AES_KEY_SIZE)

    print(f"Brute force attack successful!")
    print(f"Attempts: {attempts}")
    print(f"Time Taken: {elapsed_time:.2f} seconds")
