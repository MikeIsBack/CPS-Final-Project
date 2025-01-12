# Device-side implementation: simulates the client's multi-session operation

import socket
import pickle
import random
from vault import load_vault, update_vault
from constants import SERVER_HOST, SERVER_PORT, VAULT_SIZE

def device():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))

        for session_id in range(1, 4):  # Run 3 authentication sessions
            print(f"Session {session_id}: Starting")

            # Load the shared vault
            vault = load_vault()

            # Generate random challenge indices
            challenge_indices = random.sample(range(VAULT_SIZE), 2)

            # Send the challenge indices to the server
            client_socket.sendall(pickle.dumps(challenge_indices))

            # Receive the combined key from the server
            data = client_socket.recv(1024)
            combined_key = pickle.loads(data)

            # Update vault
            vault = update_vault(vault, combined_key)
            print(f"Session {session_id}: Vault updated")

if __name__ == "__main__":
    device()
