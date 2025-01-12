# Server-side implementation: simulates the server's multi-session operation

import socket
import pickle
from session import SessionManager
from vault import load_vault, save_vault
from utils import get_combined_key
from vault import update_vault
from constants import SERVER_HOST, SERVER_PORT

def server():
    session_manager = SessionManager(duration=10)

    # Set up the server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen(1)
        print(f"Server listening on port {SERVER_PORT}")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected to {addr}")

            for session_id in range(1, 4):  # Run 3 authentication sessions
                print(f"Session {session_id}: Starting")
                session_manager.start_session()

                # Load the shared vault
                vault = load_vault()

                # Receive the challenge indices from the device
                data = conn.recv(1024)
                challenge_indices = pickle.loads(data)

                # Compute the combined key
                combined_key = get_combined_key(vault, challenge_indices)

                # Send the combined key back to the client
                conn.sendall(pickle.dumps(combined_key))

                # Wait for session to end
                while session_manager.is_session_active():
                    pass

                # Update vault and save it back to the shared file
                vault = update_vault(vault, combined_key)
                print(f"Session {session_id}: Vault updated")

if __name__ == "__main__":
    server()
