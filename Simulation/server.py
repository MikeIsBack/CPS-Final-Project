# Server-side implementation: simulates the server's multi-session operation

import random
import socket
import pickle
from vault import load_vault
from utils import decrypt, encrypt, generate_random_indices, get_combined_key, pad_data, unpad_data, xor_keys
from vault import update_vault
from constants import *

def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen(1)
        print(f"Server listening on port {SERVER_PORT}")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected to {addr}")

            for session_id in range(1, 4):
                print(f"Session {session_id}: Starting")

                # Load the shared vault
                vault = load_vault()

                # M1: Receive device ID and session ID
                data = conn.recv(1024)
                device_id, received_session_id = pickle.loads(data)
                print(f"M1 Received: Device ID: {device_id}, Session ID: {received_session_id}")

                # M2: Generate and send challenge {C1, r1}
                C1 = generate_random_indices(len(vault), 3)
                r1 = random.getrandbits(128).to_bytes(16, 'big')
                conn.sendall(pickle.dumps((C1, r1)))
                print(f"M2 Sent: C1={C1}, r1={r1.hex()}")

                # M3: Receive and process the response
                data = conn.recv(1024)
                encrypted_response = data
                k1 = xor_keys(vault, C1)
                decrypted_response = unpad_data(decrypt(k1, encrypted_response))
                r1_received, t1, C2, r2 = pickle.loads(decrypted_response)
                print(f"M3 Received: r1={r1_received.hex()}, t1={t1.hex()}, C2={C2}, r2={r2.hex()}")

                # Verify r1
                if r1 != r1_received:
                    print("Authentication failed: r1 mismatch")
                    continue

                # M4: Generate and send response {Enc(k2, r2 || t2)}
                t2 = random.getrandbits(128).to_bytes(16, 'big')
                k2 = xor_keys(vault, C2)
                response = pickle.dumps((r2, t2))
                padded_response = pad_data(response)
                encrypted_response = encrypt(k2, padded_response)
                conn.sendall(encrypted_response)
                print(f"M4 Sent: r2={r2.hex()}, t2={t2.hex()}")

                # Update the vault
                vault = update_vault(vault, int.from_bytes(k1, 'big') ^ int.from_bytes(k2, 'big'))
                print(f"Session {session_id}: Vault updated")

if __name__ == "__main__":
    server()
