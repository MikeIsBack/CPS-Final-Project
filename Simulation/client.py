# Device-side implementation: simulates the client's multi-session operation

from hashlib import sha256
import socket
import pickle
import random
from utils import *
from vault import load_vault, update_vault
from constants import SERVER_HOST, SERVER_PORT

def device():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))

        for session_id in range(1, 4):
            print(f"Session {session_id}: Starting")

            # Load the shared vault
            vault = load_vault()

            # M1: Send device ID and session ID
            device_id = "Device123"
            m1 = pickle.dumps((device_id, session_id))
            client_socket.sendall(m1)
            print(f"M1 Sent: Device ID={device_id}, Session ID={session_id}")

            # M2: Receive challenge {C1, r1}
            data = client_socket.recv(1024)
            C1, r1 = pickle.loads(data)
            print(f"M2 Received: C1={C1}, r1={r1.hex()}")

            # M3: Compute response {Enc(k1, r1 || t1 || C2 || r2)}
            t1 = random.getrandbits(128).to_bytes(16, 'big')
            C2 = generate_random_indices(len(vault), 3)
            r2 = random.getrandbits(128).to_bytes(16, 'big')
            k1 = xor_keys(vault, C1)
            response = pickle.dumps((r1, t1, C2, r2))
            padded_response = pad_data(response)
            encrypted_response = encrypt(k1, padded_response)
            client_socket.sendall(encrypted_response)
            print(f"M3 Sent: r1={r1.hex()}, t1={t1.hex()}, C2={C2}, r2={r2.hex()}")

            # M4: Receive and process server response
            data = client_socket.recv(1024)
            k2 = xor_keys(vault, C2)
            decrypted_response = unpad_data(decrypt(k2, data))
            r2_received, t2 = pickle.loads(decrypted_response)
            print(f"M4 Received: r2={r2_received.hex()}, t2={t2.hex()}")

            # Verify r2
            if r2 != r2_received:
                print("Authentication failed: r2 mismatch")
                continue

            # Update the vault
            vault = update_vault(vault, int.from_bytes(k1, 'big') ^ int.from_bytes(k2, 'big'))
            print(f"Session {session_id}: Vault updated")

if __name__ == "__main__":
    device()
