# Device-side implementation: simulates the client's multi-session operation

import random, socket, pickle
from constants import SERVER_HOST, SERVER_PORT, HASH_SIZE
from vault import load_vault, update_vault
from utils import decrypt, encrypt, generate_random_indices, pad_data, unpad_data, xor_keys

def device():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))

        n_emulated_sessions = 5

        for session_id in range(0, n_emulated_sessions):
            print(f"\nSession {session_id}: Starting")

            # Load the shared vault
            vault = load_vault()

            # M1: Send device ID and session ID
            device_id = "Device123"
            m1 = pickle.dumps((device_id, session_id))
            client_socket.sendall(m1)
            print(f"M1 Sent: Device ID={device_id}, Session ID={session_id}")

            # M2: Receive challenge {C1, r1}
            data = client_socket.recv(1024) # Device waits for the challenge sent by the server. 1024 is max number of bytes to receive in one call
            C1, r1 = pickle.loads(data)
            print(f"M2 Received: C1={C1}, r1={r1.hex()}")

            # M3: Compute response {Enc(k1, r1 || t1 || {C2, r2})}
            k1 = xor_keys(vault, C1)
            t1 = random.getrandbits(128).to_bytes(16, 'big')
            C2 = generate_random_indices(len(vault))
            r2 = random.getrandbits(128).to_bytes(16, 'big')
            response = pickle.dumps((r1, t1, C2, r2))
            padded_response = pad_data(response)
            encrypted_response = encrypt(k1, padded_response)
            client_socket.sendall(encrypted_response)
            print(f"M3 Sent: r1={r1.hex()}, t1={t1.hex()}, C2={C2}, r2={r2.hex()}")

            # M4: Receive and process server response
            data = client_socket.recv(1024)
            k2 = xor_keys(vault, C2)
            decryption_key = int.from_bytes(k2, 'big') ^ int.from_bytes(t1, 'big')
            decryption_key = decryption_key.to_bytes(len(k2), 'big')

            decrypted_response = unpad_data(decrypt(decryption_key, data))
            r2_received, t2 = pickle.loads(decrypted_response)
            print(f"M4 Received: r2={r2_received.hex()}, t2={t2.hex()}")

            # Verify r2
            if r2 != r2_received:
                print("Authentication failed: r2 mismatch")
                continue

            # Update the vault
            exchanged_data = (int.from_bytes(k1, 'big') ^ int.from_bytes(k2, 'big')).to_bytes(len(k1), 'big')
            vault = update_vault(vault, exchanged_data, HASH_SIZE) #vault = update_vault(vault, int.from_bytes(k1, 'big') ^ int.from_bytes(k2, 'big'), HASH_SIZE)
            print(f"Session {session_id}: Vault updated")

if __name__ == "__main__":
    device()
