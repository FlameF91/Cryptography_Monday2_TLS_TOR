import socket
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

# --- 1. Global Parameters (as required: no negotiation) ---
HOST = '127.0.0.1'
PORT = 65432
# Use P-384 elliptic curve
CURVE = ec.SECP384R1()
# Use SHA-256 for hashing
HASH_ALGORITHM = hashes.SHA256()


def derive_keys(shared_secret, transcript_hash):
    """
    Derive session keys from the shared secret and handshake transcript hash.
    This mimics the key derivation process of TLS 1.3.
    """
    # Use HKDF to derive the encryption key
    hkdf = HKDF(
        algorithm=HASH_ALGORITHM,
        length=32,  # AES-256 requires a 32-byte key
        salt=None,
        info=transcript_hash,
    )
    return hkdf.derive(shared_secret)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server is listening on {HOST}:{PORT}...")
        conn, addr = s.accept()
        with conn:
            print(f"Client {addr} has connected.")

            # --- 2. Simplified Handshake Process ---
            print("\n[Handshake Phase]")

            # Initialize the hasher for handshake messages
            transcript_hasher = hashes.Hash(HASH_ALGORITHM)

            # A. Server generates its own ECDH key pair
            server_private_key = ec.generate_private_key(CURVE)
            server_public_key = server_private_key.public_key()
            # Serialize the public key for transmission
            server_public_bytes = server_public_key.public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            print("1. Server generated ECDH key pair.")

            # B. Receive the client's public key (ClientHello)
            client_public_bytes = conn.recv(1024)
            transcript_hasher.update(client_public_bytes)  # Update the hash
            client_public_key = load_der_public_key(client_public_bytes)
            print("2. Received client's public key.")

            # C. Send the server's public key (ServerHello)
            conn.sendall(server_public_bytes)
            transcript_hasher.update(server_public_bytes)  # Update the hash
            print("3. Sent server's public key to the client.")

            # D. Calculate the shared secret
            shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
            print("4. Calculated the shared secret.")

            # E. Derive the session key
            transcript_hash = transcript_hasher.finalize()
            session_key = derive_keys(shared_secret, transcript_hash)
            print(f"5. Derived session key using HKDF: {session_key.hex()}")

            print("[Handshake Complete]\n")

            # --- 3. Application Data Transfer Phase ---
            print("[Application Data Phase]")
            aead = AESGCM(session_key)

            while True:
                # Receive data
                # Simple protocol: first 12 bytes are nonce, the rest is ciphertext
                nonce = conn.recv(12)
                if not nonce:
                    break

                # We need to know the ciphertext length; here we just assume a max value
                ciphertext = conn.recv(1024)

                try:
                    # Decrypt and verify data using AEAD
                    plaintext = aead.decrypt(nonce, ciphertext, None)
                    print(f"Received and decrypted client message: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"Decryption failed: {e}")
                    break

                # Send a response
                response_plaintext = input("Enter message to send to client: ")
                response_nonce = os.urandom(12)  # A new nonce must be used for each encryption
                response_ciphertext = aead.encrypt(response_nonce, response_plaintext.encode('utf-8'), None)

                # Send nonce and ciphertext
                conn.sendall(response_nonce)
                conn.sendall(response_ciphertext)
                print(f"Encrypted and sent message: {response_plaintext}")


if __name__ == '__main__':
    main()