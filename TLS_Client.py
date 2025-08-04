import socket
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

# --- 1. Global Parameters (must match the server) ---
HOST = '127.0.0.1'
PORT = 65432
CURVE = ec.SECP384R1()
HASH_ALGORITHM = hashes.SHA256()


def derive_keys(shared_secret, transcript_hash):
    """
    Derive session keys from the shared secret and handshake transcript hash.
    This function must be identical to the one on the server side.
    """
    hkdf = HKDF(
        algorithm=HASH_ALGORITHM,
        length=32,  # AES-256
        salt=None,
        info=transcript_hash,
    )
    return hkdf.derive(shared_secret)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Connected to server {HOST}:{PORT}.")

        # --- 2. Simplified Handshake Process ---
        print("\n[Handshake Phase]")

        # Initialize the hasher for handshake messages
        transcript_hasher = hashes.Hash(HASH_ALGORITHM)

        # A. Client generates its own ECDH key pair
        client_private_key = ec.generate_private_key(CURVE)
        client_public_key = client_private_key.public_key()
        client_public_bytes = client_public_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        print("1. Client generated ECDH key pair.")

        # B. Send the client's public key (ClientHello)
        s.sendall(client_public_bytes)
        transcript_hasher.update(client_public_bytes)
        print("2. Sent client's public key to the server.")

        # C. Receive the server's public key (ServerHello)
        server_public_bytes = s.recv(1024)
        transcript_hasher.update(server_public_bytes)
        server_public_key = load_der_public_key(server_public_bytes)
        print("3. Received server's public key.")

        # D. Calculate the shared secret
        shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
        print("4. Calculated the shared secret.")

        # E. Derive the session key
        transcript_hash = transcript_hasher.finalize()
        session_key = derive_keys(shared_secret, transcript_hash)
        print(f"5. Derived session key using HKDF: {session_key.hex()}")

        print("[Handshake Complete]\n")

        # --- 3. Application Data Transfer Phase ---
        print("[Application Data Phase]")
        aead = AESGCM(session_key)

        # Start conversation
        for i in range(3):  # Simple demo, interact 3 times
            # Send message
            message_plaintext = input("Enter message to send to server: ")
            message_nonce = os.urandom(12)  # A new nonce must be used for each encryption
            message_ciphertext = aead.encrypt(message_nonce, message_plaintext.encode('utf-8'), None)

            # Send nonce and ciphertext
            s.sendall(message_nonce)
            s.sendall(message_ciphertext)
            print(f"Encrypted and sent message: {message_plaintext}")

            # Receive response
            response_nonce = s.recv(12)
            if not response_nonce:
                break

            response_ciphertext = s.recv(1024)

            try:
                # Decrypt and verify
                response_plaintext = aead.decrypt(response_nonce, response_ciphertext, None)
                print(f"Received and decrypted server message: {response_plaintext.decode('utf-8')}")
            except Exception as e:
                print(f"Decryption failed: {e}")
                break

        print("\nConversation ended.")


if __name__ == '__main__':
    main()