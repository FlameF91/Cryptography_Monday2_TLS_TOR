# tls_socket.py
import socket
import os
import json
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

# --- 全局参数 ---
CURVE = ec.SECP384R1()
HASH_ALGORITHM = hashes.SHA256()


def derive_keys(shared_secret, transcript_hash):
    hkdf = HKDF(
        algorithm=HASH_ALGORITHM,
        length=32,
        salt=None,
        info=transcript_hash,
    )
    return hkdf.derive(shared_secret)


class TLSSocket:
    def __init__(self, sock, aead_cipher=None):
        self.sock = sock
        self.aead = aead_cipher

    def _perform_client_handshake(self):
        transcript_hasher = hashes.Hash(HASH_ALGORITHM)

        client_private_key = ec.generate_private_key(CURVE)
        client_public_key = client_private_key.public_key()
        client_public_bytes = client_public_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        self.sock.sendall(client_public_bytes)
        transcript_hasher.update(client_public_bytes)

        server_public_bytes = self.sock.recv(1024)
        transcript_hasher.update(server_public_bytes)
        server_public_key = load_der_public_key(server_public_bytes)

        shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
        transcript_hash = transcript_hasher.finalize()
        session_key = derive_keys(shared_secret, transcript_hash)
        self.aead = AESGCM(session_key)
        print("[TLS] Client handshake complete.")

    def _perform_server_handshake(self):
        transcript_hasher = hashes.Hash(HASH_ALGORITHM)

        server_private_key = ec.generate_private_key(CURVE)
        server_public_key = server_private_key.public_key()
        server_public_bytes = server_public_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )

        client_public_bytes = self.sock.recv(1024)
        transcript_hasher.update(client_public_bytes)
        client_public_key = load_der_public_key(client_public_bytes)

        self.sock.sendall(server_public_bytes)
        transcript_hasher.update(server_public_bytes)

        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
        transcript_hash = transcript_hasher.finalize()
        session_key = derive_keys(shared_secret, transcript_hash)
        self.aead = AESGCM(session_key)
        print("[TLS] Server handshake complete.")

    @classmethod
    def create_client_socket(cls, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        tls_sock = cls(sock)
        tls_sock._perform_client_handshake()
        return tls_sock

    def accept(self):
        conn, addr = self.sock.accept()
        tls_conn = TLSSocket(conn)
        tls_conn._perform_server_handshake()
        return tls_conn, addr

    def send(self, data):
        if not self.aead:
            raise Exception("Handshake not performed")

        nonce = os.urandom(12)
        ciphertext = self.aead.encrypt(nonce, data, None)
        # 使用 [4字节长度][nonce][密文] 格式发送
        message = nonce + ciphertext
        self.sock.sendall(struct.pack('!I', len(message)) + message)

    def recv(self):
        if not self.aead:
            raise Exception("Handshake not performed")

        len_bytes = self.sock.recv(4)
        if not len_bytes:
            return None
        msg_len = struct.unpack('!I', len_bytes)[0]

        message = self.sock.recv(msg_len)
        if not message:
            return None

        nonce = message[:12]
        ciphertext = message[12:]
        return self.aead.decrypt(nonce, ciphertext, None)

    def close(self):
        self.sock.close()