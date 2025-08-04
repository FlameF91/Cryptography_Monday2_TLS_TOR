# client.py (FINAL CORRECTED VERSION)
import socket
import json
import uuid
import base64
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tls_socket import TLSSocket

# --- DH 参数 (与路由器一致) ---
_p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
_g = 2
_params = dh.DHParameterNumbers(_p, _g)
DH_PARAMETERS = _params.parameters()


def derive_symmetric_key(shared_key):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)


class Client:
    def __init__(self, circuit_nodes, dest_host, dest_port):
        self.circuit_nodes = circuit_nodes
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.circuit_id = str(uuid.uuid4())
        self.session_keys = []
        self.entry_socket = None

    def build_circuit(self):
        print("Building a new circuit...")

        entry_node_host, entry_node_port = self.circuit_nodes[0]
        self.entry_socket = TLSSocket.create_client_socket(entry_node_host, entry_node_port)

        for i in range(len(self.circuit_nodes)):
            if i == 0:
                private_key = DH_PARAMETERS.generate_private_key()
                public_key = private_key.public_key()

                create_cell = {
                    "command": "create",
                    "circuit_id": self.circuit_id,
                    "dh_key": base64.b64encode(public_key.public_numbers().y.to_bytes(
                        (_p.bit_length() + 7) // 8, 'big'
                    )).decode('utf-8')
                }
                self.entry_socket.send(json.dumps(create_cell).encode('utf-8'))

                created_cell_raw = self.entry_socket.recv()
                if not created_cell_raw:
                    raise ConnectionError("Connection closed by the first node prematurely.")
                created_cell = json.loads(created_cell_raw.decode('utf-8'))

                peer_public_key_bytes = base64.b64decode(created_cell['dh_key'])
                y = int.from_bytes(peer_public_key_bytes, 'big')
                peer_public_key = dh.DHPublicNumbers(y, _params).public_key()

                shared_key = private_key.exchange(peer_public_key)
                session_key = derive_symmetric_key(shared_key)
                self.session_keys.append(session_key)
                print(f"Established key with node 1: {session_key.hex()}")

            else:
                node_host, node_port = self.circuit_nodes[i]

                private_key = DH_PARAMETERS.generate_private_key()
                public_key = private_key.public_key()

                extend_cell = {
                    "sub_command": "extend",
                    "target_ip": node_host,
                    "target_port": node_port,
                    "dh_key": base64.b64encode(public_key.public_numbers().y.to_bytes(
                        (_p.bit_length() + 7) // 8, 'big'
                    )).decode('utf-8')
                }

                self._send_relay_cell(extend_cell, is_sub_command=True)

                extended_cell = self._recv_relay_cell()

                peer_public_key_bytes = base64.b64decode(extended_cell['dh_key'])
                y = int.from_bytes(peer_public_key_bytes, 'big')
                peer_public_key = dh.DHPublicNumbers(y, _params).public_key()

                shared_key = private_key.exchange(peer_public_key)
                session_key = derive_symmetric_key(shared_key)
                self.session_keys.append(session_key)
                print(f"Established key with node {i + 1}: {session_key.hex()}")

        print("Circuit established successfully!")

    def send_data(self, data):
        begin_cell = {"sub_command": "begin", "target_ip": self.dest_host, "target_port": self.dest_port}
        self._send_relay_cell(begin_cell, is_sub_command=True)

        print("Waiting for 'connected' confirmation...")
        response = self._recv_relay_cell()
        if response.get("sub_command") != "connected":
            raise Exception("Failed to connect to destination")
        print("Connection to destination confirmed.")

        data_cell = {"sub_command": "data", "content": base64.b64encode(data).decode('utf-8')}
        self._send_relay_cell(data_cell, is_sub_command=True)
        print(f"Sent data: {data.decode('utf-8')}")

        print("Waiting for final response...")
        response_data_cell = self._recv_relay_cell()
        if response_data_cell.get("sub_command") == "data":
            final_response = base64.b64decode(response_data_cell['content'])
            print(f"Received final response:\n---\n{final_response.decode('utf-8')}\n---")

        self.entry_socket.close()

    def _send_relay_cell(self, payload_dict, is_sub_command=False):
        payload = json.dumps(payload_dict).encode('utf-8')

        # Onion encryption
        for key in reversed(self.session_keys):
            aead = AESGCM(key)
            nonce = os.urandom(12)
            payload = nonce + aead.encrypt(nonce, payload, None)

        relay_cell = {
            "command": "relay",
            "circuit_id": self.circuit_id,
            "payload": base64.b64encode(payload).decode('utf-8')
        }
        self.entry_socket.send(json.dumps(relay_cell).encode('utf-8'))

    def _recv_relay_cell(self):
        response_raw = self.entry_socket.recv()
        if not response_raw:
            raise ConnectionError("Connection closed while waiting for a relay response.")

        response_cell = json.loads(response_raw.decode('utf-8'))
        payload = base64.b64decode(response_cell['payload'])

        # Onion decryption
        for key in self.session_keys:
            aead = AESGCM(key)
            nonce = payload[:12]
            ciphertext = payload[12:]
            payload = aead.decrypt(nonce, ciphertext, None)

        return json.loads(payload.decode('utf-8'))


if __name__ == '__main__':
    CIRCUIT_NODES = [('127.0.0.1', 8001), ('127.0.0.1', 8002)]
    TARGET_HOST = '127.0.0.1'
    TARGET_PORT = 9999

    client = Client(CIRCUIT_NODES, TARGET_HOST, TARGET_PORT)
    client.build_circuit()

    message_to_send = b"Try to get connection to the world from Ace"
    client.send_data(message_to_send)