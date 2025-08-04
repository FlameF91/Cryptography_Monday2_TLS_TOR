# onion_router.py (Bob and Carol) - FINAL VERSION WITH RETURN PATH
import socket
import json
import threading
import sys
import base64
import traceback
import os

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tls_socket import TLSSocket

# --- DH 参数 ---
_p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
_g = 2
_params = dh.DHParameterNumbers(_p, _g)
DH_PARAMETERS = _params.parameters()


def derive_symmetric_key(shared_key):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared_key)


class OnionRouter:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.circuits = {}

    def handle_client(self, tls_conn, addr):
        print(f"New connection from {addr}")
        circuit_id_in_use = None
        try:
            while True:
                data = tls_conn.recv()
                if not data: break

                cell = json.loads(data.decode('utf-8'))
                command = cell.get("command")
                circuit_id_in_use = cell.get('circuit_id')

                if command == 'create':
                    self._handle_create(circuit_id_in_use, cell, tls_conn)
                elif command == 'relay':
                    self._handle_relay(cell, tls_conn)
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
            # traceback.print_exc() # Uncomment for deep debugging
        finally:
            print(f"Connection with {addr} closed.")
            tls_conn.close()

    def _handle_create(self, circuit_id, cell, tls_conn):
        private_key = DH_PARAMETERS.generate_private_key()
        public_key = private_key.public_key()

        peer_public_key_bytes = base64.b64decode(cell['dh_key'])
        y = int.from_bytes(peer_public_key_bytes, 'big')
        peer_public_key = dh.DHPublicNumbers(y, _params).public_key()

        shared_key = private_key.exchange(peer_public_key)
        session_key = derive_symmetric_key(shared_key)

        my_public_key_bytes = public_key.public_numbers().y.to_bytes((_p.bit_length() + 7) // 8, 'big')

        self.circuits[circuit_id] = {'key': session_key}

        response = {"command": "created", "dh_key": base64.b64encode(my_public_key_bytes).decode('utf-8')}
        tls_conn.send(json.dumps(response).encode('utf-8'))
        print(f"Circuit {circuit_id} created.")

    def _handle_relay(self, cell, incoming_conn):
        circuit_id = cell['circuit_id']
        session_info = self.circuits.get(circuit_id)
        if not session_info: return

        session_key = session_info['key']
        aead = AESGCM(session_key)

        encrypted_payload = base64.b64decode(cell['payload'])
        nonce = encrypted_payload[:12]
        ciphertext = encrypted_payload[12:]
        decrypted_payload = aead.decrypt(nonce, ciphertext, None)

        next_hop_socket = session_info.get('next_hop')
        if next_hop_socket:
            forward_cell = {"command": "relay", "circuit_id": circuit_id,
                            "payload": base64.b64encode(decrypted_payload).decode('utf-8')}
            next_hop_socket.send(json.dumps(forward_cell).encode('utf-8'))
        else:
            try:
                relay_cell = json.loads(decrypted_payload.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                print("Error: Received non-JSON relay payload.")
                return

            sub_command = relay_cell.get('sub_command')
            if sub_command == 'extend':
                self._handle_extend(relay_cell, circuit_id, aead, incoming_conn)
            elif sub_command == 'begin':
                self._handle_begin(relay_cell, circuit_id, aead, incoming_conn)
            elif sub_command == 'data':
                final_socket = session_info.get('final_socket')
                if final_socket:
                    content = base64.b64decode(relay_cell['content'])
                    print(f"Relay (Exit): sending data to final destination: {content.decode('utf-8')}")
                    final_socket.sendall(content)

    def _handle_extend(self, relay_cell, circuit_id, prev_hop_aead, incoming_conn):
        target_host, target_port = relay_cell['target_ip'], relay_cell['target_port']
        print(f"Relay (Extend): extending circuit {circuit_id} to {target_host}:{target_port}")

        next_hop_socket = TLSSocket.create_client_socket(target_host, target_port)
        self.circuits[circuit_id]['next_hop'] = next_hop_socket

        create_cell = {"command": "create", "circuit_id": circuit_id, "dh_key": relay_cell['dh_key']}
        next_hop_socket.send(json.dumps(create_cell).encode('utf-8'))

        created_response_raw = next_hop_socket.recv()
        created_response = json.loads(created_response_raw.decode('utf-8'))

        # Start the backward listening thread HERE
        threading.Thread(target=self._listen_and_relay_backwards,
                         args=(incoming_conn, next_hop_socket, prev_hop_aead, circuit_id)).start()

        extended_cell = {"sub_command": "extended", "dh_key": created_response['dh_key']}
        nonce = os.urandom(12)
        encrypted_extended = nonce + prev_hop_aead.encrypt(nonce, json.dumps(extended_cell).encode('utf-8'), None)

        response_to_client = {"command": "relay", "circuit_id": circuit_id,
                              "payload": base64.b64encode(encrypted_extended).decode('utf-8')}
        incoming_conn.send(json.dumps(response_to_client).encode('utf-8'))
        print(f"Relay (Extend): successfully extended circuit {circuit_id}.")

    def _listen_and_relay_backwards(self, upstream_conn, downstream_conn, key_aead, circuit_id):
        try:
            while True:
                data = downstream_conn.recv()
                if not data: break

                # This data is a relay cell from the next hop, which we need to forward.
                # We simply re-encrypt its payload with our key and send it up.
                cell = json.loads(data.decode('utf-8'))
                payload_from_downstream = base64.b64decode(cell['payload'])

                nonce = os.urandom(12)
                encrypted_payload = nonce + key_aead.encrypt(nonce, payload_from_downstream, None)

                response_to_upstream = {
                    "command": "relay",
                    "circuit_id": circuit_id,
                    "payload": base64.b64encode(encrypted_payload).decode('utf-8')
                }
                upstream_conn.send(json.dumps(response_to_upstream).encode('utf-8'))
        except Exception as e:
            print(f"Error in backward relay thread for {circuit_id}: {e}")
        finally:
            print(f"Backward relay thread for {circuit_id} finished.")
            upstream_conn.close()
            downstream_conn.close()

    def _handle_begin(self, relay_cell, circuit_id, aead, incoming_conn):
        target_host, target_port = relay_cell['target_ip'], relay_cell['target_port']
        print(f"Relay (Exit): beginning stream to {target_host}:{target_port}")

        final_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        final_socket.connect((target_host, target_port))
        self.circuits[circuit_id]['final_socket'] = final_socket

        # Start listening for replies from the final server
        threading.Thread(target=self.listen_from_final_server,
                         args=(incoming_conn, final_socket, aead, circuit_id)).start()

        connected_cell = {"sub_command": "connected"}
        nonce = os.urandom(12)
        encrypted_connected = nonce + aead.encrypt(nonce, json.dumps(connected_cell).encode('utf-8'), None)
        response_to_client = {"command": "relay", "circuit_id": circuit_id,
                              "payload": base64.b64encode(encrypted_connected).decode('utf-8')}
        incoming_conn.send(json.dumps(response_to_client).encode('utf-8'))

    def listen_from_final_server(self, upstream_conn, final_socket, key_aead, circuit_id):
        try:
            while True:
                data = final_socket.recv(4096)
                if not data: break

                print(f"Received from final server, relaying back: {data.decode('utf-8', errors='ignore')[:80]}...")

                data_cell = {"sub_command": "data", "content": base64.b64encode(data).decode('utf-8')}
                nonce = os.urandom(12)
                encrypted_data = nonce + key_aead.encrypt(nonce, json.dumps(data_cell).encode('utf-8'), None)

                response_to_upstream = {"command": "relay", "circuit_id": circuit_id,
                                        "payload": base64.b64encode(encrypted_data).decode('utf-8')}
                upstream_conn.send(json.dumps(response_to_upstream).encode('utf-8'))
        except Exception as e:
            print(f"Error in final server listener: {e}")
        finally:
            final_socket.close()

    def start(self):
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind((self.host, self.port))
        listen_sock.listen(5)
        print(f"Onion Router listening on {self.host}:{self.port}")

        tls_listen_sock = TLSSocket(listen_sock)

        while True:
            conn, addr = tls_listen_sock.accept()
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    router = OnionRouter(host, port)
    router.start()