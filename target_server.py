# target_server.py (Dave)
import socket

HOST = '127.0.0.1'
PORT = 9999


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Target server (Dave) listening on {HOST}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            if not data:
                return

            print(f"Received from Tor circuit: {data.decode('utf-8')}")

            response = b"HTTP/1.1 200 OK\r\n\r\nHello from Dark!"
            print(f"Sending response: {response.decode('utf-8')}")
            conn.sendall(response)


if __name__ == '__main__':
    main()