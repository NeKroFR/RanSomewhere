import socket
import subprocess

HOST = '127.0.0.1'
PORT = 4050


def generate_key():
    subprocess.run(["python3", "keygen.py"])

def start_server(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                generate_key()

if __name__ == "__main__":
    start_server(HOST, PORT)
