import socket
from Crypto.Util.number import getPrime, long_to_bytes
import configparser

config = configparser.ConfigParser()
config.read('/app/config.ini')
keygen_port = config.getint('server', 'keygen_port')
HOST = '0.0.0.0'
PORT = keygen_port

def loaddb():
    database = []
    try:
        for line in open("database.txt", "r"):
            database.append(line.strip())
        return database
    except:
        return []

def RSA():
    p = getPrime(1024)
    q = getPrime(1024)
    n = p*q
    e = 65537
    phi = (p-1)*(q-1)
    d = pow(e, -1, phi)
    n = long_to_bytes(n).hex()
    d = long_to_bytes(d).hex()
    privkey = n + '-' + d
    return privkey, n

def generate_key():
    database = loaddb()
    privkey, pubkey = RSA()
    with open("database.txt", "a") as f:
        f.write(f"{privkey}\n")
    return len(database), pubkey

def send_key(conn):
    id, key = generate_key()
    conn.sendall(f"{id}\n{key}\n".encode())
    conn.close()

def start_server(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                send_key(conn)

if __name__ == "__main__":
    start_server(HOST, PORT)
