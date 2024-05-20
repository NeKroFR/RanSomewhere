import os, socket

HOST = '127.0.0.1'
PORT = 4050

def loaddb():
    database = []
    try:
        for line in open("database.txt", "r"):
                database.append(line.strip())
        return database
    except:
        return []

def generate_key():
    database = loaddb()
    key = os.urandom(32).hex()
    with open("database.txt", "a") as f:
        f.write(f"{key}\n")
    return len(database), key

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