import os

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
    return len(database)

if __name__ == "__main__":
    id = generate_key()
    print(id)