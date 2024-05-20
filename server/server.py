from flask import Flask, request, render_template, jsonify
import os

app = Flask(__name__)

def loaddb():
    database = []
    try:
        with open("database.txt", "r") as f:
            database = [line.strip() for line in f]
        return database
    except FileNotFoundError:
        return []

def get_key(id):
    database = loaddb()
    if 0 <= id < len(database):
        return database[id]
    else:
        return None

def verify_transaction(transaction_id):
    # TODO
    return True


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_key', methods=['POST'])
def fetch_key():
    try:
        id = int(request.form['id'])
        transaction_id = request.form['transaction']
        
        key = get_key(id)
        if not key:
            return jsonify({'error': 'Key not found'}), 404
        else:
            if verify_transaction(transaction_id):
                return jsonify({'key': key})
            else:
                return jsonify({'error': 'Transaction not verified'}), 404
    except ValueError:
        return jsonify({'error': 'Invalid ID'}), 400

if __name__ == "__main__":
    app.run(debug=True)
