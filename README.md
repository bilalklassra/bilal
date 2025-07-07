from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS
import bcrypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)

# Configuration
app.config['MONGO_URI'] = 'mongodb://localhost:27017/ewallet'
app.config['SECRET_KEY'] = 'your_secret_key'

mongo = PyMongo(app)
users = mongo.db.users

# JWT Token Check Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.find_one({'email': data['email']})
        except:
            return jsonify({'message': 'Invalid token!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Signup
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if users.find_one({'email': data['email']}):
        return jsonify({'message': 'Email already exists'}), 400

    hashed = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    users.insert_one({
        'name': data['name'],
        'email': data['email'],
        'password': hashed,
        'balance': 0
    })
    return jsonify({'message': 'Signup successful'}), 201

# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = users.find_one({'email': data['email']})
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if bcrypt.checkpw(data['password'].encode('utf-8'), user['password']):
        token = jwt.encode({
            'email': user['email'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    else:
        return jsonify({'message': 'Wrong password'}), 401

# Get Balance
@app.route('/balance', methods=['GET'])
@token_required
def balance(current_user):
    return jsonify({'balance': current_user['balance']})

# Add Money
@app.route('/add', methods=['POST'])
@token_required
def add_money(current_user):
    data = request.get_json()
    amount = data.get('amount', 0)
    users.update_one({'email': current_user['email']}, {'$inc': {'balance': amount}})
    updated_user = users.find_one({'email': current_user['email']})
    return jsonify({'message': f'Rs {amount} added', 'balance': updated_user['balance']})

# Transfer Money
@app.route('/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    data = request.get_json()
    receiver_email = data['email']
    amount = data['amount']

    receiver = users.find_one({'email': receiver_email})
    if not receiver:
        return jsonify({'message': 'Receiver not found'}), 404

    if current_user['balance'] < amount:
        return jsonify({'message': 'Insufficient balance'}), 400

    users.update_one({'email': current_user['email']}, {'$inc': {'balance': -amount}})
    users.update_one({'email': receiver_email}, {'$inc': {'balance': amount}})
    updated_sender = users.find_one({'email': current_user['email']})

    return jsonify({'message': 'Transfer successful', 'balance': updated_sender['balance']})

# Run server
if __name__ == '__main__':
    app.run(debug=True, port=5000)
