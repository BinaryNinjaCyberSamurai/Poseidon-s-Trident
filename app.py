from flask import Flask, send_from_directory, request, jsonify
import os

app = Flask(__name__, static_folder='frontend/build')

@app.route('/')
def serve():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_proxy(path):
    return send_from_directory(app.static_folder, path)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    # Implement your login logic here
    return jsonify({"message": "Login successful"})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    # Implement your registration logic here
    return jsonify({"message": "Registration successful"})

if __name__ == '__main__':
    app.run(debug=True)    cd frontend
    npm run build