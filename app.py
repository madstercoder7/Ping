from flask import Flask, redirect, render_template
from flask_socketio import SocketIO
import os

secret_key = os.getenv("SECRET_KEY")

app = Flask(__name__)
if secret_key: 
    app.config['SECRET_KEY'] = secret_key
else: 
    print("No secret key found")
socketio = SocketIO(app)

@app.route("/")
def index():
    return render_template('index.html')

if __name__ == "__main__":
    socketio.run(app, debug=True)