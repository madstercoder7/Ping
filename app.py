from flask import Flask, redirect, render_template
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here' # Replace with a strong secret key
socketio = SocketIO(app)

@app.route("/")
def index():
    return render_template('index.html')

if __name__ == "__main__":
    socketio.run(app, debug=True)