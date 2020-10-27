from google.cloud import datastore
from flask import Flask, request, jsonify
import json
import boat
import load

app = Flask(__name__)
app.register_blueprint(boat.bp)
app.register_blueprint(load.bp)
client = datastore.Client()

@app.route('/')
def index():
	return "Please navigate to /boats to use this API"

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=8080, debug=True)