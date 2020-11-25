'''
	Harinder Gakhal
	CS493 - Assignment 6: OAuth 2.0 Implementation
	10/27/2020
'''

from google.cloud import datastore
from flask import Flask, request, jsonify, render_template, redirect, session
import flask
import requests
import json
import uuid
import string
import random
import constants # This file will hold the client id and client secret

app = flask.Flask(__name__)
app.secret_key = str(uuid.uuid4())
client = datastore.Client()

ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth?"
SCOPE = "scope=https://www.googleapis.com/auth/userinfo.profile&"
ACCESS_TYPE = "access_type=offline&"
RESPONSE_TYPE = "response_type=code&"
REDIRECT_URI = "redirect_uri=https://assignment1-gae-hgg.wl.r.appspot.com/oauth&"
CLIENT_ID = "client_id=" + constants.clientID + "&"

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/oauth')
def oauth():
	old_state = flask.session['state']
	if old_state != request.args.get('state'):
		return ("State does not match!", 404)
	data = {
		'code': request.args.get('code'),
		'client_id': constants.clientID,
		'client_secret': constants.clientSecret,
		'redirect_uri': "https://assignment1-gae-hgg.wl.r.appspot.com/oauth",
		'grant_type': 'authorization_code'
	}
	res = requests.post('https://oauth2.googleapis.com/token', data=data).json()
	token = res['access_token']
	person = requests.get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=" + token).json()
	return person['name']

@app.route('/gauth')
def gauth():
	letters = string.ascii_lowercase
	STATE = ''.join(random.choice(letters) for i in range(8))
	flask.session['state'] = STATE
	return redirect(f'{ENDPOINT}{SCOPE}{ACCESS_TYPE}{RESPONSE_TYPE}{REDIRECT_URI}{CLIENT_ID}state={STATE}')

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=8080, debug=True)
