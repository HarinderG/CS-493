# CS493 - Assignment 7: More Authentication and Authorization
# Harinder Gakhal
from google.cloud import datastore
from flask import Flask, request, jsonify
from requests_oauthlib import OAuth2Session
import json
from google.oauth2 import id_token
from google.auth import crypt
from google.auth import jwt
from google.auth.transport import requests
import constants

# This disables the requirement to use HTTPS so that you can test locally.
import os 
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
client = datastore.Client()

# These should be copied from an OAuth2 Credential section at
# https://console.cloud.google.com/apis/credentials
client_id = constants.CLIENT_ID
client_secret = constants.CLIENT_SECRET

# This is the page that you will use to decode and collect the info from
# the Google authentication flow
redirect_uri = 'https://cs493-a7-hg.wl.r.appspot.com/oauth'

# These let us get basic info to identify a user and not much else
# they are part of the Google People API
scope = ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']
oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)

# This link will redirect users to begin the OAuth flow with Google
@app.route('/')
def index():
	authorization_url, state = oauth.authorization_url(
		'https://accounts.google.com/o/oauth2/auth',
		# access_type and prompt are Google specific extra
		# parameters.
		access_type="offline", prompt="select_account")
	return '<h1>Welcome</h1>\n <p>Click <a href=%s>here</a> to get your JWT.</p>' % authorization_url

# This is where users will be redirected back to and where you can collect
# the JWT for use in future requests
@app.route('/oauth')
def oauthroute():
	token = oauth.fetch_token('https://accounts.google.com/o/oauth2/token', authorization_response=request.url, client_secret=client_secret)
	req = requests.Request()
	id_info = id_token.verify_oauth2_token(token['id_token'], req, client_id)

	# return "Your JWT is: <p style=\"font-size:12px;\">%s</p>" % token['id_token']
	return (jsonify({"jwt": token['id_token']}), 200)


# This page demonstrates verifying a JWT. id_info['email'] contains
# the user's email address and can be used to identify them
# this is the code that could prefix any API call that needs to be
# tied to a specific user by checking that the email in the verified
# JWT matches the email associated to the resource being accessed.
@app.route('/verify-jwt')
def verify():
	req = requests.Request()

	try:
		id_info = id_token.verify_oauth2_token(request.args['jwt'], req, client_id)
	except:
		return('Could not verify JWT!', 401)

	return repr(id_info) + "<br><br> the user is: " + id_info['email']

@app.route('/boats', methods=['POST','GET'])
def boats_get_post():
	if request.method == 'POST':
		# Get JWT from Authorization header
		req = requests.Request()
		jwt_token = request.headers.get('Authorization')
		if jwt_token:
			jwt_token = jwt_token.split(" ")[1]
			# Check to see if JWT is valid
			try:
				jwt_sub = id_token.verify_oauth2_token(jwt_token, req, client_id)['sub']
			except:
				return('Could not verify JWT!\n', 401)
		else:
			# Return 401 if no JWT is given
			return (jsonify('JWT was not given!'), 401)

		# Grab content from request body
		content = request.get_json()

		# Check to see if all properties are given. - No need to validate
		if len(content) != 4:
			return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)

		# Create a new boat entity
		new_boat = datastore.entity.Entity(key=client.key("boats"))
		new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"], "public": content["public"], "owner": jwt_sub})
		client.put(new_boat) # Upload boat object to Datastore

		# Return boat object
		return (jsonify({"id": new_boat.key.id, "name": content["name"], "type": content["type"], "length": content["length"], "public": content["public"], "owner": jwt_sub}), 201)
	elif request.method == 'GET':
		list_public = False

		# Get JWT from Authorization header
		req = requests.Request()
		jwt_token = request.headers.get('Authorization')
		# Check if JWT is valid/exists - if not list public boats
		if jwt_token:
			jwt_token = jwt_token.split(" ")[1]
			try:
				jwt_sub = id_token.verify_oauth2_token(jwt_token, req, client_id)['sub']
			except:
				list_public = True
		else:
			list_public = True

		# Run query on database - public or owned by current user
		query = client.query(kind="boats")
		if list_public:
			query.add_filter("public", "=", True)
		else:
			query.add_filter("owner", "=", jwt_sub)
		results = list(query.fetch())

		# Add respective id to each boat
		for entity in results:
			entity["id"] = entity.key.id

		return (jsonify(results), 200)
	else:
		return 'Method not recogonized'

@app.route('/owners/<owner_id>/boats', methods=['GET'])
def boats_get(owner_id):
	if request.method == 'GET':
		# Search the database for all boats with the owner_id and that are public
		query = client.query(kind="boats")
		query.add_filter("public", "=", True)
		query.add_filter("owner", "=", owner_id)
		results = list(query.fetch())

		# Add respective id to each boat
		for entity in results:
			entity["id"] = entity.key.id

		return (jsonify(results), 200)

@app.route('/boats/<boat_id>', methods=['DELETE'])
def delete_boat(boat_id):
	if request.method == 'DELETE':
		# Get JWT from Authorization header
		req = requests.Request()
		jwt_token = request.headers.get('Authorization')
		if jwt_token:
			jwt_token = jwt_token.split(" ")[1]
			# Check to see if JWT is valid
			try:
				jwt_sub = id_token.verify_oauth2_token(jwt_token, req, client_id)['sub']
			except:
				return('Could not verify JWT!\n', 401)
		else:
			# Return 401 if no JWT is given
			return (jsonify('JWT was not given!'), 401)
		
		# Find the boat using boat_id
		boat_key = client.key("boats", int(boat_id))
		boat = client.get(key=boat_key)
		if boat == None:
			return (jsonify({'Error': 'No boat with this boat_id exists'}), 403)
		elif boat['owner'] != jwt_sub:
			return (jsonify({'Error': 'This boat is owned by someone else!'}), 403)

		# Delete boat from Datastore
		client.delete(boat_key)
		return (jsonify(''), 204)

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=8080, debug=True)