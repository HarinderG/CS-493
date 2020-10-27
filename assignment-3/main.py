'''
	Harinder Gakhal
	CS493 - Assignment 3: Build a Restful API
	10/20/2020
'''

from google.cloud import datastore
from flask import Flask, request, jsonify
import json

app = Flask(__name__)
client = datastore.Client()

@app.route('/')
def index():
	return "Please refer to the API Spec to use this API."\

# ======================================= SLIPS =======================================

@app.route('/boats', methods=['POST','GET'])
def boats_get_post():
	if request.method == 'POST':
		content = request.get_json()
		if len(content) != 3:
			return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
		new_boat = datastore.entity.Entity(key=client.key("boats"))
		new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"]})
		client.put(new_boat)
		return (jsonify({"id": new_boat.key.id, "name": content["name"], "type": content["type"], "length": content["length"], "self": str(request.url) + "/" + str(new_boat.key.id)}), 201)
	elif request.method == 'GET':
		query = client.query(kind="boats")
		results = list(query.fetch())
		for entity in results:
			entity["id"] = entity.key.id
			entity["self"] = str(request.url) + "/" + str(entity.key.id)
		return (jsonify(results), 200)
	else:
		return 'Method not recogonized'

@app.route('/boats/<id>', methods=['PUT','DELETE','GET','PATCH'])
def boats_put_delete(id):
	if request.method == 'PUT' or request.method == 'PATCH':
		content = request.get_json()
		if len(content) != 3:
			return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
		boat_key = client.key("boats", int(id))
		boat = client.get(key=boat_key)
		if boat == None:
			return (jsonify({"Error": "No boat with this boat_id exists"}), 404)
		boat.update({"name": content["name"], "type": content["type"], "length": content["length"]})
		client.put(boat)
		return (jsonify({"id": boat.key.id, "name": content["name"], "type": content["type"], "length": content["length"], "self": str(request.url)}), 200)
	elif request.method == 'DELETE':
		boat_key = client.key("boats", int(id))
		query = client.query(kind="slips")
		query.add_filter('current_boat', '=', int(id))
		result = list(query.fetch())
		if len(result) > 0:
			result[0]["current_boat"] = None
			client.put(result[0])
		if client.get(key=boat_key) == None:
			return (jsonify({"Error": "No boat with this boat_id exists"}), 404)
		client.delete(boat_key)
		return ('',204)
	elif request.method == 'GET':
		content = request.get_json()
		boat_key = client.key("boats", int(id))
		boat = client.get(key=boat_key)
		if boat == None:
			return (jsonify({"Error": "No boat with this boat_id exists"}), 404)
		boat["id"] = id
		boat["self"] = str(request.url)
		return (jsonify(boat), 200)
	else:
		return 'Method not recogonized'

# ======================================= SLIPS =======================================

@app.route('/slips', methods=['POST','GET'])
def slips_get_post():
	if request.method == 'POST':
		content = request.get_json()
		if len(content) != 1:
			return (jsonify({"Error": "The request object is missing the required number"}), 400)
		new_slip = datastore.entity.Entity(key=client.key("slips"))
		new_slip.update({"number": content["number"], "current_boat": None})
		client.put(new_slip)
		return (jsonify({"id": new_slip.key.id, "number": content["number"], "current_boat": None, "self": str(request.url) + "/" + str(new_slip.key.id)}), 201)
	elif request.method == 'GET':
		query = client.query(kind="slips")
		results = list(query.fetch())
		for entity in results:
			entity["id"] = entity.key.id
			entity["self"] = str(request.url) + "/" + str(entity.key.id)
		return (jsonify(results), 200)
	else:
		return 'Method not recogonized'

@app.route('/slips/<id>', methods=['DELETE','GET',])
def slips_put_delete(id):
	if request.method == 'DELETE':
		slip_key = client.key("slips", int(id))
		if client.get(key=slip_key) == None:
			return (jsonify({"Error": "No slip with this slip_id exists"}), 404)
		client.delete(slip_key)
		return ('',204)
	elif request.method == 'GET':
		content = request.get_json()
		slip_key = client.key("slips", int(id))
		slip = client.get(key=slip_key)
		if slip == None:
			return (jsonify({"Error": "No slip with this slip_id exists"}), 404)
		slip["id"] = id
		slip["self"] = str(request.url)
		return (jsonify(slip), 200)
	else:
		return 'Method not recogonized'

@app.route('/slips/<slip_id>/<boat_id>', methods=['PUT', 'DELETE'])
def slips_boats_put(slip_id, boat_id):
	if request.method == 'PUT':
		slip = client.get(key=client.key("slips", int(slip_id)))
		boat = client.get(key=client.key("boats", int(boat_id)))
		if boat == None or slip == None:
			return(jsonify({"Error": "The specified boat and/or slip does not exist"}), 404)
		elif slip["current_boat"] != None:
			return(jsonify({"Error": "The slip is not empty"}), 403)
		slip.update({"current_boat": boat.key.id})
		client.put(slip)
		return('', 204)
	elif request.method == 'DELETE':
		slip = client.get(key=client.key("slips", int(slip_id)))
		boat = client.get(key=client.key("boats", int(boat_id)))
		if boat == None or slip == None or int(slip["current_boat"]) != int(boat_id):
			return(jsonify({"Error": "No boat with this boat_id is at the slip with this slip_id"}), 404)
		slip.update({"current_boat": None})
		client.put(slip)
		return('', 204)
	
if __name__ == '__main__':
	app.run(host='127.0.0.1', port=8080, debug=True)
