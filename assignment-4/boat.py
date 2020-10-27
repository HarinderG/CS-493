from flask import Blueprint, request, jsonify
from google.cloud import datastore
import json

client = datastore.Client()

bp = Blueprint('boat', __name__, url_prefix='/boats')

@bp.route('', methods=['POST','GET'])
def boats_get_post():
	if request.method == 'POST':
		content = request.get_json()
		if len(content) != 3:
			return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
		new_boat = datastore.entity.Entity(key=client.key("boats"))
		new_boat.update({'name': content['name'], 'type': content['type'], 'length': content['length'], 'loads': []})
		client.put(new_boat)
		new_boat['id'] = new_boat.key.id
		new_boat['self'] = request.url + '/' + str(new_boat.key.id)
		return (jsonify(new_boat), 200)
	elif request.method == 'GET':
		query = client.query(kind="boats")
		q_limit = int(request.args.get('limit', '3'))
		q_offset = int(request.args.get('offset', '0'))
		l_iterator = query.fetch(limit= q_limit, offset=q_offset)
		pages = l_iterator.pages
		results = list(next(pages))
		if l_iterator.next_page_token:
			next_offset = q_offset + q_limit
			next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
		else:
			next_url = None
		for e in results:
			e["id"] = e.key.id
			e["self"] = request.url + '/' + str(e.key.id)
		output = {"boats": results}
		if next_url:
			output["next"] = next_url
		return jsonify(output)
	else:
		return 'Method not recogonized'

@bp.route('/<id>', methods=['PUT','DELETE','GET'])
def boats_put_delete(id):
	if request.method == 'PUT':
		content = request.get_json()
		boat_key = client.key("boats", int(id))
		boat = client.get(key=boat_key)
		boat.update({'name': content['name'], 'type': content['type'], 'length': content['length']})
		client.put(boat)
		boat['id'] = boat.key.id
		boat['self'] = request.url
		return (jsonify(boat), 200)
	elif request.method == 'DELETE':
		key = client.key("boats", int(id))
		if client.get(key=key) == None:
			return (jsonify({"Error": "No boat with this boat_id exists"}), 404)
		client.delete(key)
		return ('',200)
	elif request.method == 'GET':
		boat_key = client.key("boats", int(id))
		boat = client.get(key=boat_key)
		if boat == None:
			return (jsonify({"Error": "No boat with this boat_id exists"}), 404)
		boat["id"] = id
		boat["self"] = request.url
		return (jsonify(boat), 200)
	else:
		return 'Method not recogonized'

@bp.route('/<bid>/loads/<lid>', methods=['PUT','DELETE'])
def add_delete_reservation(bid, lid):
	if request.method == 'PUT':
		boat_key = client.key("boats", int(bid))
		boat = client.get(key=boat_key)
		load_key = client.key("loads", int(lid))
		load = client.get(key=load_key)
		if boat == None or load == None:
			return (jsonify({"Error": "No boat/load with this id exists"}), 404)
		if 'loads' in boat.keys():
			# for loads in boat['loads']:
			# 	print(loads)
			# 	if loads['id'] == load.key.id:
			# 		return(jsonify({"Error": "Load is already in boat."}), 400)
			boat['loads'].append(jsonify({"id": load.key.id}))
		else:
			boat['loads'] = jsonify({"id": load.key.id})
		client.put(boat)
		boat['id'] = boat.key.id
		boat['self'] = request.url
		return(jsonify(boat), 200)
	if request.method == 'DELETE':
		boat_key = client.key("boats", int(bid))
		boat = client.get(key=boat_key)
		if 'loads' in boat.keys():
			boat['loads'].remove(int(lid))
			client.put(boat)
		return('',200)

@bp.route('/<id>/loads', methods=['GET'])
def get_reservations(id):
	boat_key = client.key("boats", int(id))
	boat = client.get(key=boat_key)
	load_list  = []
	if 'loads' in boat.keys():
		for lid in boat['loads']:
			load_key = client.key("loads", int(lid))
			load_list.append(load_key)
		return json.dumps(client.get_multi(load_list))
	else:
		return json.dumps([])