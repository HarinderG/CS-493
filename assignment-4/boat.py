'''
	Harinder Gakhal
	CS493 - Assignment 4: Intermediate Rest API
	10/27/2020
'''

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
		return (jsonify(new_boat), 201)
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
			if len(e['loads']) > 0:
				for single_load in e['loads']:
					single_load['self'] = request.url_root + "loads/" + str(single_load['id'])
		output = {"boats": results}
		if next_url:
			output["next"] = next_url
		return (jsonify(output), 200)
	else:
		return 'Method not recogonized'

@bp.route('/<id>', methods=['DELETE','GET'])
def boats_get_delete(id):
	if request.method == 'DELETE':
		key = client.key("boats", int(id))
		boat = client.get(key=key)
		if boat == None:
			return (jsonify({"Error": "No boat with this boat_id exists"}), 404)
		if len(boat['loads']) > 0:
			for load in boat['loads']:
				load_obj = client.get(key=client.key("loads", load['id']))
				load_obj['carrier'] = None
				client.put(load_obj)
		client.delete(key)
		return (jsonify(''),204)
	elif request.method == 'GET':
		boat_key = client.key("boats", int(id))
		boat = client.get(key=boat_key)
		if boat == None:
			return (jsonify({"Error": "No boat with this boat_id exists"}), 404)
		for load in boat['loads']:
			load["self"] = request.url_root + "loads/" + str(load['id'])
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
		if load['carrier'] != None:
			return (jsonify({"Error": "Load already assigned to boat"}), 403)
		if 'loads' in boat.keys():
			for loads in boat['loads']:
				if loads['id'] == load.key.id:
					return(jsonify({"Error": "Load already assigned to boat"}), 403)
			boat['loads'].append({"id": load.key.id})
			load['carrier'] = {"id": boat.key.id, "name": boat["name"]}
		else:
			boat['loads'] = {"id": load.key.id}
			load['carrier'] = {"id": boat.key.id, "name": boat["name"]}
		client.put(boat)
		client.put(load)
		return(jsonify(''), 204)
	if request.method == 'DELETE':
		boat_key = client.key("boats", int(bid))
		boat = client.get(key=boat_key)
		load_key = client.key("loads", int(lid))
		load = client.get(key=load_key)
		if boat == None or load == None:
			return (jsonify({"Error": "No boat/load with this id exists"}), 404)
		if load['carrier'] == None or load['carrier']['id'] != boat.key.id:
			return (jsonify({"Error": "This load is not on the boat"}), 404)
		if 'loads' in boat.keys():
			boat['loads'].remove({"id": load.key.id})
			load['carrier'] = None
			client.put(boat)
			client.put(load)
		return(jsonify(''),204)

@bp.route('/<id>/loads', methods=['GET'])
def get_reservations(id):
	boat_key = client.key("boats", int(id))
	boat = client.get(key=boat_key)
	if boat == None:
		return (jsonify({"Error": "No boat with this boat_id exists"}), 404)
	load_list  = []
	if len(boat["loads"]) > 0:
		for load in boat['loads']:
			load_key = client.key("loads", int(load['id']))
			load_obj = client.get(key=load_key)
			load_obj["id"] = load_obj.key.id
			load_obj["self"] = request.url_root + "loads/" + str(load_obj.key.id)
			load_obj["carrier"]["self"] = request.url_root + "boats/" + str(load_obj["carrier"]["id"])
			load_list.append(load_obj)
		return (jsonify(load_list), 200)
	else:
		return (jsonify(''), 204)
