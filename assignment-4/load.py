'''
	Harinder Gakhal
	CS493 - Assignment 4: Intermediate Rest API
	10/27/2020
'''

from flask import Blueprint, request, jsonify
from google.cloud import datastore
import json

client = datastore.Client()

bp = Blueprint('load', __name__, url_prefix='/loads')

@bp.route('', methods=['POST','GET'])
def loads_get_post():
	if request.method == 'POST':
		content = request.get_json()
		if len(content) != 3:
			return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
		new_load = datastore.entity.Entity(key=client.key("loads"))
		new_load.update({"weight": content["weight"], 'carrier': None, 'content': content['content'], 'delivery_date': content['delivery_date']})
		client.put(new_load)
		new_load['id'] = new_load.key.id
		new_load['self'] = request.url + '/' + str(new_load.key.id)
		return (jsonify(new_load), 201)
	elif request.method == 'GET':
		query = client.query(kind="loads")
		q_limit = int(request.args.get('limit', '3'))
		q_offset = int(request.args.get('offset', '0'))
		g_iterator = query.fetch(limit= q_limit, offset=q_offset)
		pages = g_iterator.pages
		results = list(next(pages))
		if g_iterator.next_page_token:
			next_offset = q_offset + q_limit
			next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
		else:
			next_url = None
		for e in results:
			e["id"] = e.key.id
			e["self"] = request.url_root + "loads/" + str(e.key.id)
			if e["carrier"] != None:
				e['carrier']['self'] = request.url_root + "boats/" + str(e['carrier']['id'])
		output = {"loads": results}
		if next_url:
			output["next"] = next_url
		return (jsonify(output), 200)

@bp.route('/<id>', methods=['DELETE','GET'])
def loads_get_delete(id):
	if request.method == 'DELETE':
		key = client.key("loads", int(id))
		load = client.get(key=key)
		if load == None:
			return (jsonify({"Error": "No load with this load_id exists"}), 404)
		if load['carrier'] != None:
			boat = client.get(key=client.key("boats", load['carrier']['id']))
			boat["loads"].remove({'id': load.key.id})
			client.put(boat)
		client.delete(key)
		return (jsonify(''),204)
	elif request.method == 'GET':
		load_key = client.key("loads", int(id))
		load = client.get(key=load_key)
		if load == None:
			return (jsonify({"Error": "No load with this load_id exists"}), 404)
		if load["carrier"]:
			load["carrier"]["self"] = request.url_root + "boats/" + str(load["carrier"]["id"])
		load["id"] = id
		load["self"] = request.url
		return (jsonify(load), 200)
	else:
		return 'Method not recogonized'
