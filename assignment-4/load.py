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
		return (jsonify(new_load), 200)
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
		output = {"loads": results}
		if next_url:
			output["next"] = next_url
		return json.dumps(output)

@bp.route('/<id>', methods=['PUT','DELETE','GET'])
def loads_put_delete(id):
	if request.method == 'PUT':
		content = request.get_json()
		load_key = client.key("loads", int(id))
		load = client.get(key=load_key)
		load.update({"name": content["name"]})
		client.put(load)
		return ('',200)
	elif request.method == 'DELETE':
		key = client.key("loads", int(id))
		client.delete(key)
		return ('',200)
	elif request.method == 'GET':
		load_key = client.key("loads", int(id))
		load = client.get(key=load_key)
		if load == None:
			return (jsonify({"Error": "No load with this load_id exists"}), 404)
		load["id"] = id
		load["self"] = request.url
		return (jsonify(load), 200)
	else:
		return 'Method not recogonized'