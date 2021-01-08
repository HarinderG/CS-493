# CS493 - Portfolio Assignment: Final Project
# Harinder Gakhal
# SET ENV VAR FOR GCLOUD

from google.cloud import datastore
from flask import Flask, request, jsonify
from requests_oauthlib import OAuth2Session
from google.oauth2 import id_token
from google.auth import crypt, jwt
from google.auth.transport import requests
import requests as reqq
import constants


# This disables the requirement to use HTTPS so that you can test locally.
import os 
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
client = datastore.Client()

# OAuth2 Credentials
client_id = constants.CLIENT_ID
client_secret = constants.CLIENT_SECRET

# This is the page that you will use to decode and collect the info from
# the Google authentication flow
redirect_uri = 'https://cs493-final-hg.wl.r.appspot.com/profile'

# These let us get basic info to identify a user and not much else
# they are part of the Google People API
scope = ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']
oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)

# This link will redirect users to begin the OAuth flow with Google
@app.route('/')
def index():
	authorization_url, state = oauth.authorization_url('https://accounts.google.com/o/oauth2/auth',	access_type="offline", prompt="select_account")
	return '<h1>Welcome</h1>\n <p>Click <a href=%s>here</a> to log in or create a new account.</p>' % authorization_url

# This is where users will be redirected back to and where you can collect
# the JWT for use in future requests
@app.route('/profile')
def oauthroute():
	token = oauth.fetch_token('https://accounts.google.com/o/oauth2/token', authorization_response=request.url, client_secret=client_secret)
	req = requests.Request()
	id_info = id_token.verify_oauth2_token(token['id_token'], req, client_id)

	# Search database for user
	query = client.query(kind="users")
	query.add_filter("sub", "=", id_info['sub'])
	result = list(query.fetch())

	# Create a new user if they don't exist in the database
	if len(result) == 0:
		new_user = datastore.entity.Entity(key=client.key('users'))
		new_user.update({'email': id_info['email'], 'sub': id_info['sub']})
		client.put(new_user)
		return (("<h1>Account has been created</h1>\n	<p>JWT: %s</p>\n	<p>Unique ID (sub): %s</p>\n" % (token['id_token'], id_info['sub'])), 201)
	elif len(result) == 1:
		return (("<h1>Welcome back!</h1>\n	<p>JWT: %s</p>\n	<p>Unique ID (sub): %s</p>\n" % (token['id_token'], id_info['sub'])), 200)

@app.route('/users', methods=['GET'])
def get_users():
	if request.method == 'GET':
		query = client.query(kind="users")
		results = list(query.fetch())

		# Add respective id to each object
		for entity in results:
			entity["id"] = entity.key.id
			entity["self"] = request.url + "/" + str(entity.key.id)

		return (jsonify(results), 200)

@app.route('/users/<uid>', methods=['GET'])
def get_user_id(uid):
	if request.method == 'GET':

		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)
		
		# Verify that the request is authorized to access user
		if jwt_sub != uid:
			return(jsonify({'Error': 'You do not have access to this user!'}), 401)
			
		# Find user with sub
		query = client.query(kind="users")
		query.add_filter("sub", "=", uid)
		results = list(query.fetch())

		# Throw error is user does not exist in database
		if len(results) == 0:
			return(jsonify({'Error': 'This user does not exist!\n'}), 401)

		# Add respective id to each object
		for entity in results:
			entity["id"] = entity.key.id
			entity["self"] = request.url

		return (jsonify(results), 200)

@app.route('/projects', methods=['POST', 'GET'])
def projects_post_get():
	if request.method == 'POST':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		# Grab content from request zdy
		content = request.get_json()
		# Check to see if all properties are given. - No need to validate
		if len(content) != 3:
			return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
		
		new_project = datastore.entity.Entity(key=client.key("projects"))
		new_project.update({"title": content["title"], "due_by": content["due_by"], "notes": content["notes"], "owner": jwt_sub, "tasks": [], "completed_tasks": []})
		client.put(new_project)

		# Return object
		new_project.update({'id': new_project.key.id, 'self': request.url + "/" + str(new_project.key.id)})
		return (jsonify(new_project), 201)
	elif request.method == 'GET':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		query = client.query(kind="projects")
		query.add_filter('owner', '=', jwt_sub)
		q_limit = int(request.args.get('limit', '5'))
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
			e["self"] = request.url_root + 'projects/' + str(e.key.id)
			if e['tasks']:
				for single_task in e['tasks']:
					gtask_key = client.key("tasks", single_task['id'])
					gtask = client.get(key=gtask_key)
					single_task['title'] = gtask['title']
					single_task['due_by'] = gtask['due_by']
					single_task['description'] = gtask['description']
					single_task['completed'] = gtask['completed']
					single_task["self"] = request.url_root + "tasks/" + str(single_task['id'])
			if e['completed_tasks']:
				for ctask in e['completed_tasks']:
					gtask_key = client.key("tasks", ctask['id'])
					gtask = client.get(key=gtask_key)
					ctask['title'] = gtask['title']
					ctask['due_by'] = gtask['due_by']
					ctask['description'] = gtask['description']
					ctask['completed'] = gtask['completed']
					ctask["self"] = request.url_root + "tasks/" + str(ctask['id'])

		output = {"projects": results}
		if next_url:
			output["next"] = next_url
		output['total'] = len(list(query.fetch()))
		return (jsonify(output), 200)

@app.route('/tasks', methods=['POST', 'GET'])
def tasks_post_get():
	if request.method == 'POST':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		# Grab content from request body
		content = request.get_json()
		# Check to see if all properties are given. - No need to validate
		if len(content) != 3:
			return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
		
		new_task = datastore.entity.Entity(key=client.key("tasks"))
		new_task.update({'title': content['title'], 'pid': None, 'completed': False, "description": content["description"], "due_by": content["due_by"], "owner": jwt_sub})
		client.put(new_task)

		# Return object
		new_task.update({'id': new_task.key.id, 'self': request.url + "/" + str(new_task.key.id)})
		return (jsonify(new_task), 201)
	elif request.method == 'GET':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		query = client.query(kind="tasks")
		query.add_filter('owner', '=', jwt_sub)
		q_limit = int(request.args.get('limit', '5'))
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
			e["self"] = request.url_root + 'tasks/' + str(e.key.id)
		output = {"tasks": results}
		if next_url:
			output["next"] = next_url
		output['total'] = len(list(query.fetch()))
		return (jsonify(output), 200)

@app.route('/projects/<pid>/tasks', methods=['POST', 'GET'])
def tasks_post_projects(pid):
	if request.method == 'GET':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		project_key = client.key("projects", int(pid))
		project = client.get(key=project_key)

		if project == None:
			return (jsonify({'Error': 'This project does not exist!'}), 401)

		if project['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this project!'}), 401)

		query = client.query(kind="tasks")
		query.add_filter("pid", "=", pid)
		query.add_filter("completed", "=", False)
		tasks = list(query.fetch())

		query = client.query(kind="tasks")
		query.add_filter("pid", "=", pid)
		query.add_filter("completed", "=", True)
		ctasks = list(query.fetch())

		for entity in tasks:
			entity["id"] = entity.key.id
			entity["self"] = request.url_root + "tasks/" + str(entity.key.id)
		for entity in ctasks:
			entity["id"] = entity.key.id
			entity["self"] = request.url_root + "tasks/" + str(entity.key.id)

		return(jsonify({'tasks': tasks, 'completed_tasks': ctasks}), 200)
		
	elif request.method == 'POST':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		project_key = client.key("projects", int(pid))
		project = client.get(key=project_key)

		if project == None:
			return (jsonify({'Error': 'This project does not exist!'}), 401)

		if project['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this project!'}), 401)

		# Grab content from request body
		content = request.get_json()
		# Check to see if all properties are given. - No need to validate
		if len(content) != 3:
			return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
		
		new_task = datastore.entity.Entity(key=client.key("tasks"))
		new_task.update({'title': content['title'], 'pid': pid, 'completed': False, "description": content["description"], "due_by": content["due_by"], "owner": jwt_sub})
		client.put(new_task)

		# Put task in project
		project['tasks'].append({'id': new_task.key.id, 'owner': jwt_sub, 'pid': pid})
		client.put(project)

		# Return object
		project.update({'id': project.key.id, 'self': request.url_root + "projects/" + str(project.key.id)})
		for task in project['tasks']:
			task['self'] = request.url_root + "tasks/" + str(task['id'])
		return (jsonify(project), 201)

@app.route('/projects/<pid>/tasks/<tid>', methods=['PUT'])
def put_task_project(pid, tid):
	if request.method == 'PUT':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		project_key = client.key("projects", int(pid))
		project = client.get(key=project_key)
		task_key = client.key("tasks", int(tid))
		task = client.get(key=task_key)

		if project == None:
			return (jsonify({"Error": "This project does not exist!"}), 404)
		if task == None:
			return (jsonify({"Error": "This task does not exist!"}), 404)

		if project['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this project!'}), 401)
		elif task['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this task!'}), 401)

		for ptask in project['tasks']:
			if ptask['id'] == int(tid):
				return (jsonify({'Error': 'This task is already in the project!'}), 403)
		
		project['tasks'].append({'id': task.key.id, 'owner': task['owner'], 'pid': pid})
		client.put(project)
		task['pid'] = pid
		client.put(task)

		return(jsonify(''), 204)

@app.route('/tasks/<tid>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def tasks_get_delete_put_patch(tid):
	if request.method == 'PUT' or request.method == 'PATCH':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		task_key = client.key("tasks", int(tid))
		task = client.get(key=task_key)

		if task == None:
			return (jsonify({'Error': 'This task does not exist!'}), 401)
		
		if task['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this task!'}), 401)
		
		# Grab content from request body
		content = request.get_json()
		if len(content) == 0:
			return (jsonify({"Error": "The request object is missing!"}), 400)

		# Validate content
		for prop in content:
			if prop == 'completed' and type(content.get(prop)) == bool:
				if task["pid"]:
					project_key = client.key("projects", int(task['pid']))
					project = client.get(key=project_key)
					if task['completed'] == False and content.get(prop) == True:
						project['tasks'].remove({'id': task.key.id, 'owner': jwt_sub, 'pid': str(project.key.id)})
						project['completed_tasks'].append({'id': task.key.id, 'owner': jwt_sub, 'pid': str(project.key.id)})
					elif task['completed'] == True and content.get(prop) == False:
						project['completed_tasks'].remove({'id': task.key.id, 'owner': jwt_sub, 'pid': str(project.key.id)})
						project['tasks'].append({'id': task.key.id, 'owner': jwt_sub, 'pid': str(project.key.id)})
					client.put(project)
				task["completed"] = content.get(prop)
			elif prop == 'title' and type(content.get(prop)) == str:
				task["title"] = content.get(prop)
			elif prop == 'description' and type(content.get(prop)) == str:
				task["description"] = content.get(prop)
			elif prop == 'due_by' and type(content.get(prop)) == str:
				task["due_by"] = content.get(prop)
			else:
				return (jsonify({"Error": "Invalid content!"}), 400)

		client.put(task)
		task['id'] = task.key.id
		task['self'] = request.url
		return(jsonify(task), 201)
	elif request.method == 'GET':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		task_key = client.key("tasks", int(tid))
		task = client.get(key=task_key)

		if task == None:
			return (jsonify({'Error': 'This task does not exist!'}), 401)

		if task['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this task!'}), 401)

		task['id'] = task.key.id
		task['self'] = request.url
		return(jsonify(task), 200)
	elif request.method == 'DELETE':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		task_key = client.key("tasks", int(tid))
		task = client.get(key=task_key)

		if task == None:
			return (jsonify({"Error": "No task with this task_id exists"}), 404)
		elif task['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this task!'}), 401)
		
		if task['pid']:
			project_key = client.key("projects", int(task['pid']))
			project = client.get(key=project_key)
			if task['completed']:
				project['completed_tasks'].remove({'id': task.key.id, 'owner': jwt_sub, 'pid': str(project.key.id)})
			else:
				project['tasks'].remove({'id': task.key.id, 'owner': jwt_sub, 'pid': str(project.key.id)})
			client.put(project)
		
		client.delete(task)			

		return(jsonify(''), 204)

@app.route('/projects/<pid>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def projects_get_delete(pid):
	if request.method == 'PUT' or request.method == 'PATCH':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		project_key = client.key("projects", int(pid))
		project = client.get(key=project_key)

		if project == None:
			return (jsonify({'Error': 'This project does not exist!'}), 401)
		
		if project['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this project!'}), 401)
		
		# Grab content from request body
		content = request.get_json()
		if len(content) == 0:
			return (jsonify({"Error": "The request object is missing!"}), 400)

		# Validate content
		for prop in content:
			if prop == 'title' and type(content.get(prop)) == str:
				project["title"] = content.get(prop)
			elif prop == 'notes' and type(content.get(prop)) == str:
				project["notes"] = content.get(prop)
			elif prop == 'due_by' and type(content.get(prop)) == str:
				project["due_by"] = content.get(prop)
			else:
				return (jsonify({"Error": "Invalid content!"}), 400)

		client.put(project)
		project['id'] = project.key.id
		project['self'] = request.url
		
		if project['tasks']:
			for single_task in project['tasks']:
				gtask_key = client.key("tasks", single_task['id'])
				gtask = client.get(key=gtask_key)
				single_task['title'] = gtask['title']
				single_task['due_by'] = gtask['due_by']
				single_task['description'] = gtask['description']
				single_task['completed'] = gtask['completed']
				single_task["self"] = request.url_root + "tasks/" + str(single_task['id'])
		if project['completed_tasks']:
			for ctask in project['completed_tasks']:
				gtask_key = client.key("tasks", ctask['id'])
				gtask = client.get(key=gtask_key)
				ctask['title'] = gtask['title']
				ctask['due_by'] = gtask['due_by']
				ctask['description'] = gtask['description']
				ctask['completed'] = gtask['completed']
				ctask["self"] = request.url_root + "tasks/" + str(ctask['id'])
		return(jsonify(project), 201)
	elif request.method == 'GET':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		project_key = client.key("projects", int(pid))
		project = client.get(key=project_key)

		if project == None:
			return (jsonify({"Error": "This project does not exist!"}), 404)

		if project['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this project!'}), 401)

		project['id'] = project.key.id
		project['self'] = request.url
		if project['tasks']:
			for task in project['tasks']:
				gtask_key = client.key("tasks", task['id'])
				gtask = client.get(key=gtask_key)
				task['title'] = gtask['title']
				task['due_by'] = gtask['due_by']
				task['description'] = gtask['description']
				task['completed'] = gtask['completed']
				task['self'] = request.url_root + "tasks/" + str(task['id'])
		if project['completed_tasks']:
			for ctask in project['completed_tasks']:
				gtask_key = client.key("tasks", ctask['id'])
				gtask = client.get(key=gtask_key)
				ctask['title'] = gtask['title']
				ctask['due_by'] = gtask['due_by']
				ctask['description'] = gtask['description']
				ctask['completed'] = gtask['completed']
		return(jsonify(project), 200)
	elif request.method == 'DELETE':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

		project_key = client.key("projects", int(pid))
		project = client.get(key=project_key)

		if project == None:
			return (jsonify({'Error': 'This project does not exist!'}), 401)
		
		if project['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this project!'}), 401)
		
		if project['tasks']:
			for task in project['tasks']:
				gtask_key = client.key("tasks", task['id'])
				gtask = client.get(key=gtask_key)
				gtask['pid'] = None
				client.put(gtask)
		if project['completed_tasks']:
			for task in project['completed_tasks']:
				gtask_key = client.key("tasks", task['id'])
				gtask = client.get(key=gtask_key)
				gtask['pid'] = None
				client.put(gtask)
		
		client.delete(project)
		return(jsonify(''), 204)

def verifyJWT():
	# Get JWT from Authorization header
	req = requests.Request()
	jwt_token = request.headers.get('Authorization')
	if jwt_token:
		jwt_token = jwt_token.split(" ")[1]
		# Check to see if JWT is valid
		try:
			jwt_sub = id_token.verify_oauth2_token(jwt_token, req, client_id)['sub']
		except:
			return 'fail'
	else:
		# Return 401 if no JWT is given
		return 'nojwt'
	return jwt_sub

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=8080, debug=True)
