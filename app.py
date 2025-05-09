from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import subprocess  # For executing commands
from flask_cors import CORS
from datetime import datetime
import logging  # Import the logging module
import re  # For parsing docker ps output
import json # Import the json module

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///servers.db'  # Use SQLite for simplicity, change if needed
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)  # Important for session management
db = SQLAlchemy(app)
CORS(app)  # Enable CORS to allow requests from your frontend (adjust origins if needed)

# --- Configuration for External Script Execution ---
API_KEY = 'X X X X X X X X X X X'  # Replace with a strong, unique API key
ALLOWED_SCRIPT_PATH = '/home/sysadmin/minecraft-docker/install'  # Whitelist the allowed script path
EXTERNAL_SCRIPT_ENDPOINT = '/execute_script'  # New endpoint for external script execution
ADMIN_USERNAME = 'admin'  # Replace with your desired admin username
ADMIN_PASSWORD = 'XXXXX'  # Replace with a strong admin password
ADMIN_PANEL_ENDPOINT = '/admin'
LOG_FILE = 'flask_app.log'  # Log file for the main Flask app

# --- Logging Setup ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Database Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    servers = db.relationship('Server', backref='user', lazy=True)  # Relationship with Server model

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    start_command = db.Column(db.String(512), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Server {self.name}>'


# --- Helper Functions ---
def login_required(f):
    """Decorator to require a user to be logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def require_api_key(f):
    """Decorator to require a valid API key."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('X-API-Key')
        if auth_header == API_KEY:
            return f(*args, **kwargs)
        else:
            logging.warning(f"Unauthorized access attempt with API key: {auth_header}")
            return jsonify({"error": "Unauthorized"}), 401
    wrapper.__name__ = f.__name__
    return wrapper

def admin_login_required(f):
    """Decorator to require admin login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            return render_template('admin_login.html')  # Create a simple admin_login.html
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def execute_docker_command(command_list):
    """Helper function to execute Docker commands."""
    try:
        process = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=15)
        output = stdout.decode('utf-8').strip()
        error = stderr.decode('utf-8').strip()
        if error:
            logging.error(f"Error running Docker command {command_list}: {error}")
            return False, error
        return True, output
    except FileNotFoundError:
        error = "Error: 'docker' command not found. Ensure Docker is installed."
        logging.error(error)
        return False, error
    except subprocess.TimeoutExpired:
        error = f"Error: Docker command {command_list} timed out."
        logging.error(error)
        return False, error
    except Exception as e:
        error = f"An unexpected error occurred: {e}"
        logging.error(f"Error running Docker command {command_list}: {e}")
        return False, error
# -- docker stats

def get_docker_stats():
    """Fetches Docker container statistics for all containers (running and stopped),
    showing '0%' and '0 MB' for stopped containers, and includes port information.
    """
    all_containers_info = []
    try:
        # Get a list of all containers (name, ID, state, and ports)
        list_command = ['docker', 'ps', '-a', '--format', '{{json .}}']
        list_result = subprocess.run(list_command, capture_output=True, text=True, check=True)
        list_output = list_result.stdout.strip().split('\n')

        running_container_names = set()
        container_ports = {}  # Store ports for each container

        for line in list_output:
            try:
                container_info = json.loads(line)
                name = container_info.get('Names', 'N/A')
                state = container_info.get('State', 'N/A')
                container_id_short = container_info.get('ID', 'N/A')[:12]

                # Get port mappings using 'docker inspect'
                inspect_command = ['docker', 'inspect', name, '--format', '{{json .NetworkSettings.Ports}}']
                inspect_result = subprocess.run(inspect_command, capture_output=True, text=True, check=False) # Don't check=True as stopped containers might not have network settings
                ports_output = inspect_result.stdout.strip()
                ports = []
                if inspect_result.returncode == 0 and ports_output and ports_output != 'null':
                    ports_data = json.loads(ports_output)
                    for private_port, public_infos in ports_data.items():
                        if public_infos:
                            for public_info in public_infos:
                                ports.append({
                                    'private_port': private_port.split('/')[0], # Remove protocol from private port
                                    'public_port': public_info.get('HostPort'),
                                    'type': private_port.split('/')[1] if '/' in private_port else 'tcp' # Default to tcp if no protocol
                                })
                container_ports[name] = ports

                container_data = {
                    'name': name,
                    'id': container_id_short,
                    'state': state,
                    'ports': ports,
                }
                if state.startswith('running'):
                    container_data.update({
                        'cpu_percent': 'N/A',  # Will be updated with actual stats
                        'mem_usage': 'N/A',
                        'mem_percent': 'N/A',
                    })
                    running_container_names.add(name)
                else:
                    container_data.update({
                        'cpu_percent': '0%',
                        'mem_usage': '0 MB',
                        'mem_percent': '0%',
                    })
                all_containers_info.append(container_data)

            except json.JSONDecodeError as e:
                logging.error(f"Error decoding container list JSON: {e}, line: {line}")

        # Get live stats for running containers
        if running_container_names:
            stats_command = ['docker', 'stats', '--no-stream', '--format', '{{json .}}'] + list(running_container_names)
            stats_result = subprocess.run(stats_command, capture_output=True, text=True, check=False) # Don't check=True in case some containers exited very recently
            if stats_result.returncode == 0:
                stats_output = stats_result.stdout.strip().split('\n')
                for line in stats_output:
                    try:
                        stats_data = json.loads(line)
                        name = stats_data.get('Name')
                        if name in [info['name'] for info in all_containers_info if info['state'].startswith('running')]:
                            for info in all_containers_info:
                                if info['name'] == name:
                                    info['cpu_percent'] = stats_data.get('CPUPerc', 'N/A')
                                    info['mem_usage'] = stats_data.get('MemUsage', 'N/A').split('/')[0].strip() if stats_data.get('MemUsage') else 'N/A'
                                    info['mem_percent'] = stats_data.get('MemPerc', 'N/A')
                                    break
                    except json.JSONDecodeError as e:
                        logging.error(f"Error decoding stats JSON: {e}, line: {line}")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running Docker command: {e}")
        return []
    return all_containers_info

# --- Admin Routes ---
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(ADMIN_PANEL_ENDPOINT)
        else:
            return render_template('admin_login.html', error='Invalid credentials')
    return render_template('admin_login.html')

@app.route(ADMIN_PANEL_ENDPOINT, methods=['GET'])
@admin_login_required
def admin_panel():
    container_stats = get_docker_stats()
    return render_template('admin_panel.html', containers=container_stats)

@app.route('/admin/stop/<container_name>', methods=['POST'])
@admin_login_required
def stop_container(container_name):
    success, output = execute_docker_command(['docker', 'stop', container_name])
    if success:
        logging.info(f"Stopped container: {container_name}")
    else:
        logging.error(f"Failed to stop container {container_name}: {output}")
    return redirect(ADMIN_PANEL_ENDPOINT)

@app.route('/admin/remove/<container_name>', methods=['POST'])
@admin_login_required
def remove_container(container_name):
    success, output = execute_docker_command(['docker', 'rm', container_name])
    if success:
        logging.info(f"Removed container: {container_name}")
    else:
        logging.error(f"Failed to remove container {container_name}: {output}")
    return redirect(ADMIN_PANEL_ENDPOINT)

import subprocess
from flask import jsonify

@app.route('/start/<container_name>', methods=['POST'])
def start_container(container_name):
    success, output = execute_docker_command(['docker', 'start', container_name])
    if success:
        logging.info(f"Started container: {container_name}")
    else:
        logging.error(f"Failed to start container {container_name}: {output}")
    return redirect(ADMIN_PANEL_ENDPOINT)

# --- User Routes ---
@app.route('/register', methods=['POST'])
def register():
    """Handles user registration."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409

    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registration successful"}), 201

@app.route('/login', methods=['POST'])
def login():
    """Handles user login."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        session['user_id'] = user.id  # Store user ID in session
        return jsonify({"message": "Login successful", "user_id": user.id, "username": user.username}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    """Handles user logout."""
    session.pop('user_id', None)  # Remove user ID from session
    return jsonify({"message": "Logout successful"}), 200

@app.route('/check_login', methods=['GET'])
def check_login():
    """Checks if the user is logged in."""
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            return jsonify({'logged_in': True, 'username': user.username}), 200
        else:
            return jsonify({'logged_in': False, 'username': None}), 200
    else:
        return jsonify({'logged_in': False, 'username': None}), 200

@app.route('/servers', methods=['GET'])
@login_required
def get_servers():
    """Retrieves all servers belonging to the logged-in user."""
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    servers = [
        {
            'id': server.id,
            'name': server.name,
            'ip_address': server.ip_address,
            'port': server.port,
            'created_at': server.created_at.isoformat(),
            'start_command': server.start_command  # Include the start command in the response
        }
        for server in user.servers
    ]
    return jsonify(servers), 200

@app.route('/servers', methods=['POST'])
@login_required
def create_server():
    """Creates a new server for the logged-in user."""
    data = request.get_json()
    name = data.get('name')
    ip_address = data.get('ip_address')
    port = data.get('port')
    start_command = data.get('start_command')  # Get the start command from the request
    user_id = session.get('user_id')

    if not all([name, ip_address, port, start_command]):
        return jsonify({"error": "Missing required fields"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    new_server = Server(
        name=name,
        ip_address=ip_address,
        port=port,
        start_command=start_command,  # Store the start command
        user=user
    )
    db.session.add(new_server)
    db.session.commit()
    return jsonify({"message": "Server created successfully", "server_id": new_server.id}), 201

@app.route('/start_server/<int:server_id>', methods=['POST'])
@login_required
def start_server(server_id):
    """Starts the server with the given ID for the logged-in user."""
    user_id = session.get('user_id')
    server = Server.query.filter_by(id=server_id, user_id=user_id).first()

    if not server:
        return jsonify({"error": "Server not found or unauthorized"}), 404

@app.route('/user/servers', methods=['GET'])
@login_required
def get_user_servers():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User \xa0not found"}), 404
    servers = [
        {
            'id': server.id,
            'name': server.name,
            'ip_address': server.ip_address,
            'port': server.port,
            'created_at': server.created_at.isoformat(),
            'start_command': server.start_command
        }
        for server in user.servers
    ]
    return jsonify(servers), 200

    print(f"Attempting to start server: {server.name} (ID: {server.id}) with command: {server.start_command}")
    try:
        process = subprocess.Popen(
            [server.start_command],  # Execute the stored start command directly
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False
        )
        stdout, stderr = process.communicate(timeout=10)  # added timeout
        if stderr:
            print(f"Error starting server: {stderr.decode()}")
            return jsonify({"error": "Failed to start server", "details": stderr.decode()}), 500
        print(f"Server started (process ID: {process.pid})")
        return jsonify({"message": f"Server {server.name} started!", "process_id": process.pid}), 200

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Server start timed out"}), 500
    except Exception as e:
        print(f"Exception starting server: {e}")
        return jsonify({"error": "Failed to start server", "details": str(e)}), 500

@app.route(EXTERNAL_SCRIPT_ENDPOINT, methods=['POST'])
@require_api_key
def execute_external_script():
    """Endpoint to securely execute a whitelisted external script."""
    data = request.get_json()
    if not data or 'script_path' not in data:
        logging.error("Missing 'script_path' in request body for external script execution")
        return jsonify({"error": "Missing 'script_path' in request body"}), 400

    script_path = data['script_path']

    # --- Security Check: Whitelist Allowed Script ---
    if script_path != ALLOWED_SCRIPT_PATH:
        logging.warning(f"Attempted execution of unauthorized script: {script_path}")
        return jsonify({"error": "Unauthorized script path"}), 403

    logging.info(f"Attempting to execute external script: {script_path}")
    try:
        process = subprocess.Popen(
            [script_path],  # Execute the script directly
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(script_path),  # Set the working directory
            shell=False
        )
        stdout, stderr = process.communicate(timeout=60)
        return_code = process.returncode  # Get the exit code

        if return_code != 0:
            error_message = stderr.decode()
            logging.error(f"Error executing external script (return code {return_code}): {error_message}")
            return jsonify({"error": "Failed to execute external script", "details": error_message}), 500
        else:
            output = stdout.decode()
            logging.info(f"External script executed successfully. Output: {output}")
            return jsonify({"message": "External script executed successfully", "output": output}), 200

    except subprocess.TimeoutExpired:
        logging.error("External script execution timed out")
        return jsonify({"error": "External script execution timed out"}), 500
    except FileNotFoundError:
        logging.error(f"Script not found at: {script_path}")
        return jsonify({"error": "External script not found at specified path"}), 404
    except Exception as e:
        error_message = str(e)
        logging.error(f"Exception during external script execution: {error_message}")
        return jsonify({"error": "Failed to execute external script", "details": error_message}), 500


@app.route('/test_api', methods=['GET'])
def test_api():
    """Simple test endpoint."""
    return jsonify({"message": "API is working!"}), 200

if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
        print("Database Initialized")  # prints to console
    app.run(host='0.0.0.0', port=5000, debug=True)
