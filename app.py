import jwt
from flask import Flask, request, jsonify, g
from datatime import datetime, timedelta
from functools import wraps
from flaskext.mysql import MySQL

# Initialize flask app
app = Flask(__name__)

# conf MySQL settings
app.config['MYSQL_DATABASE_USER'] = 'segun'
app.config['MYSQL_DATABASE_PASSWORD'] = ''
app.config['MYSQL_DATABASE_DB'] = 'RECORDS'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'

# Initialize MySQL
mysql = MySQL(app)

# In-memory store for user database
users = []

# Generate alternative usernames by appending numbers
def suggest_username(username):
    suggested_username =username
    counter = 1
    while any(user['username'] == suggested_username for user in users):
        suggested_username = f"{username}{counter}"
        counter += 1
        return suggested_username

# Secret key for JWT encoding/decoding(!!!note: KEY should be taken seriouly)
SECRET_KEY = 'secret-key'


# Home route for app
@app.route('/')
def homepage():
    return "Hello, Alumni's! API"


# route for handle registration via POST requests
@app.route('/register', methods=['POST'])
def register():
    try:
        # Get JSON data from request body
        data = request.json

        # extract registration data from JSON
        first_name = data['first_name']
        middle_name = data['middle_name']
        last_name = data['last_name']
        grad_year = data['grad_year']
        username = data['username']
        password = data['password']

        conn = mysql.connect()
        cursor = conn.cursor()

        # Check if the username is already taken
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            suggested_username = suggest_username(username)
            return jsonify({"message": f"Username already taken, Try {suggest_username} instead"})
        
        
        # Add New User Data into the database
        cursor.execute("INSERT INTO users (first_name, middle_name, last_name, grad_year, username, password) VALUES (%s, %s, %s, %s, %s, %s)",
                (first_name, middle_name, last_name, grad_year, username, password))
        conn.commit()

        cursor.close()
        conn.close()

        # Return successfully response with status code
        return jsonify({"message": "User registration successfully!"}), 201
    
    except Exception as e:
        # Return an error response if an exception occurs
        return jsonify({"error", str(e)}), 500


# route that handles User Login 
@app.route('/login', methods=['POST'])
def login():
    # Get JSON data from request body
    data = request.json

    # Extract username and password from request body
    username = data['username']
    password = data['password']

    conn = mysql.connect()
    cursor = conn.cursor()

    # Find User in Alumni database
    cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
    user = cursor.fetchone()

    # if the user exists and the password matches
    if user and user['password'] == password:
        # Generate a JWT token
        payload = {
                # unique identifier for each user
                'user_id': user['id'],
                # Token expiration time
                'exp': datetime.utcnow() + timedelta(days=1)
                }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return jsonify({"token": token}), 200
    else:
        return jsonify({"message": "Invalid Credentials"}), 401

# route that handles retrieving user data based on username
@app.route('/users/<username>', methods=['GET'])
def get_user_by_username(username):
    conn = mysql.connect()
    cursor = conn.cursor()

    # Find User in Alumni database
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user:
        return jsonify(user), 200
    else:
        return jsonify({"message": "User Not Found"}), 404


# route that handles updating of user data based on username
@app.route('/users/<username>', methods=['PUT'])
def update_user(username):
    
    conn = mysql.connect()
    cursor = conn.cursor()

    # Get user json data from request body
    data = request.json

    # check for user in database(Alumni database)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    
    if user:
        # Update user data based on incoming JSON data
        cursor.execute("UPDATE users SET first_name = %s, middle_name = %s, last_name = %s, grad_year = %s WHERE username = %s",
                (data['first_name'], data['middle_name'], data['last_name'], data['grad_year'], username))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"message": "Update Successful!"}), 200
    else:
        cursor.close()
        conn.close()
                
        # check for user in database(Alumni database)
        return jsonify({"message": "User Not Found"}), 404

# route that handles deleting of user data based on username
@app.route('/users/<username>', methods=['DELETE'])
def del_user(username):
    conn = mysql.connect()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM users WHERE username = %s", (username,))
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({"message": "User deleted successfully!"}), 200


# route for users(Alumni database)
@app.route('/users', methods=['GET'])
def get_users():
    return jsonify(users)

# Custom decorator to enforce authentication on routes
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get the token from the 'Authorization' header of the request
        token = request.headers.get('Authorization', None)

        # If the token is missing, return a 401 Unauthorized response
        if not token:
            return jsonify({"message": "Token is missing"}), 401

        try:
            # Decode the token using the secret key and the chosen algorithm
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

            # store user ID from the token in the request for use in route
            g.user_id = decoded_token['user_id']
        except jwt.ExpiredSignatureError:
            # if token has expired, return a 401 Unauthorized response
            return jsonify({"message": "Token has expired"}), 401
        except jwt.DecodeError:
            # if the token is invalid, return a 401 Unauthorized response
            return jsonify({"message": "Token is Invalid"}), 401
        
        
        # If token is valid and user is authorized, proceed to the original route function
        return f(*args, **kwargs)

    # Return the decorated function
    return decorated        

# run app if script is executed
if __name__ == '__main__':
    app.run(debug=True)
