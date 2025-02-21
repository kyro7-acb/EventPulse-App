from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Avoids unnecessary overhead

# Set the JWT secret key from environment variables
jwt_secret_key = os.getenv('jwtkey')
if not jwt_secret_key:
    raise ValueError("JWT_SECRET_KEY is not set in the environment variables.")
app.config['JWT_SECRET_KEY'] = jwt_secret_key


jwt = JWTManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# Define the User schema
class UserSchema(SQLAlchemySchema):
    class Meta:
        model = User
        load_instance = True  # Deserialize to model instances

    # Explicitly define fields
    id = auto_field()
    username = auto_field()
    email = auto_field()

# Create instances of the schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)

@app.route('/')
def home():
    return jsonify({"key": "message"})

@app.route('/register', methods=['POST'])
def create_user():
    data = request.json

    # Check for missing fields
    required_fields = {"username", "email", "password"}
    if required_fields - data.keys():
        return jsonify({"error": "Missing fields"}), 400

    # Validate email format
    try:
        validate_email(data["email"])
    except EmailNotValidError:
        return jsonify({"error": "Invalid email format"}), 400

    # Validate password complexity
    password = data["password"]
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400

    # Hash the password before storing it
    hashed_password = generate_password_hash(password)

    # Check if the username or email already exists
    if User.query.filter((User.username == data["username"]) | (User.email == data["email"])).first():
        return jsonify({"error": "Registration failed"}), 400  # Generic error message

    # Create and save the new user
    try:
        new_user = User(username=data["username"], email=data["email"], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Registration failed"}), 500  # Generic error message

    return jsonify(user_schema.dump(new_user)), 201

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
      users = User.query.all()
      return jsonify(users_schema.dump(users)), 200
    



@app.route('/login', methods=['POST'])
def login():
    data = request.json

    # Check if email and password are provided
    if not data or "email" not in data or "password" not in data:
        return jsonify({"error": "Fill up every requireed fields."}), 400

    # Retrieve user by email
    user = User.query.filter_by(email=data["email"]).first()
    if not user or not check_password_hash(user.password, data["password"]):
        return jsonify({"error": "Invalid email or password"}), 401

    # Generate JWT token
    access_token = create_access_token(identity=user.username)
    return jsonify({"access_token": access_token}), 200



if __name__ == "__main__":
    app.run(debug=True)