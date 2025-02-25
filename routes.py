from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from models import User, Event, db, users_schema, user_schema
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
from email_validator import validate_email, EmailNotValidError
from functools import wraps


routes = Blueprint('routes', __name__)

def role_required(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            username = get_jwt_identity()
            user = User.query.filter_by(username=username).first()

            if user is not None and user.role != required_role:
                return jsonify({"error": "Unauthorized"}), 403
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


@routes.route('/')
def home():
    return jsonify({"key": "message"})

@routes.route('/register', methods=['POST'])
def create_user():
    data = request.json

    # Check for missing fields
    required_fields = {"username", "email", "password", "role"}
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
    
    role = data.get("role", "customer").lower()  # Default to "customer"
    if role not in ["customer", "service_provider"]:
        return jsonify({"error": "Invalid role"}), 400

    # Check if the username or email already exists
    if User.query.filter((User.username == data["username"]) | (User.email == data["email"])).first():
        return jsonify({"error": "Registration failed"}), 400  # Generic error message
  
    # Create and save the new user
    try:
        new_user = User(username=data["username"], email=data["email"], password=hashed_password, role=data["role"])
        db.session.add(new_user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Registration failed"}), 500  # Generic error message

    return jsonify(user_schema.dump(new_user)), 201

@routes.route('/login', methods=['POST'])
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
    access_token = create_access_token(identity=user.username, additional_claims={"role": user.role})
    return jsonify({"access_token": access_token, "role": user.role}), 200

@routes.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    refreshed_access_token = create_access_token(identity=user.username, additional_claims={"role": user.role})
    
    return jsonify({"access_token": refreshed_access_token}), 200



@routes.route('/users', methods=['GET'])
@jwt_required()
@role_required("admin")
def get_users():
    users = User.query.all()
    return jsonify(users_schema.dump(users)), 200



@routes.route('/events', methods=['GET','POST'])
@jwt_required()
@role_required("customer")
def event():
    
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    
    if request.method == 'POST':
        data = request.json
        # Check for missing fields
        required_fields = {"name", "date_time", "location", "category"}
        if required_fields - data.keys():
            return jsonify({"error": "Missing fields"}), 400

        try:
            event = Event(
                name=data["name"],
                description=data.get("description"),
                date_time=datetime.strptime(data["date_time"], "%Y-%m-%d %H:%M:%S"),
                location=data["location"],
                category=data["category"],
                budget=data.get("budget"),
                additional_requests=data.get("additional_requests"),
                customer_id=user.id
            )
            db.session.add(event)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": "Failed to create event", "details": str(e)}), 500

        return jsonify({"message": "Event created successfully!", "event": {
            "name": event.name,
            "description": event.description,
            "date_time": event.date_time.strftime("%Y-%m-%d %H:%M:%S"),
            "location": event.location,
            "category": event.category,
            "budget": event.budget,
            "additional_requests": event.additional_requests,
            "customer_id": event.customer_id
        }}), 201
    

    events = Event.query.filter_by(customer_id=user.id).all()
    
    event_list = [{
        "id": event.id,
        "name": event.name,
        "description": event.description,
        "date_time": event.date_time.strftime("%Y-%m-%d %H:%M:%S"),
        "location": event.location,
        "category": event.category,
        "budget": event.budget,
        "additional_requests": event.additional_requests
    } for event in events]

    return jsonify({"events": event_list}), 200
        

@routes.route('/events/edit/<int:id>', methods=['GET','POST'])
@jwt_required()
@role_required("customer")
def edit_event(id):
    data=request.json
    # event= Event.query.filter_by(id=id).first  (will come in need when frontend implementation starts)
    
    try:
        event = Event(
            name=data["name"],
            description=data.get("description"),
            date_time=datetime.strptime(data["date_time"], "%Y-%m-%d %H:%M:%S"),
            location=data["location"],
            category=data["category"],
            budget=data.get("budget"),
            additional_requests=data.get("additional_requests"),
            customer_id= id
        )
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to update event", "details": str(e)}), 500
    
    return jsonify({"message": "Event updated successfully!", "event": {
            "name": event.name,
            "description": event.description,
            "date_time": event.date_time.strftime("%Y-%m-%d %H:%M:%S"),
            "location": event.location,
            "category": event.category,
            "budget": event.budget,
            "additional_requests": event.additional_requests,
            "customer_id": event.customer_id
        }}), 201
    
@routes.route("/events/delete/<int:id>", methods= ['POST'])
@jwt_required()
@role_required("customer")
def delete_event(id):
    event= Event.query.filter_by(id=id).first()
    print(event)
    try:
        db.session.delete(event)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete event", "details": str(e)}), 500

    return jsonify({"message": "Deleted event successfully"}), 201

    
'''DASHBOARDS'''


@routes.route('/admin/dashboard', methods=['GET'])
@jwt_required()
@role_required("admin")
def admin_dashboard():
    return jsonify({"message": "Welcome, Admin!"})

@routes.route('/provider/dashboard', methods=['GET'])
@jwt_required()
@role_required("service_provider")
def provider_dashboard():
    return jsonify({"message": "Welcome, Service Provider!"})

@routes.route('/customer/dashboard', methods=['GET'])
@jwt_required()
@role_required("customer")
def customer_dashboard():
    return jsonify({"message": "Welcome, Customer!"})
