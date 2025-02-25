from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field


db = SQLAlchemy()

class Role:
    ADMIN = "admin"
    CUSTOMER = "customer"
    SERVICE_PROVIDER = "service_provider"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=Role.CUSTOMER)
    
# Define the User schema
class UserSchema(SQLAlchemySchema):
    class Meta:
        model = User
        load_instance = True  # Deserialize to model instances

    # Explicitly define fields
    id = auto_field()
    username = auto_field()
    email = auto_field()
    role = auto_field()
    
# Create instances of the schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)

    
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date_time = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    budget = db.Column(db.Float, nullable=True)
    additional_requests = db.Column(db.Text, nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    customer = db.relationship('User', backref=db.backref('events', lazy=True))