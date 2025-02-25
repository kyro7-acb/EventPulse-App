from flask import Flask
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os
from datetime import timedelta
from models import db
from routes import routes

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Avoids unnecessary overhead

# Set the JWT secret key from environment variables
jwt_secret_key = os.getenv('jwtkey')
if not jwt_secret_key:
    raise ValueError("JWT_SECRET_KEY is not set in the environment variables.")
app.config['JWT_SECRET_KEY'] = jwt_secret_key
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)

db.init_app(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

app.register_blueprint(routes)

if __name__ == "__main__":
    app.run(debug=True)