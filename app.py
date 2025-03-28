from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from config import Config
from models import db
from routes import routes, bcrypt, jwt

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
bcrypt.init_app(app)
jwt.init_app(app)

# Register Routes
app.register_blueprint(routes)

# Create DB Tables (Only needed once)
try:
    with app.app_context():
        db.create_all()
    print("Connected to DB and created tables")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    app.run(debug=True)
