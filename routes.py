from crypt import methods

from flask import Blueprint, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import db, User, Expense

bcrypt = Bcrypt()
jwt = JWTManager()

# Create Blueprint for routes
routes = Blueprint('routes', __name__)


#health
@routes.route('/', methods=['GET'])
def health():
    return "Flask server is running!!"


# Signup Route
@routes.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password required"}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User created successfully"}), 201
    except:
        return jsonify({"error": "Username already exists"}), 400

# Login Route
@routes.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.username)
        return jsonify({"access_token": access_token}), 200

    return jsonify({"error": "Invalid credentials"}), 401

# Add Expense Route
@routes.route('/add_expense', methods=['POST'])
@jwt_required()
def add_expense():
    data = request.get_json()
    current_user = get_jwt_identity()

    if not data.get("name") or not data.get("category") or not isinstance(data.get("amount"), (int, float)):
        return jsonify({"error": "Invalid input. Provide name, category, and amount."}), 400

    new_expense = Expense(
        user_id=User.query.filter_by(username=current_user).first().id,
        name=data["name"],
        category=data["category"],
        amount=float(data["amount"])
    )

    try:
        db.session.add(new_expense)
        db.session.commit()
        return jsonify({"message": "Expense added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
