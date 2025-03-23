import sqlalchemy.exc
from sqlalchemy import text
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admin:npg_iXN1oyYr8UeR@ep-winter-wind-a143tvcz-pooler.ap-southeast-1.aws.neon.tech/splitItDB?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'my_secret'

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


try:
    with app.app_context():
        db.create_all()
    print("Connected to DB and created tables")
except sqlalchemy.exc.OperationalError as e:
    print(f"Database connection failed! Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")


#Health route
@app.route("/")
def health():
    return "Flask server is running !!"


# Signup Route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    print(data)
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    new_user = User(username=data['username'], password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User created successfully"}), 201
    except:
        return jsonify({"error": "Username already exists"}), 400



# Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.username)
        print("Logged in successfully!!")
        return jsonify({"access_token": access_token}), 200
    return jsonify({"error": "Invalid credentials"}), 401



# Protected Route Example
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello, user {current_user}"}), 200



@app.route('/add_expense', methods =['POST'])
# @jwt_required()
def addExpense():
    data = request.get_json()
    print("Received expense data:", data)
    return jsonify({"message": "Expense received", "data": data}), 200



if __name__ == '__main__':
    print("Starting Flask application...")
    app.run(debug=True)
