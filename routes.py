from crypt import methods
from flask import Blueprint, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from sqlalchemy import func
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
    new_user = User(username=data['username'], password_hash=hashed_password)

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

    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        access_token = create_access_token(identity=user.username)
        return jsonify({"access_token": access_token}), 200

    return jsonify({"error": "Invalid credentials"}), 401

# Add Expense Route
@routes.route('/add_expense', methods=['POST'])
@jwt_required()
def add_expense():
    data = request.get_json()
    current_user = get_jwt_identity()

    try:
        amount = float(data.get("amount"))
    except(TypeError, ValueError):
        return jsonify({"error": "Invalid input. Amount must be a number."}), 400


    if not data.get("name") or not data.get("category") or not isinstance(data.get("amount"), (int, float)) or not data.get("split_mode"):
        return jsonify({"error": "Invalid input. Enter data in all the fields."}), 400

    user1 = User.query.filter_by(username=current_user).first()
    user2 = User.query.filter_by(username=data.get("split_with")).first()

    if not user1 or (data.get("split_with") and not user2):
        return jsonify({"error: User not found."}),404

    split_mode = data["split_mode"]
    split_with_user_id = user2.id if user2 else None

    if split_mode not in ["user1_paid_split_equal", "user2_paid_split_equal", "user1_paid_no_split",
                          "user2_paid_no_split"]:
        return jsonify({"error": "Invalid split mode."}), 400

#Split amount calculation

    user1_share, user2_share = 0, 0

    if split_mode == "user1_paid_split_equal":
        user1_share, user2_share = amount / 2, amount / 2
    elif split_mode == "user2_paid_split_equal":
        user1_share, user2_share = amount / 2, amount / 2
    elif split_mode == "user1_paid_no_split":
        user1_share, user2_share = amount, 0
    elif split_mode == "user2_paid_no_split":
        user1_share, user2_share = 0, amount

    new_expense = Expense(
        user_id=user1.id,
        split_with_user_id=split_with_user_id,
        name=data["name"],
        category=data["category"],
        amount=amount,
        split_mode=split_mode,
        user1_share=user1_share,
        user2_share=user2_share
    )

    try:
        db.session.add(new_expense)
        db.session.commit()
        return jsonify({"message": "Expense added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@routes.route('/get_expenses', methods=['GET'])
@jwt_required()
def get_expenses():
    current_user = get_jwt_identity()

    user = User.query.filter_by(username=current_user).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        # Fetch all expenses where the user is involved
        expenses = Expense.query.filter(
            (Expense.user_id == user.id) | (Expense.split_with_user_id == user.id)
        ).all()

        # Total expense initiated by the user
        total_expense = db.session.query(func.sum(Expense.amount)).filter(Expense.user_id == user.id).scalar() or 0

        # Compute balance: amount user owes or is owed
        amount_owed = 0
        amount_lent = 0

        expenses_list = []
        for exp in expenses:
            expense_data = {
                "id": exp.id,
                "name": exp.name,
                "category": exp.category,
                "amount": exp.amount,
                "split_with_user_id": exp.split_with_user_id,
                "split_mode": exp.split_mode,
                "user1_share": exp.user1_share,
                "user2_share": exp.user2_share
            }

            # Determine how much user owes or is owed
            if exp.split_with_user_id == user.id:
                if exp.split_mode in ["user1_paid_split_equal", "user2_paid_split_equal"]:
                    amount_owed += exp.user2_share  # user owes this much
                elif exp.split_mode == "user2_paid_no_split":
                    amount_owed += exp.amount  # user2 paid everything, user1 owes full amount

            if exp.user_id == user.id:
                if exp.split_mode in ["user1_paid_split_equal", "user2_paid_split_equal"]:
                    amount_lent += exp.user1_share  # user paid this much for the other person
                elif exp.split_mode == "user1_paid_no_split":
                    amount_lent += 0  # No split, user paid their own expense

            expenses_list.append(expense_data)

        return jsonify({
            "total_expense": total_expense,
            "amount_owed": amount_owed,
            "amount_lent": amount_lent,
            "expenses": expenses_list
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500