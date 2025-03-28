from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    expenses = db.relationship('Expense', backref='user', lazy=True, foreign_keys='Expense.user_id')

#Expense Model
class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    split_with_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    split_mode = db.Column(db.String(50), nullable=False)
    user1_share = db.Column(db.Float, nullable=False, default=0)
    user2_share = db.Column(db.Float, nullable=False, default=0)
