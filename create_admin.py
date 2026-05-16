import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
import getpass

# Setup a minimal Flask app to access the database
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

def create_admin():
    print("--- PhishGuard Admin Creation Utility ---")
    username = input("Enter Admin Username: ")
    password = getpass.getpass("Enter Admin Password: ")
    confirm = getpass.getpass("Confirm Admin Password: ")

    if password != confirm:
        print("Error: Passwords do not match!")
        return

    with app.app_context():
        # Check if user already exists
        existing = User.query.filter_by(username=username).first()
        if existing:
            print(f"Error: User '{username}' already exists. Promoting to admin instead...")
            existing.role = 'admin'
            db.session.commit()
            print("Successfully promoted existing user to Admin!")
        else:
            new_admin = User(
                username=username,
                password=generate_password_hash(password),
                role='admin'
            )
            db.session.add(new_admin)
            db.session.commit()
            print(f"Successfully created new Admin account: {username}")

if __name__ == "__main__":
    create_admin()
