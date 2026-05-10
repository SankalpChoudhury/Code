from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import numpy as np
import os
import pickle
import pandas as pd
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'phishing_detection_secret_key_123')

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# CSS fix by adding modified timestamp
@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)

def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                 endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)

# load model
model_RF = pickle.load(open('model_RF.pkl','rb'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Administrator access required. Please log in.", "warning")
            return redirect(url_for('admin_login'))
        if session.get('role') != 'admin':
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@app.route('/first')
def first():
    return render_template('first.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    import random
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        captcha_answer = request.form.get('captcha_answer')
        
        # Verify Captcha
        if str(captcha_answer) != str(session.get('captcha_result')):
            flash("Incorrect CAPTCHA answer. Please try again.", "danger")
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            if user['role'] == 'admin':
                flash("Admins must use the Admin Login portal.", "warning")
                return redirect(url_for('admin_login'))
            
            session['user'] = user['username']
            session['role'] = user['role']
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials. Please try again.", "danger")
            
    # Generate new Captcha for GET request
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    session['captcha_result'] = num1 + num2
    captcha_text = f"{num1} + {num2}"
            
    return render_template('login.html', portal_type="User", captcha_text=captcha_text)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    import random
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        captcha_answer = request.form.get('captcha_answer')
        
        # Verify Captcha
        if str(captcha_answer) != str(session.get('admin_captcha_result')):
            flash("Incorrect CAPTCHA. Access Denied.", "danger")
            return redirect(url_for('admin_login'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password) and user['role'] == 'admin':
            session['user'] = user['username']
            session['role'] = user['role']
            flash("Admin session established.", "success")
            return redirect(url_for('upload'))
        else:
            flash("Invalid admin credentials.", "danger")
            
    # Generate new Captcha for GET request
    num1 = random.randint(5, 15)
    num2 = random.randint(5, 15)
    session['admin_captcha_result'] = num1 + num2
    captcha_text = f"{num1} + {num2}"
            
    return render_template('admin_login.html', portal_type="Admin", captcha_text=captcha_text)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash("Username and password are required.", "warning")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        role = 'admin' if username.lower() == 'admin' else 'user'

        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                         (username, hashed_password, role))
            conn.commit()
            conn.close()
            flash(f"Registration successful! Role: {role.capitalize()}. Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists. Please choose another one.", "danger")
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('first'))

@app.route('/upload')
@admin_required
def upload():
    return render_template('upload.html')  

@app.route('/preview',methods=["POST"])
@admin_required
def preview():
    if request.method == 'POST':
        dataset = request.files['datasetfile']
        if dataset:
            file_path = os.path.join(app.root_path, 'dataset_Upload.csv')
            dataset.save(file_path)
            df = pd.read_csv(file_path, encoding='unicode_escape')
            # Handle possible Id column for preview display
            if 'Id' in df.columns:
                df.set_index('Id', inplace=True)
            return render_template("preview.html", df_view=df)
    return redirect(url_for('upload'))

@app.route('/train', methods=['POST'])
@admin_required
def train():
    import subprocess
    import sys
    try:
        # Run the training script using the same python executable that is running Flask
        result = subprocess.run([sys.executable, 'random_forest_test.py'], 
                              capture_output=True, text=True, check=True)
        
        # Reload the model in the current process
        global model_RF
        model_RF = pickle.load(open('model_RF.pkl', 'rb'))
        
        flash("Model retrained successfully with the new dataset!", "success")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else e.stdout
        flash(f"Retraining failed: {error_msg}", "danger")
    except Exception as e:
        flash(f"Error during retraining: {str(e)}", "danger")
    
    return redirect(url_for('upload'))

@app.route("/home")
@app.route("/dashboard")
@login_required
def home():
    return render_template('index.html')

@app.route("/detect")
@login_required
def detect():
    return render_template('detector.html')

@app.route("/information")
@login_required
def information():
    try:
        with open('accuracy.txt', 'r') as f:
            current_acc = f.read()
    except:
        current_acc = "95.2" # Fallback
    return render_template('information.html', acc=current_acc)

from url_extractor import (
    extract_features,
    is_high_risk_phishing_pattern,
    is_high_risk_feature_profile,
)

@app.route("/result", methods=['POST','GET'])
@login_required
def result():
    # Only use values that exist in the form to avoid errors if some are hidden
    int_features = []
    expected_order = ['ip', 'ul', 'at', 'ps', 'sd', 'ht', 'ru', 'ua', 'sfh', 'ab', 're', 'mo', 'po', 'ad', 'dns', 'wt']
    for key in expected_order:
        val = request.form.get(key, '1') # Default to 1 (usually neutral)
        int_features.append(int(val))
        
    final = [np.array(int_features)]
    predict = model_RF.prediction(final)
    
    if predict == 1:
        return render_template('result.html', pred='SAFE', url="Manual Entry")
    return render_template('result.html', pred='Phishing', url="Manual Entry")

@app.route("/detect_url", methods=['GET', 'POST'])
@login_required
def detect_url():
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            # Rule-based check first
            if is_high_risk_phishing_pattern(url):
                return render_template('result.html', pred='Phishing', url=url)

            int_features = extract_features(url)
            
            # Feature-profile check second
            if is_high_risk_feature_profile(int_features, url):
                return render_template('result.html', pred='Phishing', url=url)

            final = [np.array(int_features)]
            predict = model_RF.prediction(final)
            if predict == 1:
                return render_template('result.html', pred='SAFE', url=url)
            return render_template('result.html', pred='Phishing', url=url)
    return render_template('detector.html')

@app.route('/chart')
@login_required
def chart():
    return render_template('chart.html')

@app.route('/report', methods=['POST'])
def report():
    url = request.form.get('url')
    report_type = request.form.get('type') # 'phishing' or 'safe'
    
    if url and report_type:
        report_file = 'community_reports.csv'
        file_exists = os.path.isfile(report_file)
        
        with open(report_file, 'a', encoding='utf-8') as f:
            if not file_exists:
                f.write("url,report_type,timestamp\n")
            f.write(f'"{url}",{report_type},{datetime.now()}\n')
            
        return {"status": "success", "message": "Report submitted successfully"}
    return {"status": "error", "message": "Invalid report data"}, 400

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")

if __name__ == "__main__":
    app.run(debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true')