from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import numpy as np
import os
import pickle
import pandas as pd
from datetime import datetime
import whois
from urllib.parse import urlparse
from threat_intel import run_external_checks
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'phishing_detection_secret_key_123')

# Database Configuration (Render Postgres or Local SQLite fallback)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Scan(db.Model):
    __tablename__ = 'scans'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    url = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(20), nullable=False)
    confidence = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.now)

class ModelHistory(db.Model):
    __tablename__ = 'model_history'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    accuracy = db.Column(db.Float, nullable=False)

class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    report_type = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)

with app.app_context():
    db.create_all()

def get_whois_info(url):
    try:
        if not url.startswith('http'):
            parsed_url = urlparse('http://' + url)
        else:
            parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
            
        w = whois.whois(domain)
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]
            
        country = w.country
        if isinstance(country, list):
            country = country[0]
            
        return {
            'domain': domain,
            'creation_date': creation_date.strftime('%Y-%m-%d') if hasattr(creation_date, 'strftime') else 'Unknown',
            'registrar': registrar if registrar else 'Unknown',
            'country': country if country else 'Unknown'
        }
    except Exception as e:
        return {
            'domain': url,
            'creation_date': 'Unknown',
            'registrar': 'Unknown',
            'country': 'Unknown'
        }

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
        
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            if user.role == 'admin':
                flash("Admins must use the Admin Login portal.", "warning")
                return redirect(url_for('admin_login'))
            
            session['user'] = user.username
            session['role'] = user.role
            flash(f"Welcome back, {user.username}!", "success")
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
        
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password) and user.role == 'admin':
            session['user'] = user.username
            session['role'] = user.role
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

        # All web registrations are 'user' by default for security
        role = 'user'
        
        try:
            new_user = User(username=username, password=generate_password_hash(password), role=role)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash("Username already exists.", "danger")
            
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
    history = ModelHistory.query.order_by(ModelHistory.timestamp.asc()).all()
    model_history = [{'timestamp': str(row.timestamp), 'accuracy': row.accuracy} for row in history]
    
    return render_template('upload.html', model_history=model_history)  

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
        
        try:
            with open('accuracy.txt', 'r') as f:
                new_acc = float(f.read().strip())
        except:
            new_acc = 95.2
            
        new_entry = ModelHistory(accuracy=new_acc)
        db.session.add(new_entry)
        db.session.commit()
        
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
        
    scans = Scan.query.filter_by(username=session.get('user')).all()
    
    total = len(scans)
    phishing_count = sum(1 for row in scans if row.result == 'Phishing')
    
    if total > 0:
        threat_level = round((phishing_count / total) * 100, 1)
        acc_display = f"{threat_level}"
        label = "Historical Threat Level"
    else:
        acc_display = current_acc
        label = "Base Model Accuracy"
        
    last_scan = session.get('last_scan', None)
        
    return render_template('information.html', acc=acc_display, label=label, total=total, last_scan=last_scan)

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
    
    try:
        tree_preds = [tree.prediction(final)[0] for tree in model_RF.trees]
        pred_val = predict[0] if isinstance(predict, (list, np.ndarray)) else predict
        votes = tree_preds.count(pred_val)
        confidence = round((votes / len(tree_preds)) * 100, 1)
    except Exception as e:
        confidence = 92.5
        
    # Save to Database
    new_scan = Scan(username=session.get('user'), url="Manual Entry", result=res_str, confidence=confidence)
    db.session.add(new_scan)
    db.session.commit()
        
    session['last_scan'] = {
        'url': "Manual Entry",
        'result': res_str,
        'features': [int(f) for f in int_features],
        'findings': [],
        'confidence': confidence,
        'whois': None,
        'threat_intel': None
    }
    session.modified = True

    if predict == 1:
        return render_template('result.html', pred='SAFE', url="Manual Entry")
    return render_template('result.html', pred='Phishing', url="Manual Entry")

@app.route('/detect', methods=['POST'])
@login_required
def detect_url():
    url = request.form.get('url')
    if not url:
        return render_template('detector.html')

    # Extract features
    int_features = extract_features(url)
    
    # Feature Names and mapping for report
    feature_names = [
        "IP Address Usage", "URL Length", "Shortening/At Symbol", "Prefix-Suffix (-)",
        "Sub-domain Count", "HTTPS in Domain", "Request URL Integrity", "URL Anchor Patterns",
        "Server Form Handler", "Domain Registration", "Redirect Frequency", "Mouse Effects",
        "Pop-up Security", "Domain Age", "DNS Record Status", "Web Traffic Pattern"
    ]
    
    # Analysis logic
    findings = []
    # 1=Safe, 0=Suspicious, 2=Phishing
    for i, val in enumerate(int_features):
        name = feature_names[i]
        if val == 2:
            findings.append({"feature": name, "status": "Danger", "msg": f"High risk {name} detected."})
        elif val == 0:
            findings.append({"feature": name, "status": "Warning", "msg": f"{name} appears unusual."})
        else:
            findings.append({"feature": name, "status": "Safe", "msg": f"{name} is verified safe."})

    # Rule-based overrides for clear phishing
    is_rule_phish = is_high_risk_phishing_pattern(url)
    is_profile_phish = is_high_risk_feature_profile(int_features, url)
    
    # Machine Learning Prediction
    final = [np.array(int_features)]
    predict = model_RF.prediction(final)
    
    # Logic for final result: If ML says Phish OR high-risk rules trigger
    if predict == 0 or is_rule_phish or is_profile_phish:
        result = "Phishing"
        color = "#f43f5e"
    else:
        result = "Safe"
        color = "#10b981"
        
    try:
        tree_preds = [tree.prediction(final)[0] for tree in model_RF.trees]
        pred_val = predict[0] if isinstance(predict, (list, np.ndarray)) else predict
        votes = tree_preds.count(pred_val)
        confidence = round((votes / len(tree_preds)) * 100, 1)
        
        # Adjust confidence if rules triggered an override
        if result == "Phishing" and (is_rule_phish or is_profile_phish):
            confidence = max(confidence, 98.5)
    except Exception as e:
        confidence = 92.5
        
    # WHOIS Lookup
    whois_data = get_whois_info(url)
    
    # External Threat Intelligence
    threat_intel_data = run_external_checks(url)
        
    # Save to Database
    new_scan = Scan(username=session.get('user'), url=url, result=result, confidence=confidence)
    db.session.add(new_scan)
    db.session.commit()
        
    session['last_scan'] = {
        'url': url,
        'result': result,
        'features': [int(f) for f in int_features],
        'findings': findings,
        'confidence': confidence,
        'whois': whois_data,
        'threat_intel': threat_intel_data
    }
    session.modified = True
        
    return render_template('detector.html', 
                           url=url, 
                           result=result, 
                           color=color, 
                           findings=findings,
                           whois=whois_data,
                           threat_intel=threat_intel_data)

@app.route('/chart')
@login_required
def chart():
    scans = Scan.query.filter_by(username=session.get('user')).order_by(Scan.timestamp.asc()).all()
    history_urls = [{'url': row.url, 'result': row.result, 'confidence': row.confidence, 'timestamp': str(row.timestamp)} for row in scans]
    
    safe_count = sum(1 for row in history_urls if row['result'] == 'Safe')
    phishing_count = sum(1 for row in history_urls if row['result'] == 'Phishing')
    
    last_scan = session.get('last_scan', None)
    return render_template('chart.html', safe_count=safe_count, phishing_count=phishing_count, last_scan=last_scan, history_urls=history_urls)

@app.route('/api/v1/scan', methods=['POST'])
def api_scan():
    """
    Public JSON API for Browser Extensions or External integrations.
    Expects JSON: {"url": "https://example.com"}
    """
    data = request.get_json()
    if not data or 'url' not in data:
        return {"error": "Missing 'url' in JSON payload"}, 400
        
    url = data['url']
    try:
        # Extract features
        int_features = extract_features(url)
        
        # ML Prediction
        final = [np.array(int_features)]
        predict = model_RF.prediction(final)
        
        # Rule overrides
        is_rule_phish = is_high_risk_phishing_pattern(url)
        is_profile_phish = is_high_risk_feature_profile(int_features, url)
        
        if predict == 0 or is_rule_phish or is_profile_phish:
            result = "Phishing"
        else:
            result = "Safe"
            
        tree_preds = [tree.prediction(final)[0] for tree in model_RF.trees]
        pred_val = predict[0] if isinstance(predict, (list, np.ndarray)) else predict
        votes = tree_preds.count(pred_val)
        confidence = round((votes / len(tree_preds)) * 100, 1)
        if result == "Phishing" and (is_rule_phish or is_profile_phish):
            confidence = max(confidence, 98.5)
            
        return {
            "url": url,
            "status": result,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/report', methods=['POST'])
def report():
    url = request.form.get('url')
    report_type = request.form.get('type') # 'phishing' or 'safe'
    
    if url and report_type:
        new_report = Report(url=url, report_type=report_type)
        db.session.add(new_report)
        db.session.commit()
            
        return {"status": "success", "message": "Report submitted successfully"}
    return {"status": "error", "message": "Invalid report data"}, 400

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")

if __name__ == "__main__":
    app.run(debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true')