from flask import Flask, render_template, request, redirect, url_for
import numpy as np
import os
import pickle
import pandas as pd
from datetime import datetime

app = Flask(__name__)

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

@app.route('/')
@app.route('/first')
def first():
    return render_template('first.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/upload')
def upload():
    return render_template('upload.html')  

@app.route('/preview',methods=["POST"])
def preview():
    if request.method == 'POST':
        dataset = request.files['datasetfile']
        df = pd.read_csv(dataset,encoding = 'unicode_escape')
        df.set_index('Id', inplace=True)
        return render_template("preview.html",df_view = df) 

@app.route("/home")
@app.route("/dashboard")
def home():
    return render_template('index.html')

@app.route("/detect")
def detect():
    return render_template('detector.html')

from random_forest_test import acc
@app.route("/information")
def information():
    return render_template('information.html', acc=acc)

from url_extractor import (
    extract_features,
    is_high_risk_phishing_pattern,
    is_high_risk_feature_profile,
)

@app.route("/result", methods=['POST','GET'])
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