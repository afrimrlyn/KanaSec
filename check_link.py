from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from functools import wraps
from datetime import datetime, timedelta
import json

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reports.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
db = SQLAlchemy(app)

API_KEY = '01e5fea1bef3cff3c0bd616ee3ee58656d491ab5a0a430983a5fbed2f7c391d9'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    report_url = db.Column(db.String(500), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())

class DangerousLinkHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    analysis = db.Column(db.Text, nullable=False)
    date_checked = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)  # Tambahkan kolom date_checked

class SafeLinkHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    analysis = db.Column(db.Text, nullable=False)
    date_checked = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)


# Create database tables
with app.app_context():
    db.create_all()

def is_url_safe(url):
    endpoint = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {
        'apikey': API_KEY,
        'resource': url
    }

    response = requests.get(endpoint, params=params)
    if response.status_code == 200:
        result = response.json()
        analysis = []
        for engine, details in result['scans'].items():
            analysis.append({
                'engine': engine,
                'detected': details['detected'],
                'result': details.get('result', 'Clean')
            })
        if result['positives'] > 0:
            return 'Warning', analysis  # URL is not safe
        else:
            return 'Safe', analysis  # URL is safe
    else:
        raise Exception(f"Error checking URL: {response.status_code}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('sign_in'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/check_link', methods=['GET', 'POST'])
def check_link():
    result = None
    analysis = None

    if request.method == 'POST':
        url = request.form['url']
        try:
            result, analysis = is_url_safe(url)
        except Exception as e:
            result = str(e)

    return render_template('indexnoin.html', result=result, analysis=analysis)

@app.route('/', methods=['GET', 'POST'])
def indexnoin():
    result = None
    analysis = None
    report_submitted = False

    # Retrieve dangerous link history, limit to 5 latest entries
    dangerous_links = DangerousLinkHistory.query \
                        .order_by(DangerousLinkHistory.date_checked.desc()) \
                        .limit(5) \
                        .all()
    
    # Retrieve safe link history, limit to 5 latest entries
    safe_links = SafeLinkHistory.query \
                    .order_by(SafeLinkHistory.date_checked.desc()) \
                    .limit(5) \
                    .all()

    if request.method == 'POST':
        if 'url' in request.form:
            url = request.form['url']
            try:
                result, analysis = is_url_safe(url)
                if result == 'Warning':
                    # Save dangerous link to history
                    new_dangerous_link = DangerousLinkHistory(url=url, analysis=json.dumps(analysis))
                    db.session.add(new_dangerous_link)

                    # Update: Clean up history to keep only the latest 5 entries
                    all_dangerous_links = DangerousLinkHistory.query \
                                                            .order_by(DangerousLinkHistory.date_checked.desc()) \
                                                            .all()
                    if len(all_dangerous_links) > 5:
                        links_to_delete = all_dangerous_links[5:]
                        for link in links_to_delete:
                            db.session.delete(link)

                elif result == 'Safe':
                    # Save safe link to history
                    new_safe_link = SafeLinkHistory(url=url, analysis=json.dumps(analysis))
                    db.session.add(new_safe_link)

                    # Update: Clean up history to keep only the latest 5 entries
                    all_safe_links = SafeLinkHistory.query \
                                                    .order_by(SafeLinkHistory.date_checked.desc()) \
                                                    .all()
                    if len(all_safe_links) > 5:
                        links_to_delete = all_safe_links[5:]
                        for link in links_to_delete:
                            db.session.delete(link)

                db.session.commit()

            except Exception as e:
                result = str(e)
        elif 'name' in request.form:
            # Save report to database
            name = request.form['name']
            email = request.form['email']
            report_url = request.form['report_url']
            reason = request.form['reason']
            
            new_report = Report(name=name, email=email, report_url=report_url, reason=reason)
            db.session.add(new_report)
            db.session.commit()

            report_submitted = True

    return render_template('indexnoin.html', result=result, analysis=analysis, report_submitted=report_submitted, dangerous_links=dangerous_links, safe_links=safe_links)

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    result = None
    analysis = None
    report_submitted = False

    # Retrieve dangerous link history, limit to 5 latest entries
    dangerous_links = DangerousLinkHistory.query \
                        .order_by(DangerousLinkHistory.date_checked.desc()) \
                        .limit(5) \
                        .all()
    
    # Retrieve safe link history, limit to 5 latest entries
    safe_links = SafeLinkHistory.query \
                    .order_by(SafeLinkHistory.date_checked.desc()) \
                    .limit(5) \
                    .all()

    if request.method == 'POST':
        if 'url' in request.form:
            url = request.form['url']
            try:
                result, analysis = is_url_safe(url)
                if result == 'Warning':
                    # Save dangerous link to history
                    new_dangerous_link = DangerousLinkHistory(url=url, analysis=json.dumps(analysis))
                    db.session.add(new_dangerous_link)

                    # Update: Clean up history to keep only the latest 5 entries
                    all_dangerous_links = DangerousLinkHistory.query \
                                                            .order_by(DangerousLinkHistory.date_checked.desc()) \
                                                            .all()
                    if len(all_dangerous_links) > 5:
                        links_to_delete = all_dangerous_links[5:]
                        for link in links_to_delete:
                            db.session.delete(link)

                elif result == 'Safe':
                    # Save safe link to history
                    new_safe_link = SafeLinkHistory(url=url, analysis=json.dumps(analysis))
                    db.session.add(new_safe_link)

                    # Update: Clean up history to keep only the latest 5 entries
                    all_safe_links = SafeLinkHistory.query \
                                                    .order_by(SafeLinkHistory.date_checked.desc()) \
                                                    .all()
                    if len(all_safe_links) > 5:
                        links_to_delete = all_safe_links[5:]
                        for link in links_to_delete:
                            db.session.delete(link)

                db.session.commit()

            except Exception as e:
                result = str(e)
        elif 'name' in request.form:
            # Save report to database
            name = request.form['name']
            email = request.form['email']
            report_url = request.form['report_url']
            reason = request.form['reason']
            
            new_report = Report(name=name, email=email, report_url=report_url, reason=reason)
            db.session.add(new_report)
            db.session.commit()

            report_submitted = True

    return render_template('index.html', result=result, analysis=analysis, report_submitted=report_submitted, dangerous_links=dangerous_links, safe_links=safe_links)

@app.route('/reports')
@login_required
def view_reports():
    reports = Report.query.order_by(Report.date_created.desc()).all()
    return render_template('reports.html', reports=reports)

@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Sign in successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('sign_in.html')

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check for existing username
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('sign_up'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Sign up successful, please sign in', 'success')
        return redirect(url_for('sign_in'))

    return render_template('sign_up.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('sign_in'))

if __name__ == '__main__':
    app.run(debug=True)