import datetime

from config_engine import ENV, PROD_DB_URI, AUTH_TYPE, APP_EXT_URL, LDAP_HOST, LDAP_PORT, LDAP_BASE_DN, \
    LDAP_USER_DN, LDAP_GROUP_DN, LDAP_USER_RDN_ATTR, LDAP_USER_LOGIN_ATTR, LDAP_BIND_USER_DN, LDAP_BIND_USER_PASSWORD
from flask import Flask
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flaskext.markdown import Markdown
from vr.db_models.setup import _init_db
if AUTH_TYPE == 'ldap':
    from flask_ldap3_login import LDAP3LoginManager
import base64
import logging
import sys
from logging import StreamHandler
from apscheduler.schedulers.background import BackgroundScheduler
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import pandas as pd
import joblib
import os

app = Flask(__name__)
moment = Moment(app)
Markdown(app)
csrf = CSRFProtect(app)

app.config['APP_EXT_URL'] = APP_EXT_URL

app.config['RUNTIME_ENV'] = ENV
if app.config['RUNTIME_ENV'] == 'test':
    DB_URI = 'sqlite:///database.db'
    import sqlite3
else:
    DB_URI = PROD_DB_URI
    import mysql.connector

app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

if AUTH_TYPE == 'ldap':
    # LDAP Configuration
    app.config['LDAP_HOST'] = LDAP_HOST
    app.config['LDAP_PORT'] = LDAP_PORT
    app.config['LDAP_BASE_DN'] = LDAP_BASE_DN
    app.config['LDAP_USER_DN'] = LDAP_USER_DN
    app.config['LDAP_GROUP_DN'] = LDAP_GROUP_DN
    app.config['LDAP_USER_RDN_ATTR'] = LDAP_USER_RDN_ATTR
    app.config['LDAP_USER_LOGIN_ATTR'] = LDAP_USER_LOGIN_ATTR
    app.config['LDAP_BIND_USER_DN'] = LDAP_BIND_USER_DN
    app.config['LDAP_BIND_USER_PASSWORD'] = LDAP_BIND_USER_PASSWORD

    # Flask-LDAP3-Login Manager
    ldap_manager = LDAP3LoginManager(app)

with app.app_context():
    db = SQLAlchemy()
    db.init_app(app)
    _init_db(db=db, app=app)

app.config["REMEMBER_COOKIE_DURATION"] = datetime.timedelta(seconds=3600)

login_manager = LoginManager()

from vr.admin import admin
app.register_blueprint(admin)

from vr.assets import assets
app.register_blueprint(assets)

from vr.vulns import vulns
app.register_blueprint(vulns)

from vr.sourcecode import sourcecode
app.register_blueprint(sourcecode)

from vr.orchestration import orchestration
app.register_blueprint(orchestration)

from vr.threat_modeling import threat_modeling
app.register_blueprint(threat_modeling)

from vr.api import api
csrf.exempt(api)
app.register_blueprint(api)

bootstrap = Bootstrap(app)
login_manager.init_app(app)
login_manager.login_view = 'admin.login'

stdout_handler = StreamHandler(stream=sys.stdout)
stdout_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
stdout_handler.setFormatter(formatter)
app.logger.addHandler(stdout_handler)

@app.template_filter('format_datetime')
def format_datetime(value):
    if ENV == 'test':
        try:
            formatted = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f")
        except:
            formatted = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
    else:
        formatted = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
    return formatted

@app.template_filter('base64encode')
def base64encode(value):
    if value:
        return base64.b64encode(value.encode()).decode()
    else:
        return None


## Cronjob-like tasks section ##
def train_model_every_six_hours():
    scheduler = BackgroundScheduler()
    scheduler.add_job(train_model, 'interval', hours=6)
    scheduler.start()


if app.config['RUNTIME_ENV'] == 'test':
    def connect_to_db():
        cur_path = os.getcwd()
        if 'www' in cur_path and 'html' in cur_path:
            db_uri = '/var/www/html/src/instance/database.db'
        else:
            db_uri = 'instance/database.db'
        db = sqlite3.connect(db_uri)
        cur = db.cursor()
        return cur, db
else:
    def connect_to_db():
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        main_part = db_uri.split('://')[1]
        un = main_part.split(':', 1)[0]
        db_name = main_part.rsplit('/', 1)[1]
        host_and_port = main_part.rsplit('@', 1)[1].replace(f"/{db_name}", '')
        host = host_and_port.split(':')[0]
        port = int(host_and_port.split(':')[1])
        pw = main_part.split(':', 1)[1].replace(f"@{host}", '').replace(f"/{db_name}", '').replace(f":{port}", "")
        db = mysql.connector.connect(host=host, database=db_name, user=un, password=pw, port=port)
        cur = db.cursor()
        return cur, db


def train_model():
    try:
        vuln_all = []
        db = None
        try:
            cur, db = connect_to_db()
            if app.config['RUNTIME_ENV'] == 'test':
                sql = "SELECT Severity, Classification, Description, Status, Attack, Evidence, Source, VulnerabilityName FROM Vulnerabilities WHERE (Status = ? OR Status = ? OR Status = ? OR Status = ?)"

            else:
                sql = "SELECT Severity, Classification, Description, Status, Attack, Evidence, Source, VulnerabilityName FROM Vulnerabilities WHERE (Status = %s OR Status = %s OR Status = %s OR Status = %s)"
            args = ('Closed-Mitigated', 'Open-Reviewed', 'Open-RiskAccepted', 'Closed-FalsePositive',)
            cur.execute(sql, args)
            vuln_all = cur.fetchall()
        except:
            print(f'Warning: Unable to Connect to Vulnerability Data for ML Training!')
        finally:
            if db:
                db.close()
        # Convert vuln_all to a list of dictionaries
        true_positive_dispos = ['Closed-Mitigated', 'Open-Reviewed', 'Open-RiskAccepted']
        vuln_data = []
        for vuln in vuln_all:
            vuln_dict = {
                "severity": vuln[0],
                "type": vuln[1],
                "description": vuln[2],
                "true_positive": 1 if vuln[3] in true_positive_dispos else 0,
                "attack": vuln[4],
                "evidence": vuln[5],
                "source": vuln[6],
                "name": vuln[7]
            }
            vuln_data.append(vuln_dict)  # Directly append the dictionary

        if vuln_data:
            # Convert to DataFrame
            columns = ['severity', 'type', 'description', 'true_positive', 'attack', 'evidence', 'source', 'name']
            data = pd.DataFrame(vuln_data, columns=columns)

            # Label encoding for 'severity' and 'type'
            label_encoder_severity = LabelEncoder()
            label_encoder_type = LabelEncoder()

            # Manually fit the label encoders with all possible categories
            all_possible_severities = ['Informational', 'Low', 'Medium', 'High', 'Critical']
            all_possible_types = ['DAST', 'Container', 'SCA', 'SAST', 'IaC', 'Secret', 'DASTAPI']
            label_encoder_severity.fit(all_possible_severities)
            label_encoder_type.fit(all_possible_types)

            # Now transform the data with the fitted label encoders
            data['severity'] = label_encoder_severity.transform(data['severity'])
            data['type'] = label_encoder_type.transform(data['type'])

            # Feature engineering (e.g., extract length of description)
            data['description_length'] = data['description'].apply(len)
            data['attack_length'] = data['attack'].apply(len)
            data['evidence_length'] = data['evidence'].apply(len)
            data['source_length'] = data['source'].apply(len)
            data['name_length'] = data['name'].apply(len)

            # Features and labels
            X = data[
                ['severity', 'type', 'description_length', 'attack_length', 'evidence_length', 'source_length', 'name_length']]
            y = data['true_positive']

            # Split data into training and validation sets
            X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

            # Scale features
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_val_scaled = scaler.transform(X_val)

            # Training the model
            model = RandomForestClassifier()
            model.fit(X_train_scaled, y_train)

            # Validation
            predictions = model.predict(X_val_scaled)
            accuracy = accuracy_score(y_val, predictions)
            print(f'Vulnerability Managment ML Model Accuracy: {accuracy}')

            # Save the model and scalers
            joblib.dump(model, 'model.pkl')
            joblib.dump(scaler, 'scaler.pkl')
            joblib.dump(label_encoder_severity, 'label_encoder_severity.pkl')
            joblib.dump(label_encoder_type, 'label_encoder_type.pkl')
    except:
        print('Unable to train ML model')


# Call the Jobs Here #
train_model_every_six_hours()
