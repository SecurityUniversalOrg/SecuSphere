import datetime
import requests
from config_engine import ENV, PROD_DB_URI, AUTH_TYPE, APP_EXT_URL, LDAP_HOST, LDAP_PORT, LDAP_BASE_DN, \
    LDAP_USER_DN, LDAP_GROUP_DN, LDAP_USER_RDN_ATTR, LDAP_USER_LOGIN_ATTR, LDAP_BIND_USER_DN, LDAP_BIND_USER_PASSWORD, \
    AZAD_CLIENT_ID, AZAD_CLIENT_SECRET, AZAD_AUTHORITY, JENKINS_USER, JENKINS_ENABLED
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
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from requests.auth import HTTPBasicAuth
from vr.db_models.updates import createNewTables

if AUTH_TYPE == 'azuread':
    from flask_session import Session
    import msal
    from flask import session, url_for


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
elif AUTH_TYPE == 'azuread':
    app.config['CLIENT_ID'] = AZAD_CLIENT_ID
    app.config['CLIENT_SECRET'] = AZAD_CLIENT_SECRET
    app.config['AUTHORITY'] = AZAD_AUTHORITY
    app.config['REDIRECT_PATH'] = "/getAToken"
    app.config['ENDPOINT'] = 'https://graph.microsoft.com/v1.0/me/memberOf'
    app.config['SCOPE'] = ["User.ReadBasic.All", "Group.Read.All", "Application.Read.All"]
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)



    def _load_cache():
        cache = msal.SerializableTokenCache()
        if session.get("token_cache"):
            cache.deserialize(session["token_cache"])
        return cache


    def _save_cache(cache):
        if cache.has_state_changed:
            session["token_cache"] = cache.serialize()


    def _build_msal_app(cache=None, authority=None):
        return msal.ConfidentialClientApplication(
            app.config['CLIENT_ID'], authority=authority or app.config['AUTHORITY'],
            client_credential=app.config['CLIENT_SECRET'], token_cache=cache)


    def _build_auth_code_flow(authority=None, scopes=None):
        return _build_msal_app(authority=authority).initiate_auth_code_flow(
            scopes or [],
            redirect_uri=url_for("authorized", _external=True))


    def _get_token_from_cache(scope=None):
        cache = _load_cache()  # This web app maintains one cache per session
        cca = _build_msal_app(cache=cache)
        accounts = cca.get_accounts()
        if accounts:  # So all account(s) belong to the current signed-in user
            result = cca.acquire_token_silent(scope, account=accounts[0])
            _save_cache(cache)
            return result

    app.jinja_env.globals.update(_build_auth_code_flow=_build_auth_code_flow)

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

from vr.assessments import assessments
app.register_blueprint(assessments)

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
if AUTH_TYPE == 'local' or AUTH_TYPE == 'azuread':
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


## Release-based updates ##
createNewTables(app)

## Cronjob-like tasks section ##
def train_model_every_six_hours():
    scheduler = BackgroundScheduler()
    scheduler.add_job(train_model, 'interval', hours=6)
    scheduler.start()


def get_jenkins_data_every_hour():
    scheduler = BackgroundScheduler()
    scheduler.add_job(get_jenkins_data, 'interval', minutes=1)
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
                sub_key = "?"
            else:
                sub_key = "%s"
            sql = f"SELECT Severity, Classification, Description, Status, Attack, Evidence, Source, VulnerabilityName FROM Vulnerabilities WHERE (Status = {sub_key} OR Status = {sub_key} OR Status = {sub_key} OR Status = {sub_key})"
            args = ('Closed-Mitigated', 'Open-Reviewed', 'Open-RiskAccepted', 'Closed-Manual-False Positive',)
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

def decrypt_with_priv_key(encoded_encrypted_msg):
    with open('runtime/certs/cred_store_pri.pem') as outfile:
        priv_key_raw = outfile.read()
    priv_key = RSA.importKey(priv_key_raw)
    if len(encoded_encrypted_msg) > 100:
        decoded_decrypted_msg = rsa_long_decrypt(priv_key, encoded_encrypted_msg)
    else:
        decryptor = PKCS1_OAEP.new(priv_key)
        decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
        decoded_decrypted_msg = decryptor.decrypt(decoded_encrypted_msg)
    return decoded_decrypted_msg.decode('utf-8')


def rsa_long_decrypt(priv_obj, msg, length=256):
    """128 for 1024bit certificates and 256 bits for 2048bit certificates"""
    decryptor = PKCS1_OAEP.new(priv_obj)
    msg = base64.b64decode(msg)
    res = []
    for i in range(0, len(msg), length):
        res.append(decryptor.decrypt(msg[i:i + length]))
    decoded_decrypted_msg = b''.join(res)
    return decoded_decrypted_msg


def get_jenkins_data():
    user_check = JENKINS_USER
    if user_check != 'changeme':
        app.logger.info('Getting Jenkins Data')
        cur, db = connect_to_db()
        if app.config['RUNTIME_ENV'] == 'test':
            sub_key = "?"
        else:
            sub_key = "%s"
        sql = f"SELECT b.ID, b.ApplicationName, b.ApplicationAcronym, a.Type, a.AppEntity, i.Url, i.Username, i.Password, c.ID FROM BusinessApplications b JOIN AppIntegrations a ON b.ID=a.AppID JOIN Integrations i ON a.IntegrationID=i.ID JOIN CICDPipelines c ON i.ID=c.IntegrationID WHERE a.Type={sub_key}"
        args = ('Jenkins',)
        cur.execute(sql, args)
        apps_all = cur.fetchall()

        # Make a request to the Jenkins API
        unique_jenkins_url = []
        for a in apps_all:
            instance_dict = {
                'url': a[5],
                'username': decrypt_with_priv_key(a[6]),
                'token': decrypt_with_priv_key(a[7])
            }
            if instance_dict not in unique_jenkins_url:
                unique_jenkins_url.append(instance_dict)

        jenkins_instance_data = {}
        for i in unique_jenkins_url:
            response = requests.get(f"{i['url']}/api/json?tree=jobs[name,_class]", auth=(i['username'], i['token']))
            # Parse the response
            jobs = json.loads(response.text)['jobs']
            jenkins_instance_data[i['url']] = {'jobs': jobs}

        for a in apps_all:
            cicd_pipeline_id = a[8]
            jenkins_url = a[5]
            project_name = a[4].lstrip().rstrip()
            username = decrypt_with_priv_key(a[6])
            token = decrypt_with_priv_key(a[7])
            # r = requests.get(f'{jenkins_url}/job/{project_name}/job/release%2F0.1.0-beta%2FTest-1/api/json', auth=HTTPBasicAuth(username, token))
            for job in jenkins_instance_data[jenkins_url]['jobs']:
                run = False
                pipeline_type = 'Unknown'
                if project_name == job['name']:
                    run = True
                    if job['_class'].endswith('WorkflowJob'):
                        pipeline_type = 'pipeline'
                    elif job['_class'].endswith('WorkflowMultiBranchProject'):
                        pipeline_type = 'multibranch'
                if run:
                    if pipeline_type == 'multibranch':
                        builds = []
                        # Make a request to the Jenkins API for the specific multibranch pipeline
                        url = f"{jenkins_url}/job/{project_name}/api/json?tree=jobs[name]"
                        response = requests.get(url, auth=(username, token))

                        # Check if the request was successful
                        if response.status_code == 200:
                            # Parse the response and get the branches
                            branches = json.loads(response.text)['jobs']
                            for branch in branches:
                                r = requests.get(f'{jenkins_url}/job/{project_name}/job/{branch["name"]}/api/json', auth=(username, token))
                                if r.status_code == 200:
                                    data = r.json()
                                    for build in data['builds']:
                                        if pipeline_type == 'pipeline':
                                            branch_name = None
                                            build_req = requests.get(
                                                f'{jenkins_url}/job/{project_name}/{build["number"]}/wfapi/describe',
                                                auth=HTTPBasicAuth(username, token))
                                        else:
                                            branch_name = data['name']
                                            build_req = requests.get(
                                                f'{jenkins_url}/job/{project_name}/job/{branch_name}/{build["number"]}/wfapi/describe',
                                                auth=HTTPBasicAuth(username, token))
                                        if build_req.status_code == 200:
                                            build_data = build_req.json()
                                            build_data['stage_data'] = []
                                            for i in build_data['stages']:
                                                build_data['stage_data'].append(i)
                                            build_data['branch_name'] = branch_name
                                            builds.append(build_data)

                        for b in builds:
                            now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                            second_timestamp = b['startTimeMillis'] / 1000.0
                            start_time = datetime.datetime.utcfromtimestamp(second_timestamp).strftime("%Y-%m-%d %H:%M:%S")

                            # Check if the build data already exists
                            check_sql = f"SELECT COUNT(*) FROM CICDPipelineBuilds WHERE PipelineID={sub_key} AND BuildName={sub_key} AND StartTime={sub_key} AND BranchName={sub_key}"
                            check_args = (cicd_pipeline_id, b['name'], start_time, b['branch_name'])
                            cur.execute(check_sql, check_args)
                            result = cur.fetchone()
                            if result[0] == 0:  # If build data does not exist, proceed with insertion
                                sql = f"INSERT INTO CICDPipelineBuilds (PipelineID, AddDate, BuildName, BranchName, Status, StartTime, DurationMillis) VALUES ({sub_key}, {sub_key}, {sub_key}, {sub_key}, {sub_key}, {sub_key}, {sub_key})"
                                args = (
                                cicd_pipeline_id, now, b['name'], b['branch_name'], b['status'], start_time, b['durationMillis'])
                                cur.execute(sql, args)
                                db.commit()
                                build_id = cur.lastrowid
                                for s in b['stage_data']:
                                    stage_timestamp = b['startTimeMillis'] / 1000.0
                                    stage_start_time = datetime.datetime.utcfromtimestamp(stage_timestamp).strftime(
                                        "%Y-%m-%d %H:%M:%S")
                                    sql = f"INSERT INTO CICDPipelineStageData (BuildID, AddDate, StageName, BuildNode, Status, StartTime, DurationMillis) VALUES ({sub_key}, {sub_key}, {sub_key}, {sub_key}, {sub_key}, {sub_key}, {sub_key})"
                                    args = (build_id, now, s['name'], s['execNode'], s['status'], stage_start_time,
                                            s['durationMillis'])
                                    cur.execute(sql, args)
                                    db.commit()
                    else:
                        print('Placeholder for pipeline type handler')

        db.close()


# Call the Jobs Here #
train_model_every_six_hours()
if JENKINS_ENABLED == 'yes':
    get_jenkins_data_every_hour()
