from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_moment import Moment
import datetime
from vr.db_models.setup import _init_db
from config_engine import ENV, PROD_DB_URI, AUTH_TYPE, APP_EXT_URL, LDAP_HOST, LDAP_PORT, LDAP_BASE_DN, \
    LDAP_USER_DN, LDAP_GROUP_DN, LDAP_USER_RDN_ATTR, LDAP_USER_LOGIN_ATTR, LDAP_BIND_USER_DN, LDAP_BIND_USER_PASSWORD
from flaskext.markdown import Markdown
from flask_wtf.csrf import CSRFProtect
if AUTH_TYPE == 'ldap':
    from flask_ldap3_login import LDAP3LoginManager
import base64


app = Flask(__name__)
moment = Moment(app)
Markdown(app)
csrf = CSRFProtect(app)

app.config['APP_EXT_URL'] = APP_EXT_URL

app.config['RUNTIME_ENV'] = ENV
if app.config['RUNTIME_ENV'] == 'test':
    DB_URI = 'sqlite:///database.db'
else:
    DB_URI = PROD_DB_URI

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

