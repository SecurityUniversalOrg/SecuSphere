from flask_sqlalchemy import SQLAlchemy
from flask import Flask


def createNewTables(db_uri):
    mock_app = Flask(__name__)
    # Example database URI, replace it with your actual database URI
    mock_app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    mock_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy(mock_app)

    class AppConfig(db.Model):
        __tablename__ = 'AppConfig'
        __table_args__ = {'extend_existing': True}
        id = db.Column(db.Integer, primary_key=True)
        first_access = db.Column(db.Boolean, nullable=False, default=True)
        settings_initialized = db.Column(db.Boolean, nullable=False, default=False)
        APP_EXT_URL = db.Column(db.String(200))
        AUTH_TYPE = db.Column(db.String(200))
        AZAD_AUTHORITY = db.Column(db.String(200))
        AZAD_CLIENT_ID = db.Column(db.String(200))
        AZAD_CLIENT_SECRET = db.Column(db.String(200))
        AZURE_KEYVAULT_NAME = db.Column(db.String(200))
        ENV = db.Column(db.String(200))
        INSECURE_OAUTH = db.Column(db.String(200))
        JENKINS_HOST = db.Column(db.String(200))
        JENKINS_KEY = db.Column(db.String(200))
        JENKINS_PROJECT = db.Column(db.String(200))
        JENKINS_STAGING_PROJECT = db.Column(db.String(200))
        JENKINS_TOKEN = db.Column(db.String(200))
        JENKINS_USER = db.Column(db.String(200))
        LDAP_BASE_DN = db.Column(db.String(200))
        LDAP_BIND_USER_DN = db.Column(db.String(200))
        LDAP_BIND_USER_PASSWORD = db.Column(db.String(200))
        LDAP_GROUP_DN = db.Column(db.String(200))
        LDAP_HOST = db.Column(db.String(200))
        LDAP_PORT = db.Column(db.String(200))
        LDAP_USER_DN = db.Column(db.String(200))
        LDAP_USER_LOGIN_ATTR = db.Column(db.String(200))
        LDAP_USER_RDN_ATTR = db.Column(db.String(200))
        PROD_DB_URI = db.Column(db.String(200))
        SMTP_ADMIN_EMAIL = db.Column(db.String(200))
        SMTP_HOST = db.Column(db.String(200))
        SMTP_PASSWORD = db.Column(db.String(200))
        SMTP_USER = db.Column(db.String(200))
        SNOW_CLIENT_ID = db.Column(db.String(200))
        SNOW_CLIENT_SECRET = db.Column(db.String(200))
        SNOW_INSTANCE_NAME = db.Column(db.String(200))
        SNOW_PASSWORD = db.Column(db.String(200))
        SNOW_USERNAME = db.Column(db.String(200))
        VERSION = db.Column(db.String(200))
        JENKINS_ENABLED = db.Column(db.String(200))
        SNOW_ENABLED = db.Column(db.String(200))

    with mock_app.app_context():
        db.create_all()
