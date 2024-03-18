from datetime import datetime
from sqlalchemy.types import TEXT, DECIMAL
from flask import jsonify
from config_engine import ENV
if ENV == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import mysql
from flask_login import UserMixin
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
import time


Integer = mysql.INTEGER
USER_ID = "User.id"
TECH_ID = "Technologies.TechnologyID"
BUSINESS_APP_ID = "BusinessApplications.ID"
VULN_ID = "Vulnerabilities.VulnerabilityID"
IP_ASSETS_ID = "IPAssets.ID"
BENCHMARKS_ID = "AssessmentBenchmarks.ID"
THREAT_ASSESSMENT_ID = "TmThreatAssessments.ID"


def _init_db(db=None, app=None):
    if not db:
        db = SQLAlchemy(app)


    class User(UserMixin, db.Model):
        __tablename__ = 'User'
        __table_args__ = {'extend_existing': True}
        id = db.Column(db.Integer, primary_key=True)
        is_active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')
        is_admin = db.Column('is_admin', db.Boolean(), nullable=False, server_default='0')
        is_security = db.Column('is_security', db.Boolean(), nullable=False, server_default='0')
        username = db.Column(db.String(100))
        password = db.Column(db.String(255))
        auth_type = db.Column(db.String(20))
        mfa_enabled = db.Column(db.Boolean(), nullable=False, server_default='0')
        otp_secret = db.Column(db.String(16))
        email = db.Column(db.String(255), nullable=False, unique=True)
        email_confirmed_at = db.Column(db.DateTime())
        first_name = db.Column(db.String(100), nullable=False, server_default='')
        last_name = db.Column(db.String(100), nullable=False, server_default='')
        jobtitle = db.Column(db.String(100))
        dept = db.Column(db.String(100))
        user_type = db.Column(db.String(100))
        avatar_path = db.Column(db.String(100))
        email_updates = db.Column(db.String(1))
        app_updates = db.Column(db.String(1))
        text_updates = db.Column(db.String(1))
        registration_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)
        loc_zipcode = db.Column(db.String(20))
        loc_city = db.Column(db.String(100))
        loc_state = db.Column(db.String(50))
        about_me = db.Column(db.String(2000))
        web_tz = db.Column(db.String(100))
        phone_no = db.Column(db.String(40))
        support_id = db.Column(db.String(50))
        support_key = db.Column(db.String(50))
        support_contact_id = db.Column(db.Integer)
        auth_token = db.Column(db.String(300))
        onboarding_confirmed = db.Column(db.String(1))

        def __repr__(self):
            return '<User {}>'.format(self.username)

    User()



    # Define the Role data-model
    class UserRoles(db.Model):
        __tablename__ = 'UserRoles'
        __table_args__ = {'extend_existing': True}
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(50), unique=True)
        description = db.Column(db.String(200))

    UserRoles()

    # Define the UserRoles association table
    class UserRoleAssignments(db.Model):
        __tablename__ = 'UserRoleAssignments'
        __table_args__ = {'extend_existing': True}
        id = db.Column(db.Integer(), primary_key=True)
        user_id = db.Column(db.Integer(), db.ForeignKey(USER_ID, ondelete='CASCADE'))
        role_id = db.Column(db.Integer(), db.ForeignKey('UserRoles.id', ondelete='CASCADE'))

    UserRoleAssignments()





    class EntityPermissions(db.Model):
        __tablename__ = 'EntityPermissions'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        UserID = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        EntityType = db.Column(db.String(100))
        EntityID = db.Column(db.String(100))

    EntityPermissions()



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

    AppConfig()


    class SourceCodeFile(db.Model):
        __tablename__ = 'SourceCodeFile'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime)
        GitRepoId = db.Column(db.Integer)
        FileName = db.Column(db.String(300))
        FileLocation = db.Column(db.String(300))
        FileType = db.Column(db.String(300))


    SourceCodeFile()

    class TmControls(db.Model):
        __table_args__ = {'extend_existing': True}
        __tablename__ = 'TmControls'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        Control = db.Column(LONGTEXT)
        Type = db.Column(db.String(8))
        Description = db.Column(LONGTEXT)
        Lambda = db.Column(db.String(1))
        Process = db.Column(db.String(1))
        Server = db.Column(db.String(1))
        Dataflow = db.Column(db.String(1))
        Datastore = db.Column(db.String(1))
        ExternalEntity = db.Column(db.String(1))

    TmControls()

    db.create_all()

    db_connection_handler(db)


def db_connection_handler(db_obj):
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            return db_obj.session.commit()
        except Exception as e:
            if attempt < max_attempts - 1:  # i.e. if it's not the final attempt
                continue  # go to the next iteration of the loop
            else:  # if it's the final attempt
                return jsonify(error=str(e)), 500