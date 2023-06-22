from datetime import datetime
from sqlalchemy.types import TEXT, DECIMAL
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
        extend_existing = True
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
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(50), unique=True)
        description = db.Column(db.String(200))

    UserRoles()

    # Define the UserRoles association table
    class UserRoleAssignments(db.Model):
        __tablename__ = 'UserRoleAssignments'
        id = db.Column(db.Integer(), primary_key=True)
        user_id = db.Column(db.Integer(), db.ForeignKey(USER_ID, ondelete='CASCADE'))
        role_id = db.Column(db.Integer(), db.ForeignKey('UserRoles.id', ondelete='CASCADE'))

    UserRoleAssignments()





    class EntityPermissions(db.Model):
        __tablename__ = 'EntityPermissions'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        UserID = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        EntityType = db.Column(db.String(100))
        EntityID = db.Column(db.String(100))

    EntityPermissions()



    class AppConfig(db.Model):
        __tablename__ = 'AppConfig'
        id = db.Column(db.Integer, primary_key=True)
        first_access = db.Column(db.Boolean, nullable=False, default=True)

    AppConfig()



    db.create_all()
    db.session.commit()
