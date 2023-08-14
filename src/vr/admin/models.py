from flask_wtf import Form
from wtforms import StringField, PasswordField
from flask_login import UserMixin
from vr import db, app
from vr.functions.mysql_db import connect_to_db
from datetime import datetime, timedelta
import jwt
from vr.admin.helper_functions import hash_password,verify_password
from vr.admin.functions import db_connection_handler
import pyotp
from time import time
from vr import login_manager
from marshmallow import Schema, fields
from marshmallow import post_load
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from config_engine import AUTH_TYPE
if AUTH_TYPE == 'ldap':
    from vr import ldap_manager

if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


USER_ID = 'User.id'


class RegisterForm(Form):
    firstname = StringField('First Name')
    lastname = StringField('Last Name')
    email = StringField('Email')
    password = PasswordField('Password')

class LoginForm(Form):
    pass


class EditProfileForm(Form):
    company = StringField('Company')
    username = StringField('Username')
    email = StringField('Email')
    firstname = StringField('First Name')
    lastname = StringField('Last Name')
    jobtitle = StringField('Job Title')
    department = StringField('Department')


class User(UserMixin, db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'User'
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

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def get_username(self):
        return self.username

    def try_login(self,username,hashed_pw):
        if verify_password(self.password, hashed_pw):
            return True
        else:
            return False

    def get_totp_uri(self):
        return 'otpauth://totp/Security-Universal:{0}?secret={1}&issuer=Security-Universal' \
               .format(self.username, self.otp_secret)

    def authenticate(self, mfa_password, otp):
        p = 0
        try:
            p = int(mfa_password)
        except RuntimeError:
            return False
        t = pyotp.TOTP(otp)
        t.now()
        return t.verify(p)

    def get_registration_token(self, expires_in=1800):
        return jwt.encode({'registration_token': self.id, 'exp': time() + expires_in}, app.config['SECRET_KEY'], algorithm='HS256')

    def get_delegated_registration_token(self, new_user_id, expires_in=1800):
        return jwt.encode({'registration_token': new_user_id, 'exp': time() + expires_in}, app.config['SECRET_KEY'], algorithm='HS256')

    def get_roles(self):
        cur, db = connect_to_db()
        role_list = []
        if app.config['RUNTIME_ENV'] == 'test':
            cur.execute(f'SELECT ur.name FROM UserRoleAssignments AS ura JOIN UserRoles AS ur ON ura.role_id=ur.id WHERE ura.user_id={self.id}')
        else:
            sql = 'SELECT ur.name FROM UserRoleAssignments AS ura JOIN UserRoles AS ur ON ura.role_id=ur.id WHERE ura.user_id=%s'
            args = (self.id,)
            cur.execute(sql, args)
        rows = cur.fetchall()

        for row in rows:
            role_list.append(row[0])
        db.close()
        return role_list

    @staticmethod
    def verify_registration_token(token):
        try:
            exp = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['exp']
            if exp < time():
                return
            jwt_id = jwt.decode(token, app.config['SECRET_KEY'],  algorithms=['HS256'])['registration_token']
            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            db.session.query(User).filter(User.id == int(jwt_id)).update({User.email_confirmed_at: now}, synchronize_session=False)
            db_connection_handler(db)
            return 'valid'
        except RuntimeError:
            return


    def get_pwreset_token(self, expires_in=600):
        secret = str(self.password) + "-" + str(self.registration_date)
        return jwt.encode({'pwreset_token': self.id, 'exp': time() + expires_in}, secret, algorithm='HS256')

    def verify_pwreset_token(self, token, given_id):
        secret = str(self.password) + "-" + str(self.registration_date)
        try:
            jwt_id = jwt.decode(token, secret,
                            algorithms=['HS256'])['pwreset_token']
        except RuntimeError:
            return
        if given_id == id:
            return User.query.get(jwt_id)
        else:
            return

    def get_username_token(self, expires_in=600):
        secret = str(self.username) + "-" + str(self.registration_date)
        jwt_payload = {'undisplay_token': self.id, 'exp': time() + expires_in}
        return jwt.encode(jwt_payload, secret, algorithm='HS256')

    def verify_username_token(self, token, given_id):
        secret = str(self.username) + "-" + str(self.registration_date)
        try:
            jwt_id = jwt.decode(token, secret, algorithms=['HS256'])['undisplay_token']
        except RuntimeError:
            return
        if given_id == jwt_id:
            return User.query.get(jwt_id)
        else:
            return

if AUTH_TYPE == 'local' or AUTH_TYPE == 'azuread':
    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))
elif AUTH_TYPE == 'ldap':
    # User Loader for LDAP
    @login_manager.user_loader
    def load_user(user_id):
        return ldap_manager.get_user(user_id)


    # Create a User class that inherits from UserMixin for flask-login
    class LdapUser(UserMixin):
        def __init__(self, dn, ldap_dict):
            self.dn = dn
            self.ldap_dict = ldap_dict
            self.id = ldap_dict['uid'][0].decode('utf-8')

        def __str__(self):
            return self.id


    # Save the LDAP user data
    @ldap_manager.save_user
    def save_user(dn, ldap_dict, memberships):
        return LdapUser(dn, ldap_dict)

class UsersSchema(Schema):
    id = fields.Int()
    is_active = fields.Boolean()
    username = fields.Str()
    password = fields.Str()
    auth_type = fields.Str()
    mfa_enabled = fields.Boolean()
    otp_secret = fields.Str()
    email = fields.Str()
    email_confirmed_at = fields.DateTime()
    first_name = fields.Str()
    last_name = fields.Str()
    jobtitle = fields.Str()
    dept = fields.Str()
    user_type = fields.Str()
    avatar_path = fields.Str()
    email_updates = fields.Str()
    app_updates = fields.Str()
    text_updates = fields.Str()
    registration_date = fields.DateTime()
    loc_zipcode = fields.Str()
    loc_city = fields.Str()
    loc_state = fields.Str()
    about_me = fields.Str()
    web_tz = fields.Str()
    phone_no = fields.Str()
    support_id = fields.Str()
    support_key = fields.Str()
    support_contact_id = fields.Int()
    auth_token = fields.Str()
    onboarding_confirmed = fields.Str()
    avatar_data = fields.Str()


class UserAPIKeys(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'UserAPIKeys'
    ID = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'), nullable=False)
    Name = db.Column(db.String(200))
    Otp = db.Column(db.String(200))
    ApiKey = db.Column(db.String(500))
    RegDate = db.Column(db.DateTime, index=True, nullable=False, default=datetime.utcnow)


class UserStatus(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'UserStatus'
    id = db.Column(db.Integer(), primary_key=True)
    status = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'), nullable=False)
    update_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)

# Define the Role data-model
class UserRoles(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'UserRoles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)
    description = db.Column(db.String(200))


# Define the UserRoles association table
class UserRoleAssignments(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'UserRoleAssignments'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey(USER_ID, ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('UserRoles.id', ondelete='CASCADE'))


class AuthAttempts(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AuthAttempts'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
    username = db.Column(db.String(100))
    success = db.Column(db.Boolean(), nullable=False)

class AuthLockouts(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AuthLockouts'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
    username = db.Column(db.String(100))

# New Format
class EntityPermissions(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'EntityPermissions'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    UserID = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
    EntityType = db.Column(db.String(100))
    EntityID = db.Column(db.String(100))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<EntityPermissions(name={self.AddDate!r})>'.format(self=self)


class EntityPermissionsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    UserID = fields.Int()
    EntityType = fields.Str()
    EntityID = fields.Str()


class MakeEntityPermissionsSchema(EntityPermissionsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return EntityPermissions(**data)


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'oauth2_client'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'oauth2_code'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'oauth2_token'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
    user = db.relationship('User')

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time()


class Credentials(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'Credentials'
    ID = db.Column(db.Integer, primary_key=True)
    Title = db.Column(db.String(100))
    UserName = db.Column(db.String(100))
    Password = db.Column(LONGTEXT)
    Url = db.Column(db.String(100))
    Notes = db.Column(db.String(200))
    Category = db.Column(db.String(100))
    registration_date = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    PlatformAccountID = db.Column(db.String(100))
    MgmtPolicy = db.Column(db.String(100))
    Password2 = db.Column(LONGTEXT)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<Credentials(name={self.Title!r})>'.format(self=self)


class CredentialsSchema(Schema):
    ID = fields.Int()
    Title = fields.Str()
    UserName = fields.Str()
    Password = fields.Str()
    Url = fields.Str()
    Notes = fields.Str()
    Category = fields.Str()
    registration_date = fields.Date()
    PlatformAccountID = fields.Str()
    MgmtPolicy = fields.Str()
    Password2 = fields.Str()


class MakeCredentialsSchema(CredentialsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return Credentials(**data)


class AppConfig(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AppConfig'
    id = db.Column(db.Integer, primary_key=True)
    first_access = db.Column(db.Boolean, nullable=False, default=True)


class SuSiteConfiguration(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'SuSiteConfiguration'
    id = db.Column(db.Integer, primary_key=True)
    setting_name = db.Column(db.String(100))
    setting_key = db.Column(db.String(100))
    setting_value = db.Column(db.String(100))
    update_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)


class Messages(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'Messages'
    ID = db.Column(db.Integer, primary_key=True)
    SenderUserId = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'))
    ReceiverUserId = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'))
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    MessageType = db.Column(db.String(100))
    EntityType = db.Column(db.String(100))
    EntityID = db.Column(db.Integer)
    Message = db.Column(LONGTEXT)

    def __init__(self, SenderUserId=None, ReceiverUserId=None, AddDate=None, MessageType=None,
                 EntityType=None, EntityID=None, Message=None, ID=None):
        if ID:
            self.ID = ID
        if SenderUserId:
            self.SenderUserId = SenderUserId
        if ReceiverUserId:
            self.ReceiverUserId = ReceiverUserId
        if AddDate:
            self.AddDate = AddDate
        if MessageType:
            self.MessageType = MessageType
        if EntityType:
            self.EntityType = EntityType
        if EntityID:
            self.EntityID = EntityID
        if Message:
            self.Message = Message

    def __repr__(self):
        return '<Messages(name={self.SenderUserId!r})>'.format(self=self)

class MessagesSchema(Schema):
    ID = fields.Int()
    SenderUserId = fields.Int()
    ReceiverUserId = fields.Int()
    AddDate = fields.Date()
    MessageType = fields.Str()
    Message = fields.Str()
    username = fields.Str()
    ApplicationId = fields.Int()
    EntityType = fields.Str()
    EntityID = fields.Int()

class MakeMessagesSchema(MessagesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return Messages(**data)


class MessagesStatus(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'MessagesStatus'
    ID = db.Column(db.Integer, primary_key=True)
    MessageId = db.Column(db.Integer, db.ForeignKey('Messages.ID', ondelete='CASCADE'))
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    Status = db.Column(db.String(100))
    UserId = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'))

    def __init__(self, MessageId=None, AddDate=None, Status=None, UserId=None, ID=None):
        if ID:
            self.ID = ID
        if MessageId:
            self.MessageId = MessageId
        if AddDate:
            self.AddDate = AddDate
        if Status:
            self.Status = Status
        if UserId:
            self.UserId = UserId

    def __repr__(self):
        return '<MessagesStatus(name={self.MessageId!r})>'.format(self=self)

class MessagesStatusSchema(Schema):
    ID = fields.Int()
    MessageId = fields.Int()
    AddDate = fields.Date()
    Status = fields.Str()
    UserId = fields.Int()

class MakeMessagesStatusSchema(MessagesStatusSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return MessagesStatus(**data)


