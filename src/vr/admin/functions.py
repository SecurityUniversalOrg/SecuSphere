import jwt
from flask import jsonify
from time import time
from datetime import datetime, timedelta
import pyotp
from vr.functions.mysql_db import connect_to_db
from vr.admin.helper_functions import hash_password,verify_password
from vr import app, db


class User(object):
    def __init__(self, user_obj):
        self.id = user_obj[0]
        self.is_active = user_obj[1]
        self.is_admin = user_obj[2]
        self.is_security = user_obj[3]
        self.username = user_obj[4]
        self.password = user_obj[5]
        self.auth_type = user_obj[6]
        self.mfa_enabled = user_obj[7]
        self.otp_secret = user_obj[8]
        self.email = user_obj[9]
        self.email_confirmed_at = user_obj[10]
        self.first_name = user_obj[11]
        self.last_name = user_obj[12]
        self.jobtitle = user_obj[13]
        self.dept = user_obj[14]
        self.user_type = user_obj[15]
        self.avatar_path = user_obj[16]
        self.email_updates = user_obj[17]
        self.app_updates = user_obj[18]
        self.text_updates = user_obj[19]
        self.registration_date = user_obj[20]
        self.loc_zipcode = user_obj[21]
        self.loc_city = user_obj[22]
        self.loc_state = user_obj[23]
        self.about_me = user_obj[24]
        self.web_tz = user_obj[25]
        self.phone_no = user_obj[26]
        self.support_id = user_obj[27]
        self.support_key = user_obj[28]
        self.support_contact_id = user_obj[29]
        self.auth_token = user_obj[30]
        self.onboarding_confirmed = user_obj[31]

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

    def try_login(self, hashed_pw):
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
        return jwt.encode({'registration_token': self.id, 'exp': time() + expires_in}, app.config['SECRET_KEY'],
                          algorithm='HS256')

    def get_delegated_registration_token(self, new_user_id, expires_in=1800):
        return jwt.encode({'registration_token': new_user_id, 'exp': time() + expires_in}, app.config['SECRET_KEY'],
                          algorithm='HS256')

    def get_roles(self):
        cur, db = connect_to_db()
        role_list = []
        if app.config['RUNTIME_ENV'] == 'test':
            sql = 'SELECT ur.name FROM UserRoleAssignments AS ura JOIN UserRoles AS ur ON ura.role_id=ur.id WHERE ura.user_id=?'
        else:
            sql = 'SELECT ur.name FROM UserRoleAssignments AS ura JOIN UserRoles AS ur ON ura.role_id=ur.id WHERE ura.user_id=%s'
        args = (self.id,)
        cur.execute(sql, args)
        rows = cur.fetchall()
        role_dict = {
            'Admin': 'Admin',
            'User': 'User',
            'AI Admin': 'Artificial Intelligence',
            'AI User': 'Artificial Intelligence',
            'Asset Admin': 'Assets',
            'Asset User': 'Assets',
            'Cloud Admin': 'Cloud Security',
            'Cloud User': 'Cloud Security',
            'Compliance Admin': 'Compliance Management',
            'Compliance User': 'Compliance Management',
            'Config Admin': 'Configuration Management',
            'Config User': 'Configuration Management',
            'DLP Admin': 'Data Loss Prevention',
            'DLP User': 'Data Loss Prevention',
            'Database Admin': 'Database Security',
            'Database User': 'Database Security',
            'DevOps Admin': 'DevOps',
            'DevOps User': 'DevOps',
            'Email Admin': 'Email Security',
            'Email User': 'Email Security',
            'IR Admin': 'Incident Response',
            'IR User': 'Incident Response',
            'Intrusion Admin': 'IDS Management',
            'Intrusion User': 'IDS Management',
            'Malware Admin': 'Malware Management',
            'Malware User': 'Malware Management',
            'MonLog Admin': 'Monitoring and Logging',
            'MonLog User': 'Monitoring and Logging',
            'Network Admin': 'Network Security',
            'Network User': 'Network Security',
            'Operations Admin': 'Operations Management',
            'Operations User': 'Operations Management',
            'SecMetrics Admin': 'Security Metrics',
            'SecMetrics User': 'Security Metrics',
            'SecTesting Admin': 'Security Testing',
            'SecTesting User': 'Security Testing',
            'ThreatHunting Admin': 'Threat Hunting',
            'ThreatHunting User': 'Threat Hunting',
            'Training Admin': 'Training Manager',
            'Training User': 'Training Manager',
            'UserMan Admin': 'User Management',
            'UserMan User': 'User Management',
            'Vulnerability Admin': 'Vulnerability Management',
            'Vulnerability User': 'Vulnerability Management',
            'WebBrowser Admin': 'Web Browser Security',
            'WebBrowser User': 'Web Browser Security',
            'Wireless Admin': 'Wireless Security',
            'Wireless User': 'Wireless Security'
        }
        for row in rows:
            role_list.append(role_dict[row[0]])
        db.close()
        return role_list

    @staticmethod
    def verify_registration_token(token):
        try:
            exp = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['exp']
            if exp < time():
                return
            jwt_id = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['registration_token']
            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            db.session.query(User).filter(User.id == int(jwt_id)).update({User.email_confirmed_at: now},
                                                                     synchronize_session=False)
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
            jwt_id = jwt.decode(token, secret, algorithms=['HS256'])['pwreset_token']
        except RuntimeError:
            return
        if given_id == jwt_id:
            return User.query.get(jwt_id)
        else:
            return

    def get_username_token(self, expires_in=600):
        secret = str(self.username) + "-" + str(self.registration_date)
        return jwt.encode({'undisplay_token': self.id, 'exp': time() + expires_in}, secret, algorithm='HS256')

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


def _auth_user(session, component_category, role_requirements=None, permissions_entity=None):
    if 'username' not in session:
        return '', 401, '', '', ''
    u, authorized, user_roles_dict = _handle_user_auth(session, role_requirements, permissions_entity, component_category)
    user = User(u)
    if authorized != 'y':
        return user, 403, user_roles_dict
    else:
        return user, 200, user_roles_dict


def _handle_user_auth(session, role_requirements, permissions_entity, component_category):
    cur, db = connect_to_db()
    u, user_roles = _get_user(cur, session)
    user_roles_dict = {}
    authorized = _get_role_requirements(role_requirements, user_roles, permissions_entity, u, cur, user_roles_dict,
                                        component_category)
    db.close()
    return u, authorized, user_roles_dict


def _get_user(cur, session):
    if app.config['RUNTIME_ENV'] == 'test':
        cur.execute(f'SELECT * FROM User WHERE username=\'{session["username"]}\'')
    else:
        sql = 'SELECT * FROM User WHERE username=%s'
        args = (session['username'],)
        cur.execute(sql, args)
    u = cur.fetchone()
    user_roles = session['roles']
    return u, user_roles


def _check_if_auth(user_roles, role_requirements, authorized):
    if 'Admin' in user_roles or role_requirements in user_roles:
        authorized = 'y'
    else:
        for i in user_roles:
            for j in role_requirements:
                if i == j:
                    authorized = 'y'
                    break
    return authorized

def _get_role_requirements(role_requirements, user_roles, permissions_entity, u, cur, user_roles_dict,
                           component_category):
    authorized = 'n'
    if role_requirements:
        authorized = _check_if_auth(user_roles, role_requirements, authorized)
        if permissions_entity:
            if app.config['RUNTIME_ENV'] == 'test':
                sql = 'SELECT * FROM EntityPermissions WHERE UserID=? AND EntityType=?'
            else:
                sql = 'SELECT * FROM EntityPermissions WHERE UserID=%s AND EntityType=%s'
            args = (u[0], permissions_entity)
            cur.execute(sql, args)
            user_roles_dict['entities'] = cur.fetchall()
    else:
        if 'Admin' in user_roles or component_category in user_roles or component_category == 'No Role':
            authorized = 'y'
    return authorized


def _entity_permissions_filter(user_roles, session, admin_role, filter_key):
    if user_roles and 'Admin' not in session['roles'] and admin_role not in session['roles']:
        sql_filter = '1=0'
        for i in user_roles['entities']:
            if not sql_filter:
                sql_filter = f'{filter_key}={i[4]}'
            else:
                sql_filter += f' OR {filter_key}={i[4]}'
    else:
        sql_filter = '1=1'
    if sql_filter.startswith('1=0 OR '):
        sql_filter = sql_filter[7:]
    return sql_filter


def _entity_page_permissions_filter(entity_id, user_roles, session, admin_role):
    status = 403
    if user_roles and 'Admin' not in session['roles'] and admin_role not in session['roles'] and "Security" not in session['roles']:
        for i in user_roles['entities']:
            if str(i[4]) == str(entity_id):
                status = 200
                break
    elif 'Admin' in session['roles'] or admin_role in session['roles'] or "Security" in session['roles']:
        status = 200
    return status


def _add_page_permissions_filter(session, admin_role):
    status = 403
    if 'Admin' in session['roles'] or admin_role in session['roles']:
        status = 200
    return status


def check_lockout(user_id,lo_length):
    now = datetime.utcnow()
    # First check for an existing lockout
    lo_start = now - timedelta(minutes=lo_length)
    cur, db = connect_to_db()
    if app.config['RUNTIME_ENV'] == 'test':
        if isinstance(user_id, int):
            sql = "SELECT id FROM AuthLockouts WHERE (timestamp BETWEEN ? AND ?) AND user_id=?"
            args = (lo_start, now, int(user_id),)
        else:
            sql = "SELECT id FROM AuthLockouts WHERE (timestamp BETWEEN ? AND ?) AND username=?"
            args = (lo_start, now, user_id,)
    else:
        if isinstance(user_id, int):
            sql = 'SELECT id FROM AuthLockouts WHERE (timestamp BETWEEN %s AND %s) AND user_id=%s'
            args = (lo_start, now, int(user_id),)
        else:
            sql = 'SELECT id FROM AuthLockouts WHERE (timestamp BETWEEN %s AND %s) AND username=%s'
            args = (lo_start, now, user_id,)
    cur.execute(sql, args)
    rows = cur.fetchall()
    db.close()
    if rows:
        return True
    else:
        return False


def log_failed_attempt(failed_range,user_id,max_failed):
    now = datetime.utcnow()
    win_start = now - timedelta(minutes=failed_range)
    cur, db = connect_to_db()
    attempts = _check_total_failed_attempts(user_id, win_start, now, cur)
    if len(attempts) > max_failed-1:
        # Account is locked out
        _add_acct_lockout(user_id, now, cur, db)
    db.close()


def _check_total_failed_attempts(user_id, win_start, now, cur):
    if app.config['RUNTIME_ENV'] == 'test':
        if isinstance(user_id, int):
            sql = "SELECT id FROM AuthAttempts WHERE (timestamp BETWEEN ? AND ?) AND user_id=? AND success=?"
            args = (win_start, now, user_id, 0)
        else:
            sql = "SELECT id FROM AuthAttempts WHERE (timestamp BETWEEN ? AND ?) AND username=? AND success=?"
            args = (win_start, now, user_id, 0)
    else:
        if isinstance(user_id, int):
            sql = 'SELECT id FROM AuthAttempts WHERE (timestamp BETWEEN %s AND %s) AND user_id=%s AND success=%s'
            args = (win_start, now, user_id, 0)
        else:
            sql = 'SELECT id FROM AuthAttempts WHERE (timestamp BETWEEN %s AND %s) AND username=%s AND success=%s'
            args = (win_start, now, user_id, 0)
    cur.execute(sql, args)
    attempts = cur.fetchall()
    return attempts


def _add_acct_lockout(user_id, now, cur, db):
    if app.config['RUNTIME_ENV'] == 'test':
        if isinstance(user_id, int):
            sql = "INSERT INTO AuthLockouts (user_id, timestamp) VALUES (?, ?)"
            args = (user_id, now)
        else:
            sql = "INSERT INTO AuthLockouts (username, timestamp) VALUES (?, ?)"
            args = (user_id, now)
    else:
        if isinstance(user_id, int):
            sql = 'INSERT INTO AuthLockouts (user_id, timestamp) VALUES (%s, %s)'
            args = (user_id, now)
        else:
            sql = 'INSERT INTO AuthLockouts (username, timestamp) VALUES (%s, %s)'
            args = (user_id, now)
    cur.execute(sql, args)
    db.commit()


def check_menu_tour_init(user_id):
    cur, db = connect_to_db()
    if app.config['RUNTIME_ENV'] == 'test':
        sql = 'SELECT setting_value FROM SuSiteConfiguration WHERE setting_key=?'
    else:
        sql = 'SELECT setting_value FROM SuSiteConfiguration WHERE setting_key=%s'
    args = (f"menu_tour_init_{user_id}",)
    cur.execute(sql, args)
    row = cur.fetchone()
    status = 'nd'
    if row:
        if row[0] == '1':
            status = 'd'
    db.close()
    return status


def check_if_jira_enabled(app_id):
    cur, db = connect_to_db()
    if app.config['RUNTIME_ENV'] == 'test':
        sql = 'SELECT a.ID FROM AppIntegrations a INNER JOIN Integrations i ON a.IntegrationID=i.ID WHERE i.ToolType=? AND a.AppID=?'
    else:
        sql = 'SELECT a.ID FROM AppIntegrations a INNER JOIN Integrations i ON a.IntegrationID=i.ID WHERE i.ToolType=%s AND a.AppID=%s'
    args = ("JIRA", app_id)
    cur.execute(sql, args)
    rows = cur.fetchall()
    status = None
    if rows:
        status = rows
    db.close()
    return status


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

