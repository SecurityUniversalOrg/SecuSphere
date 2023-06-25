import re
from flask_login import current_user, login_user
from flask import session, redirect, url_for, render_template, request, json, flash
# Start of Entity-specific Imports
from vr import db, app
from vr.admin import admin
from vr.admin.models import User, LoginForm, AuthAttempts, AppConfig
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, check_lockout, log_failed_attempt
from vr.admin.functions import db_connection_handler
from config_engine import AUTH_TYPE
if AUTH_TYPE == 'ldap':
    from flask_ldap3_login.forms import LDAPLoginForm


NAV_CAT= { "name": "Admin", "url": "admin.admin_dashboard"}
AUTH_FAILED_PW_LOCKOUT = 15
AUTH_FAILED_PW_ATT = 5
AUTH_FAILED_PW_WINDOW = 10
LOGIN_TEMPLATE = "admin/login.html"
LDAP_LOGIN_TEMPLATE = "admin/ldap_login.html"

@admin.route('/', methods=['GET'])
def home():
    return redirect(url_for('admin.login'))

@admin.route('/login', methods=['GET', 'POST'])
def login():
    app_config = AppConfig.query.first()
    if app_config is None:
        return redirect(url_for('admin.register'))
    if current_user.is_authenticated:
        flash('You are already logged in.', 'danger')
        return redirect(url_for('vulns.all_applications'))
    if AUTH_TYPE == 'local':
        warnmsg = ''
        form = LoginForm(request.form)
        if not form.validate():
            warnmsg = 'Please validate your entries.'
            return render_template(LOGIN_TEMPLATE, form=form, warnmsg=warnmsg)

        if request.method == 'POST':
            username = request.form.get('login[username]')
            password = request.form.get('login[password]')

            un_type = check_input(username)  # determine if email or username was provided

            resp = _get_initial_login_details(username, form, un_type)
            if not isinstance(resp, tuple):
                return resp
            else:
                userid = resp[0]
                user = resp[1]
                mfa_password = resp[2]
            # attempt to log the user in
            return _login_attempt(user, username, password, userid, form, mfa_password)
    elif AUTH_TYPE == 'ldap':
        form = LDAPLoginForm()
        if form.validate_on_submit():
            # Log the user in
            login_user(form.user)
            # Redirect to the desired page
            return redirect(request.args.get('next') or url_for('index'))
        else:
            # Print the form errors
            print("Form validation failed with errors:", form.errors)
        return render_template(LDAP_LOGIN_TEMPLATE, form=form, errors=form.errors)

    if form.errors:
        warnmsg = (form.errors, 'danger')
    return render_template(LOGIN_TEMPLATE, form=form, warnmsg=warnmsg)


def check_input(user_input):
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    if re.fullmatch(email_regex, user_input):
        return "Email"
    else:
        return "Username"


def _get_initial_login_details(username, form, un_type):
    if un_type == 'Username':
        user = User.query.filter(User.username.ilike(username)).first()
    else:
        user = User.query.filter(User.email.ilike(username)).first()
    if user is None:
        warnmsg = _handle_no_user(username)
        return render_template(LOGIN_TEMPLATE, form=form, warnmsg=warnmsg)

    if user.mfa_enabled:
        mfa_password = request.form.get('login[password2]')
    else:
        mfa_password = None
    userid = user.get_id()
    lo_ans = check_lockout(int(userid), AUTH_FAILED_PW_LOCKOUT)
    if lo_ans:
        warnmsg = _handle_lo_answer
        return render_template(LOGIN_TEMPLATE, form=form, warnmsg=warnmsg)
    return tuple([userid, user, mfa_password])


def _login_attempt(user, username, password, userid, form, mfa_password):
    auth_success = user.try_login(username, password)

    if auth_success == False:
        warnmsg = _handle_failed_login(userid, auth_success)
        return render_template(LOGIN_TEMPLATE, form=form, warnmsg=warnmsg)

    if user.mfa_enabled:
        otp_secret = user.otp_secret
        if not user.authenticate(mfa_password, otp_secret):
            warnmsg = _handle_failed_mfa_login(userid)
            return render_template(LOGIN_TEMPLATE, form=form, warnmsg=warnmsg)
    _handle_successful_login(userid, auth_success, user)
    try:
        if request.referrer and 'login?next=' in request.referrer:
            next_pg = request.referrer.replace(request.root_url, '').split('login?next=%2F')[1]
            if next_pg is not None:
                return redirect(next_pg)
    except RuntimeError:
        pass
    flash('You have successfully logged in.', 'success')

    return redirect(url_for('vulns.all_applications'))


def _handle_successful_login(userid, auth_success, user):
    loginattempt = AuthAttempts(user_id=userid, success=auth_success)
    db.session.add(loginattempt)
    db_connection_handler(db)
    login_user(user, remember=False, force=True)
    session.permanent = True
    session.modified = True
    session['username'] = user.username
    session['roles'] = user.get_roles()


def _handle_failed_mfa_login(userid):
    warnmsg = ('failedlogin', 'danger')
    loginattempt = AuthAttempts(user_id=userid, success=False)
    db.session.add(loginattempt)
    db_connection_handler(db)
    log_failed_attempt(AUTH_FAILED_PW_WINDOW, int(userid), AUTH_FAILED_PW_ATT)
    return warnmsg


def _handle_failed_login(userid, auth_success):
    warnmsg = ('failedlogin', 'danger')
    loginattempt = AuthAttempts(user_id=userid, success=auth_success)
    db.session.add(loginattempt)
    db_connection_handler(db)
    log_failed_attempt(AUTH_FAILED_PW_WINDOW, int(userid), AUTH_FAILED_PW_ATT)
    return warnmsg


def _handle_no_user(username):
    lo_ans = check_lockout(username, AUTH_FAILED_PW_LOCKOUT)
    loginattempt = AuthAttempts(success=False, username=username)
    db.session.add(loginattempt)
    db_connection_handler(db)
    if lo_ans:
        warnmsg = ('lockedout', 'danger')
    else:
        log_failed_attempt(AUTH_FAILED_PW_WINDOW, username, AUTH_FAILED_PW_ATT)
        warnmsg = ('failedlogin', 'danger')
    return warnmsg

def _handle_lo_answer(userid):
    warnmsg = ('lockedout', 'danger')
    loginattempt = AuthAttempts(success=False, username=userid)
    db.session.add(loginattempt)
    db_connection_handler(db)
    return warnmsg


@admin.route('/check_if_mfa', methods=['POST'])
def check_if_mfa():
    try:
        user_to_check = request.form.get('username')
        un_type = check_input(user_to_check)
        if un_type == 'Username':
            user = User.query.filter(User.username.ilike(user_to_check)).first()
        else:
            user = User.query.filter(User.email.ilike(user_to_check)).first()
        rsp_json = {"answer": ""}
        if user:
            if user.mfa_enabled:
                rsp_json['answer'] = 'active'
            else:
                rsp_json['answer'] = 'inactive'
        else:
            rsp_json['answer'] = 'active'
        response = app.response_class(
            response=json.dumps(rsp_json),
            status=200,
            mimetype='application/json'
        )
        return response
    except RuntimeError:
        return render_template('500.html'), 500

