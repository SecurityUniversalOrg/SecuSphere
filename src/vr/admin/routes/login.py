import datetime
import re
from flask_login import current_user, login_user
from flask import session, redirect, url_for, render_template, request, json, flash
# Start of Entity-specific Imports
from vr import db, app
from vr.admin import admin
from vr.admin.models import User, LoginForm, AuthAttempts, AppConfig
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, check_lockout, log_failed_attempt
from vr.admin.functions import db_connection_handler
if app.config['AUTH_TYPE'] == 'ldap':
    from flask_ldap3_login.forms import LDAPLoginForm
elif app.config['AUTH_TYPE'] == 'azuread':
    import requests
    import msal
    from vr import _build_auth_code_flow, _load_cache, _save_cache, _build_msal_app, _get_token_from_cache


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
    ad_auth_url = None
    warnmsg = ''
    if app.config['AUTH_TYPE'] == 'local':
        if current_user.is_authenticated:
            flash('You are already logged in.', 'danger')
            return redirect(url_for('assets.all_applications'))

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
    elif app.config['AUTH_TYPE'] == 'ldap':
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
    elif app.config['AUTH_TYPE'] == 'azuread':
        form = LoginForm(request.form)
        session["flow"] = _build_auth_code_flow(scopes=app.config['SCOPE'])
        ad_auth_url = session["flow"]["auth_uri"]
    if form.errors:
        warnmsg = (form.errors, 'danger')
    return render_template(LOGIN_TEMPLATE, form=form, warnmsg=warnmsg, auth_type=app.config['AUTH_TYPE'], auth_url=ad_auth_url)

if app.config['AUTH_TYPE'] == 'azuread':
    @app.route(app.config['REDIRECT_PATH'])  # Its absolute URL must match your app's redirect_uri set in AAD
    def authorized():
        try:
            cache = _load_cache()
            result = _build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
                session.get("flow", {}), request.args)
            if "error" in result:
                return render_template("admin/azuread_auth_error.html", result=result)
            session["username"] = result.get("id_token_claims")["preferred_username"]
            session["id_token_claims"] = result.get("id_token_claims")
            _save_cache(cache)
            token = _get_token_from_cache(app.config['SCOPE'])
            graph_data = requests.get(  # Use token to call downstream service
                app.config['ENDPOINT'],
                headers={'Authorization': 'Bearer ' + token['access_token']},
            ).json()
            session["roles"] = map_ad_groups_to_roles(graph_data)
            username = session["username"]
            user = User.query.filter(User.email.ilike(username)).first()
            if not user:
                user_details = session["id_token_claims"]
                user = User(
                    is_admin=True if "Admin" in session["roles"] else False,
                    is_security=True if "Security" in session["roles"] else False,
                    username=username,
                    auth_type='Azure-AD',
                    email=username,
                    email_confirmed_at=datetime.datetime.utcnow(),
                    first_name=user_details['name'].split()[0],
                    last_name=user_details['name'].split()[1],
                    user_type='system',
                    avatar_path='/static/images/default_profile_avatar.jpg',
                    email_updates="y",
                    app_updates="y",
                    text_updates="n"
                )
                db.session.add(user)
                db.session.commit()
            elif not user.is_admin and "Admin" in session["roles"]:
                user.is_admin = True
                db.session.add(user)
                db.session.commit()
            elif not user.is_security and "Security" in session["roles"]:
                user.is_security = True
                db.session.add(user)
                db.session.commit()
            # Log the user in
            login_user(user)
        except ValueError:  # Usually caused by CSRF
            pass  # Simply ignore them
        return redirect(url_for("assets.all_applications"))


def map_ad_groups_to_roles(graph_data):
    user_roles = []
    for group in graph_data['value']:
        if group['@odata.type'] == '#microsoft.graph.group':
            if group['displayName'] == 'SecuSphere Super Administrators':
                user_roles.append('Admin')
            elif group['displayName'].startswith('ART-'):
                user_roles.append(group['displayName'])
            # Add other mappings as needed
    return user_roles


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
                next_pg = next_pg.replace('%2F', '/')
                return redirect(next_pg)
    except RuntimeError:
        pass
    flash('You have successfully logged in.', 'success')

    return redirect(url_for('assets.all_applications'))


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

