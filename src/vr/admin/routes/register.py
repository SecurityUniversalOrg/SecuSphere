import os
import base64
from io import BytesIO
import pyqrcode

from flask_login import current_user
from flask import session, redirect, url_for, render_template, request, flash
# Start of Entity-specific Imports
from vr import db, app
from vr.admin import admin
from vr.admin.models import User, RegisterForm, UserStatus, UserRoles, UserRoleAssignments, AppConfig
from vr.admin.functions import db_connection_handler
from vr.admin.helper_functions import hash_password
from vr.admin.email_alerts import send_registration_email
from vr.functions.initial_setup import setup_core_db_tables, generate_key_pair
from vr.db_models.setup_2 import _init_db


NAV_CAT= { "name": "Admin", "url": "admin.admin_dashboard"}
SERV_ERR = "500.html"


@admin.route('/register', methods=['GET'])
def register():
    app_config = AppConfig.query.first()
    if app_config is None:
        try:
            if current_user.is_authenticated:
                flash('You are already logged in.', 'danger')
                return redirect(url_for('admin.profile'))
            form = RegisterForm(request.form)
            return render_template('admin/register.html', form=form)
        except RuntimeError:
            return render_template(SERV_ERR)
    else:
        return redirect(url_for('assets.all_applications'))


@admin.route('/register_user/<token>', methods=['GET'])
def register_user(token):
    if current_user.is_authenticated:
        flash('You are already logged in.', 'danger')
        return redirect(url_for('assets.all_applications'))
    form = RegisterForm(request.form)
    user = User.query.filter_by(auth_token=token).first()
    if user:
        return render_template('admin/register_user.html', form=form, user=user)
    else:
        return redirect(url_for('admin.login'))


@admin.route('/register_user_submit', methods=['POST'])
def register_user_submit():
    try:
        if current_user.is_authenticated:
            flash('You are already logged in.', 'danger')
            return redirect(url_for('assets.all_applications'))
        form = RegisterForm(request.form)

        password = request.form.get('psw')
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            hashed_pw = hash_password(password)
            db.session.query(User).filter(User.email == email).update({User.password: hashed_pw, User.is_active: True}, synchronize_session=False)
            db_connection_handler(db)

            app_view_role = UserRoles.query.filter_by(name='Application Viewer').first()
            ura = UserRoleAssignments(user_id=user.id, role_id=app_view_role.id)
            db.session.add(ura)
            db_connection_handler(db)

            session['username'] = user.username
            return redirect(url_for('assets.all_applications'))
        else:
            warnmsg = ('regfail', 'danger')
            return render_template('admin/login.html', form=form, warnmsg=warnmsg)
        warnmsg = ('regconf', 'success')
        return render_template('admin/login.html', form=form, warnmsg=warnmsg)
    except RuntimeError:
        return render_template(SERV_ERR)


@admin.route('/register_submit', methods=['POST'])
def register_submit():
    try:
        if current_user.is_authenticated:
            flash('You are already logged in.', 'danger')
            return redirect(url_for('assets.all_applications'))
        form = RegisterForm(request.form)

        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        password = request.form.get('psw')
        # read config file

        user = User.query.filter_by(email=email).first()
        if not user:
            otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
            username = firstname.lower() + "." + lastname.lower()
            hashed_pw = hash_password(password)
            user = User(email=email)
            db.session.add(user)
            db_connection_handler(db)
            db.session.query(User).filter(User.email == email).update({User.username: username,
                User.password: hashed_pw, User.otp_secret: otp_secret, User.email: email, User.first_name: firstname,
                User.last_name: lastname, User.auth_type: 'local', User.user_type: 'system',
                User.email_updates: 'y', User.app_updates: 'y', User.text_updates: 'n',
                User.avatar_path: '/static/images/default_profile_avatar.jpg', User.is_admin: 1
            }, synchronize_session=False)
            db_connection_handler(db)

            _init_db(db=db)

            generate_key_pair()
            setup_core_db_tables(app.config['ENV'])
            admin_role = UserRoles.query.filter_by(name='Admin').first()
            ura = UserRoleAssignments(user_id=user.id, role_id=admin_role.id)
            db.session.add(ura)
            db_connection_handler(db)

            send_registration_email(app.config['APP_EXT_URL'], username, firstname, lastname, '', email)

            session['username'] = username
        else:
            warnmsg = ('regfail', 'danger')
            return render_template('admin/login.html', form=form, warnmsg=warnmsg)

        # if config['mfa'] == 'Enabled':
        # if 1 == 1:
        #     return render_template('admin/two-factor-setup.html'), 200, {
        #         'Cache-Control': 'no-cache, no-store, must-revalidate',
        #         'Pragma': 'no-cache',
        #         'Expires': '0'}
        app_config = AppConfig()
        db.session.add(app_config)
        db_connection_handler(db)

        warnmsg = ('regconf', 'success')
        return render_template('admin/login.html', form=form, warnmsg=warnmsg)
    except RuntimeError:
        return render_template(SERV_ERR)


@admin.route('/qrcode')
def qrcode():
    try:
        if 'username' not in session:
            return redirect(url_for('admin.register'))
        user = User.query.filter_by(username=session['username']).first()
        url = pyqrcode.create(user.get_totp_uri())
        stream = BytesIO()
        url.svg(stream, scale=5)
        return stream.getvalue(), 200, {
            'Content-Type': 'image/svg+xml',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}
    except RuntimeError:
        return render_template(SERV_ERR)


