from flask import render_template, request, json, session
# Start of Entity-specific Imports
from vr import db, app
from vr.admin import admin
from vr.admin.models import User, LoginForm
from vr.admin.email_alerts import send_email, generate_evnt_msg
from vr.functions.timefunctions import return_datetime_now
from vr.admin.helper_functions import hash_password
from config_engine import SMTP_ADMIN_EMAIL


NAV_CAT= { "name": "Admin", "url": "admin.admin_dashboard"}
LOGIN_TEMPLATE = "admin/login.html"


@admin.route('/forgotpw', methods=['GET', 'POST'])
def forgotpw():
    try:
        form = LoginForm(request.form)
        if request.method == 'POST' and form.validate():
            # read config file
            config = None
            email = request.form.get('email')
            user = User.query.filter(User.email.ilike(email)).first()
            if user:
                token = user.get_pwreset_token()
                msg_subject = 'Security Universal Alert - Password Reset Confirmation'
                now = return_datetime_now()
                evt_list = []
                action = f'If this is a legitimate attempt to reset your password, click <a href="http://{app.config["APP_EXT_URL"]}/resetpw/{user.get_id()}/{token}">here</a> to reset it'
                action_list = [action]
                st = 'n'
                msg_body = generate_evnt_msg(msg_subject, now, evt_list, action_list, st)
                msg_fromaddr = SMTP_ADMIN_EMAIL
                try:
                    send_email(msg_fromaddr, email, msg_subject, msg_body)
                    warnmsg = ('pwresetemail', 'success')
                except:
                    warnmsg = ('pwresetemail', 'fail')
                return render_template(LOGIN_TEMPLATE, form=form, config=config, warnmsg=warnmsg)
            else:
                warnmsg = ('pwresetemail', 'success')
                return render_template(LOGIN_TEMPLATE, form=form, config=config, warnmsg=warnmsg)
        return render_template('admin/forgotpw.html')
    except RuntimeError:
        return render_template('500.html'), 500


@admin.route('/resetpw/<id>/<token>', methods=['GET', 'POST'])
def resetpw(id, token):
    try:
        user = User.query.filter_by(id=id).first()

        valid = user.verify_pwreset_token(token, int(id))
        if not valid:
            return 'Invalid Registration Token'
        else:
            form = LoginForm(request.form)
            session['username'] = user.get_username()
            if request.method == 'POST' and form.validate():
                password = request.form.get('psw')
                user = User.query.filter_by(username=session['username']).first()
                valid = user.verify_pwreset_token(token, int(id))
                if not valid:
                    return 'Invalid Registration Token'

                user.password = hash_password(password)
                db.session.add(user)
                db.session.commit()
                del session['username']
                # read config file
                with open('su/config.json', 'r') as file:
                    config = json.load(file)
                warnmsg = ('pwresetconf', 'success')
                return render_template(LOGIN_TEMPLATE, form=form, config=config, warnmsg=warnmsg)
            return render_template('admin/resetpw.html', form=form, id=id, token=token)
    except RuntimeError:
        return render_template('500.html'), 500


