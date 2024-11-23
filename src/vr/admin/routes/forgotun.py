from flask import render_template, request, json
# Start of Entity-specific Imports
from vr import app
from vr.admin import admin
from vr.admin.models import User, LoginForm
from vr.admin.email_alerts import send_email, generate_evnt_msg
from vr.functions.timefunctions import return_datetime_now


NAV_CAT= { "name": "Admin", "url": "admin.admin_dashboard"}

@admin.route('/forgotun', methods=['GET', 'POST'])
def forgotun():
    try:
        form = LoginForm(request.form)
        if request.method == 'POST' and form.validate():
            # read config file
            config = None
            email = request.form.get('email')
            user = User.query.filter(User.email.ilike(email)).first()
            if user:
                token = user.get_username_token()
                msg_subject = 'Security Universal Alert - Username Recovery Confirmation'
                now = return_datetime_now()
                evt_list = []
                action = f'If this is a legitimate attempt to recover your username, click <a href="http://{app.config["APP_EXT_URL"]}/displayun/{user.get_id()}/{token}">here</a> to recover it'
                action_list = [action]
                st = 'n'
                msg_body = generate_evnt_msg(msg_subject,now,evt_list,action_list,st)
                msg_fromaddr = app.config['SMTP_ADMIN_EMAIL']
                try:
                    send_email(msg_fromaddr, email, msg_subject, msg_body)
                    warnmsg = ('pwresetemail', 'success')
                except:
                    warnmsg = ('pwresetemail', 'fail')
                return render_template('admin/login.html', form=form, config=config, warnmsg=warnmsg)
            else:
                warnmsg = ('pwresetemail', 'success')
                return render_template('admin/login.html', form=form, config=config, warnmsg=warnmsg)
        return render_template('admin/forgotun.html')
    except RuntimeError:
        return render_template('500.html'), 500


@admin.route('/displayun/<id>/<token>', methods=['GET', 'POST'])
def displayun(id,token):
    try:
        user = User.query.filter_by(id=id).first()

        valid = user.verify_username_token(token,int(id))
        if not valid:
            return 'Invalid Registration Token'
        else:
            form = LoginForm(request.form)
            username = user.get_username()
            return render_template('admin/displayun.html', form=form, username=username, id=id, token=token)
    except RuntimeError:
        return render_template('500.html'), 500



