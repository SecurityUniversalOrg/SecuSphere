from flask_login import logout_user, login_required
from flask import session, redirect, url_for
from vr.admin import admin

NAV_CAT= { "name": "Admin", "url": "admin.admin_dashboard"}

@admin.route('/logout')
@login_required
def logout():
    logout_user()
    del session['username']
    return redirect(url_for('admin.login'))
