from vr.sourcecode import sourcecode
from flask import request, render_template, session, redirect, url_for, jsonify
from flask_login import login_required
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}

@sourcecode.route("/dashboard")
@login_required
def dashboard():
    try:
        NAV['curpage'] = {"name": "Dashboard"}
        NAV['subcat'] = ""
        NAV['subsubcat'] = ""
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'])
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        return 'Placeholder'
    except RuntimeError:
        return render_template('500.html'), 500