from vr.vulns import vulns
from flask import render_template, session, redirect, url_for
from flask_login import login_required
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}


@vulns.route("/dashboard")
@login_required
def vulnerability_dashboard():
    try:
        NAV['curpage'] = {"name": "Vulnerability Dashboard"}
        NAV['subcat'] = ""
        NAV['subsubcat'] = ""
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'])
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        return render_template('vulnerability_dashboard.html', user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500

