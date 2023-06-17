from flask_login import login_required
from flask import session, redirect, url_for, render_template
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
# Start of Entity-specific Imports
from vr.admin import admin


NAV_CAT= { "name": "Admin", "url": "admin.admin_dashboard"}

@admin.route('/unauth_403', methods=['GET'])
@login_required
def unauth_403():
    user, status, new_msg_cnt, messages, user_roles = _auth_user(session, NAV_CAT['name'])
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, nav_cat={}, nav_subcat='', \
                               nav_subsubcat='', nav_curpage={"name": "Unauthorized"})
    return render_template('403.html', user=user)



