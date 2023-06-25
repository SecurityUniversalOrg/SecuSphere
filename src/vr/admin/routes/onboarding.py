from flask import session, redirect, url_for, render_template
from flask_login import login_required
# Start of Entity-specific Imports
from vr import db
from vr.admin import admin
from vr.admin.models import User, SuSiteConfiguration
from vr.admin.functions import _auth_user, check_menu_tour_init
from vr.admin.functions import db_connection_handler


NAV = {
    'CAT': { "name": "Onboarding", "url": "admin.admin_dashboard"}
}

@admin.route('/onboarding', methods=['GET', 'POST'])
@login_required
def onboarding():
    NAV['curpage'] = {"name": "Onboarding Tasks"}
    user, status, user_roles = _auth_user(session, 'No Role')
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, nav_cat={}, nav_subcat='', \
                               nav_subsubcat='', nav_curpage={"name": "Unauthorized"})
    tour_status = check_menu_tour_init(user.id)
    task_list = [
        {
            'name': 'Complete the Security Universal Menu Navigation Tour',
            'status': tour_status,
            'link': 'javascript:void(0)'
        },

    ]
    total_done = 0
    for i in task_list:
        if i['status'] == 'd':
            total_done += 1
    return render_template('admin/onboarding.html', user_roles=user_roles, new_msg_cnt=2, messages=[], NAV=NAV,
                           user=user,
                           task_list=task_list, total_done=total_done, tour_status=tour_status)

@admin.route('/onboarding_suppress', methods=['GET', 'POST'])
@login_required
def onboarding_suppress():
    NAV['curpage'] = {"name": "Onboarding Tasks"}
    user, status, user_roles = _auth_user(session, 'No Role')
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, NAV=NAV)
    db.session.query(User).filter(User.id == user.id).update({User.onboarding_confirmed: 'y'}, synchronize_session=False)
    db_connection_handler(db)
    return str(200)

@admin.route('/onboarding_ud_menu_tour', methods=['POST'])
@login_required
def onboarding_ud_menu_tour():
    NAV['curpage'] = {"name": "Onboarding Tasks"}
    user, status, user_roles = _auth_user(session, 'No Role')
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, NAV=NAV)
    new_config = SuSiteConfiguration(setting_name=f"menu_tour_init_{user.id}",
                           setting_key=f"menu_tour_init_{user.id}", setting_value="1")
    db.session.add(new_config)
    db_connection_handler(db)
    return str(200)
