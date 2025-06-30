from vr import db, app
import base64
import os
from math import ceil
from vr.admin import admin
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from vr.admin.models import User, UserRoles, UserRoleAssignments, UsersSchema, EntityPermissions
from sqlalchemy import text
from flask import request, render_template, session, redirect, url_for, json
from flask_login import login_required
from vr.functions.table_functions import load_table, update_table
from vr.admin.email_alerts import send_registration_email
from vr.assets.model.businessapplications import BusinessApplications
from vr.admin.functions import db_connection_handler


NAV = {
    'CAT': { "name": "Admin", "url": "admin.admin_dashboard"}
}
LOGIN_URL = "admin.login"
UNAUTH_URL = "403.html"


@admin.route("/users", methods=['GET', 'POST'])
@login_required
def users():
    try:
        NAV['curpage'] = {"name": "All Users"}
        admin_role = 'Admin'
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for(LOGIN_URL))
        elif status == 403:
            return render_template(UNAUTH_URL, user=user, NAV=NAV)
        new_dict = {
            'db_name': 'User',
            "sort_field": "id"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
            allowed_columns = ["id", "name", "email", "created_at"]  # Example whitelist
            if orderby not in allowed_columns:
                orderby = "id"  # Default to a safe column
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)
        sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='User.id')
        assets_all = User.query\
            .filter(text(sql_filter)) \
            .order_by(orderby) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)
        users_all = _get_all_users(assets_all)

        pg_cnt = ceil((assets_all.total / per_page))
        entity_details = {}
        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": assets_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < assets_all.total else assets_all.total
        }

        all_apps = BusinessApplications.query.all()
        return render_template('admin/users.html', entity_details=entity_details, entities=assets_all.items, user=user,
                               NAV=NAV, table_details= table_details, app_data={"ID": 0}, user_list=users_all,
                               all_apps=all_apps)
    except RuntimeError:
        return render_template('500.html'), 500

def _get_all_users(assets_all):
    users_all = {}
    for i in assets_all.items:
        user_roles = []
        user_roles_q = UserRoleAssignments.query.with_entities(UserRoles.id, UserRoles.name, UserRoleAssignments.id) \
            .join(UserRoles, UserRoles.id == UserRoleAssignments.role_id).filter(text(f'UserRoleAssignments.user_id={i.id}')).all()
        for j in user_roles_q:
            user_roles.append(j[1])
        app_perms_raw = EntityPermissions.query.with_entities(EntityPermissions.EntityID).filter(text(f"EntityPermissions.UserID={i.id} AND EntityPermissions.EntityType='Application'")).all()
        app_perms = []
        for j in app_perms_raw:
            app_perms.append(j[0])
        user_dict = _set_user_variables(i)

        users_all[i.id] = {
            "about_me": user_dict['about_me'],
            "app_updates": user_dict['app_updates'],
            "auth_token": user_dict['auth_token'],
            "auth_type": user_dict['auth_type'],
            "avatar_path": user_dict['avatar_path'],
            "dept": user_dict['dept'],
            "email": user_dict['email'],
            "email_confirmed_at": user_dict['email_confirmed_at'],
            "email_updates": user_dict['email_updates'],
            "first_name": user_dict['first_name'],
            "id": user_dict['id'],
            "jobtitle": user_dict['jobtitle'],
            "last_name": user_dict['last_name'],
            "loc_city": user_dict['loc_city'],
            "loc_state": user_dict['loc_state'],
            "loc_zipcode": user_dict['loc_zipcode'],
            "mfa_enabled": user_dict['mfa_enabled'],
            "onboarding_confirmed": user_dict['onboarding_confirmed'],
            "phone_no": user_dict['phone_no'],
            "registration_date": user_dict['registration_date'],
            "text_updates": user_dict['text_updates'],
            "user_type": user_dict['user_type'],
            "username": user_dict['username'],
            "web_tz": user_dict['web_tz'],
            "user_roles": user_roles,
            "app_perms": app_perms
        }
    return users_all


def _set_user_variables(i):
    schema = UsersSchema()
    user_dict = schema.dump(i)
    return user_dict


@admin.route("/add_user_role", methods=['POST'])
@login_required
def add_user_role():
    role_req = ['Admin']
    user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
    if status == 401:
        return redirect(url_for(LOGIN_URL))
    elif status == 403:
        return render_template(UNAUTH_URL, user=user, NAV=NAV)

    add_new_assignment = True
    new_user_id = request.form.get('user_id')
    new_grp = request.form.get('new_grp')
    if new_grp == "Application Viewer":
        user_role_a = UserRoleAssignments.query \
            .with_entities(UserRoleAssignments.id) \
            .join(UserRoles, UserRoles.id==UserRoleAssignments.role_id)\
            .filter(text("UserRoleAssignments.user_id=:user_id AND UserRoles.name=:group_name").params(user_id=new_user_id, group_name=new_grp)).first()
        if user_role_a:
            add_new_assignment = False
        new_app_ids = request.form.get('values').split(',')
        for i in new_app_ids:
            new_ent = EntityPermissions(
                UserID=new_user_id,
                EntityType="Application",
                EntityID=i.lstrip().rstrip()
            )
            db.session.add(new_ent)
            db_connection_handler(db)
    if add_new_assignment:
        user_role_q = UserRoles.query \
            .with_entities(UserRoles.id) \
            .filter(text("UserRoles.name=:group_name").params(group_name=new_grp)).first()
        new_app = UserRoleAssignments(
            user_id=new_user_id,
            role_id=user_role_q[0]
        )
        db.session.add(new_app)
        db_connection_handler(db)
    if new_grp == "Admin":
        db.session.query(User).filter(User.id == int(new_user_id)).update(
            {User.is_admin: True},
            synchronize_session=False)
        db_connection_handler(db)
    elif new_grp == "Security":
        db.session.query(User).filter(User.id == int(new_user_id)).update(
            {User.is_security: True},
            synchronize_session=False)
        db_connection_handler(db)
    return '200', 200


@admin.route("/remove_user_role", methods=['POST'])
@login_required
def remove_user_role():
    try:
        NAV['curpage'] = {"name": "All Users"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for(LOGIN_URL))
        elif status == 403:
            return render_template(UNAUTH_URL, user=user, NAV=NAV)

        user_id = request.form.get('user_id')
        role = request.form.get('role')
        del_pair = UserRoleAssignments.query\
            .join(UserRoles, UserRoles.id == UserRoleAssignments.role_id) \
            .filter(text("UserRoleAssignments.user_id=:user_id AND UserRoles.name=:role"))\
            .params(user_id=user_id, role=role).first()
        if del_pair:
            db.session.delete(del_pair)
            db_connection_handler(db)
        if role == 'Admin':
            db.session.query(User).filter(User.id == int(user_id)).update(
                {User.is_admin: False},
                synchronize_session=False)
            db_connection_handler(db)
        elif role == 'Security':
            db.session.query(User).filter(User.id == int(user_id)).update(
                {User.is_security: False},
                synchronize_session=False)
            db_connection_handler(db)
        rsp_json = {'status': 'success'}
        response = app.response_class(
            response=json.dumps(rsp_json),
            status=200,
            mimetype='application/json'
        )
        return response
    except RuntimeError:
        return render_template('500.html'), 500


@admin.route("/remove_user_appview_role", methods=['POST'])
@login_required
def remove_user_appview_role():
    try:
        NAV['curpage'] = {"name": "All Users"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for(LOGIN_URL))
        elif status == 403:
            return render_template(UNAUTH_URL, user=user, NAV=NAV)

        user_id = request.form.get('user_id')
        app_id = request.form.get('app_id')
        del_pair = EntityPermissions.query\
            .filter(text("EntityPermissions.UserID=:user_id AND EntityPermissions.EntityID=:app_id AND EntityPermissions.EntityType='Application'"))\
            .params(user_id=user_id, app_id=app_id).first()
        if del_pair:
            db.session.delete(del_pair)
            db_connection_handler(db)
        rsp_json = {'status': 'success'}
        response = app.response_class(
            response=json.dumps(rsp_json),
            status=200,
            mimetype='application/json'
        )
        return response
    except RuntimeError:
        return render_template('500.html'), 500


@admin.route("/remove_user", methods=['POST'])
@login_required
def remove_user():
    try:
        NAV['curpage'] = {"name": "All Users"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for(LOGIN_URL))
        elif status == 403:
            return render_template(UNAUTH_URL, user=user, NAV=NAV)

        user_id = request.form.get('user_id')
        del_pair = User.query\
            .filter(User.id == user_id).first()
        if del_pair:
            db.session.delete(del_pair)
            db_connection_handler(db)
        rsp_json = {'status': 'success'}
        response = app.response_class(
            response=json.dumps(rsp_json),
            status=200,
            mimetype='application/json'
        )
        return response
    except RuntimeError:
        return render_template('500.html'), 500


@admin.route("/add_new_user", methods=['POST'])
@login_required
def add_new_user():
    role_req = ['Admin']
    user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
    if status == 401:
        return redirect(url_for(LOGIN_URL))
    elif status == 403:
        return render_template(UNAUTH_URL, user=user, NAV=NAV)

    firstname = request.form.get('firstname')
    lastname = request.form.get('lastname')
    email = request.form.get('email')
    cur_user = User.query.filter_by(email=email).first()
    if not cur_user:
        otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        username = firstname.lower() + "." + lastname.lower()
        new_user = User(
            username=username,
            email=email,
            first_name=firstname,
            last_name=lastname,
            is_active=False,
            auth_type=app.config['AUTH_TYPE'],
            otp_secret=otp_secret,
            user_type='system',
            avatar_path='/static/images/default_profile_avatar.jpg'
        )
        db.session.add(new_user)
        db_connection_handler(db)

        token = user.get_delegated_registration_token(new_user.id)
        db.session.query(User).filter(User.id == int(new_user.id)).update(
            {User.auth_token: token},
            synchronize_session=False)
        db_connection_handler(db)

        send_registration_email(app.config['APP_EXT_URL'], username, firstname, lastname, token, email)

        rsp_json = {'status': 'success'}
        response = app.response_class(
            response=json.dumps(rsp_json),
            status=200,
            mimetype='application/json'
        )
        return response
    else:
        rsp_json = {'status': 'error'}
        response = app.response_class(
            response=json.dumps(rsp_json),
            status=405,
            mimetype='application/json'
        )
        return response
