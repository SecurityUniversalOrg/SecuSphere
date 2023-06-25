from flask import request, render_template, session, redirect, url_for, jsonify
import base64
import os
from vr import db, app
from vr.admin.auth_functions import create_api_key
from vr.admin import admin
from vr.admin.models import RegisterForm, UserAPIKeys, OAuth2Client
from flask_login import login_required
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, _add_page_permissions_filter
from vr.admin.functions import db_connection_handler
from authlib.integrations.flask_oauth2 import current_token
from werkzeug.security import gen_salt
import time



NAV = {
    'CAT': { "name": "Admin", "url": "admin.dashboard"}
}

@admin.route('/api/register', methods=['GET', 'POST'])
@login_required
def api_register():
    try:
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, nav_cat={}, nav_subcat='', \
                                   nav_subsubcat='', nav_curpage={"name": "Unauthorized"})
        form = RegisterForm(request.form)
        if request.method == 'POST':
            keyname = request.form.get('keyname')
            otp_secret = base64.b32encode(os.urandom(30)).decode('utf-8')
            api_key = create_api_key(user.id, otp_secret)
            new_api_key = UserAPIKeys(
                user_id=user.id,
                Name=keyname,
                Otp=otp_secret,
                ApiKey=api_key
            )
            db.session.add(new_api_key)
            db_connection_handler(db)
            return render_template('admin/api_register_confirm.html', form=form, user=user, api_key=api_key, user_roles=user_roles, NAV=NAV)
        else:
            return render_template('admin/api_register.html', form=form, user=user, user_roles=user_roles, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500


@admin.route('/create_client', methods=('GET', 'POST'))
@login_required
def create_client():
    NAV['curpage'] = {"name": "Create API Client"}
    role_req = ['Admin']
    user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, nav_cat={}, nav_subcat='', \
                               nav_subsubcat='', nav_curpage={"name": "Unauthorized"})
    if request.method == 'GET':
        return render_template('create_client.html', user=user, user_roles=user_roles, NAV=NAV)
    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )
    form = request.form
    client_metadata = _get_client_metadata(form)
    client.set_client_metadata(client_metadata)
    client.client_secret = gen_salt(48)
    db.session.add(client)
    db_connection_handler(db)
    return render_template('create_client_output.html', user=user, user_roles=user_roles,
                           NAV=NAV, client_id=client_id, client_secret=client.client_secret)


def _get_client_metadata(form):
    scope_str = ''
    for i in form:
        if not scope_str:
            scope_str += i
        else:
            scope_str += f" {i}"
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": "http://127.0.0.1",
        "grant_types": ['client_credentials'],
        "redirect_uris": ["http://127.0.0.1"],
        "response_types": ['code'],
        "scope": scope_str,
        "token_endpoint_auth_method": "client_secret_post"
    }
    return client_metadata
