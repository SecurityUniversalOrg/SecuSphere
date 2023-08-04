from vr import db, app
from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import request, render_template, session, redirect, url_for
from flask_login import login_required
from vr.vulns.model.integrations import Integrations, IntegrationsSchema
from vr.vulns.model.appintegrations import AppIntegrations, AppIntegrationsSchema
from vr.assets.model.businessapplications import BusinessApplications
from vr.admin.functions import db_connection_handler
from vr.functions.crypto_functions import encrypt_with_pub_key, decrypt_with_priv_key
import requests
from sqlalchemy import text
from requests.auth import HTTPBasicAuth
import json


NAV = {
    'CAT': { "name": "Integrations", "url": "sourcecode.dashboard"}
}


@vulns.route("/add_integration", methods=['GET', 'POST'])
@login_required
def add_integration():
    try:
        NAV['curpage'] = {"name": "Add Integration"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        if request.method == 'POST':
            app_name = request.form.get('name')
            description = request.form.get('description')
            url = request.form.get('url')
            tool_type = request.form.get('tool_type')
            authentication_type = request.form.get('authentication_type')
            extras = request.form.get('extras')
            username = request.form.get('username')
            if username:
                username = encrypt_with_pub_key(username)
            password = request.form.get('password')
            if password:
                password = encrypt_with_pub_key(password)
            auth_title = request.form.get('auth_title')
            ssh_key = request.form.get('ssh')
            if ssh_key:
                ssh_key = encrypt_with_pub_key(ssh_key)
            api_key = request.form.get('api_key')
            if api_key:
                api_key = encrypt_with_pub_key(api_key)
            new_app = Integrations(
                Name=app_name,
                Description=description,
                Url=url,
                ToolType=tool_type,
                AuthenticationType = authentication_type,
                Extras = extras,
                Username = username,
                Password = password,
                KeyName = auth_title,
                SSHKey = ssh_key,
                APIKey = api_key
            )
            db.session.add(new_app)
            db_connection_handler(db)
            return redirect(url_for('vulns.all_integrations', user=user, NAV=NAV))
        assets_all = Integrations.query.all()
        schema = IntegrationsSchema(many=True)
        assets = schema.dump(
            filter(lambda t: t.ToolType == 'Jenkins', assets_all)
        )
        return render_template('add_integration.html', entities=assets, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500


@vulns.route("/all_integrations")
@login_required
def all_integrations():
    try:
        NAV['curpage'] = {"name": "All Integrations"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        assets_all = Integrations.query.all()
        schema = IntegrationsSchema(many=True)
        assets = schema.dump(
            filter(lambda t: t.ID != '', assets_all)
        )
        return render_template('all_integrations.html', entities=assets, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500


@vulns.route("/validate_integration", methods=['POST'])
@login_required
def validate_integration():
    try:
        NAV['curpage'] = {"name": "All Integrations"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        tool_id = request.form.get('tool_type')
        project_key = request.form.get('project_key')

        assets_all = Integrations.query.filter(Integrations.ID==tool_id).all()
        schema = IntegrationsSchema(many=True)
        assets = schema.dump(
            filter(lambda t: t.ID != '', assets_all)
        )
        status = False
        if assets and assets[0]['ToolType'] == 'JIRA':
            status = check_jira_key(project_key, assets[0])

        return {"status": status}, 200


    except RuntimeError:
        return render_template('500.html'), 500


def check_jira_key(jira_key, integration):
    email = decrypt_with_priv_key(integration['Username'])
    api_token = decrypt_with_priv_key(integration['Password'])
    url = f"{integration['Url']}/rest/api/3/project/{jira_key}"
    headers = {
        "Accept": "application/json",
    }

    response = requests.get(
        url,
        headers=headers,
        auth=HTTPBasicAuth(email, api_token)
    )

    if response.status_code == 200:
        return True
    elif response.status_code == 404:
        return False
    else:
        print(f"An error occurred. Status code: {response.status_code}")
        return False


@vulns.route("/add_app_integration/<app_id>")
@login_required
def add_app_integration(app_id):
    try:
        NAV['curpage'] = {"name": "All Integrations"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        assets_all = Integrations.query.all()
        schema = IntegrationsSchema(many=True)
        assets = schema.dump(
            filter(lambda t: t.ID != '', assets_all)
        )
        entities = []
        for i in assets:
            if i['ToolType'] == 'JIRA':
                i['Projects'] = _get_all_jira_projects(i)
            entities.append(i)
        app = BusinessApplications.query.filter(text(f'ID={app_id}')).first()
        app_data = {'ID': app_id, 'ApplicationName': app.ApplicationName}
        NAV['appbar'] = 'settings'
        return render_template('add_app_integration.html', entities=entities, user=user,
                               NAV=NAV, app_id=app_id, app_data=app_data)
    except RuntimeError:
        return render_template('500.html'), 500


@vulns.route("/submit_app_integration/<app_id>", methods=['POST'])
@login_required
def submit_app_integration(app_id):
    try:
        NAV['curpage'] = {"name": "All Integrations"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        tool_id = request.form.get('tool_type')
        project_key = request.form.get('project_key')

        integration = Integrations.query.filter(Integrations.ID==tool_id).first()

        new_app = AppIntegrations(
            AppID=app_id,
            IntegrationID = tool_id,
            Type=integration.ToolType,
            AppEntity = project_key
        )
        db.session.add(new_app)
        db_connection_handler(db)

        return redirect(url_for('vulns.all_app_integrations', app_id=app_id))
    except RuntimeError:
        return render_template('500.html'), 500


@vulns.route("/all_app_integrations/<app_id>")
@login_required
def all_app_integrations(app_id):
    try:
        NAV['curpage'] = {"name": "All Integrations"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        assets_all = AppIntegrations.query.filter(AppIntegrations.AppID==app_id).all()
        schema = AppIntegrationsSchema(many=True)
        assets = schema.dump(
            filter(lambda t: t.ID != '', assets_all)
        )
        app = BusinessApplications.query.filter(text(f'ID={app_id}')).first()
        app_data = {'ID': app_id, 'ApplicationName': app.ApplicationName}
        NAV['appbar'] = 'settings'
        return render_template('all_app_integrations.html', entities=assets, user=user,
                               NAV=NAV, app_data=app_data)
    except RuntimeError:
        return render_template('500.html'), 500

@vulns.route("/remove_app_integration", methods=['POST'])
@login_required
def remove_app_integration():
    try:
        NAV['curpage'] = {"name": "All Users"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        env_id = request.form.get('env_id')
        del_pair = AppIntegrations.query\
            .filter(text(f"AppIntegrations.ID={env_id}")).first()
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


def _get_all_jira_projects(integration):
    email = decrypt_with_priv_key(integration['Username'])
    api_token = decrypt_with_priv_key(integration['Password'])
    url = f"{integration['Url']}/rest/api/3/project"
    headers = {
        "Accept": "application/json",
    }
    response = requests.request(
        "GET",
        url,
        headers=headers,
        auth=HTTPBasicAuth(email, api_token)
    )
    projects = response.json()
    return projects

