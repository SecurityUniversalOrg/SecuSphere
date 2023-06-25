from vr import db, app
from math import ceil
from vr.sourcecode import sourcecode
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import request, render_template, session, redirect, url_for, jsonify
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications
from vr.sourcecode.model.servicetickets import ServiceTickets, ServiceTicketsSchema
from vr.sourcecode.model.releaseversions import ReleaseVersions
from vr.vulns.model.integrations import Integrations, IntegrationsSchema
from vr.vulns.model.appintegrations import AppIntegrations, AppIntegrationsSchema
from sqlalchemy import text
import requests
from requests.auth import HTTPBasicAuth
from vr.functions.crypto_functions import decrypt_with_priv_key
from vr.functions.table_functions import load_table, update_table
from vr.admin.functions import db_connection_handler


NAV = {
    'CAT': { "name": "Workflows", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"


@sourcecode.route("/all_service_tickets")
@login_required
def all_service_tickets():
    try:
        NAV['curpage'] = {"name": "Service Tickets"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='BusinessApplications.ID')

        new_dict = {
            'db_name': 'ServiceTickets',
            "sort_field": "ID"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict, direction="desc")
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict, direction="desc")

        assets_all = ServiceTickets.query\
            .with_entities(ServiceTickets.ID, ServiceTickets.TicketName, ServiceTickets.AddDate,
                           ServiceTickets.Source, ServiceTickets.Status, BusinessApplications.ApplicationName,
                           ServiceTickets.AppID) \
            .join(BusinessApplications, BusinessApplications.ID == ServiceTickets.AppID, isouter=True) \
            .filter(text(sql_filter)) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((assets_all.total / per_page))
        schema = ServiceTicketsSchema(many=True)
        assets = schema.dump(assets_all.items)

        NAV['appbar'] = 'workflows'

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": assets_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < assets_all.total else assets_all.total
        }

        return render_template('all_service_tickets.html', entities=assets, user=user, NAV=NAV, table_details=table_details)
    except RuntimeError:
        return render_template('500.html'), 500


@sourcecode.route("/issue/<appid>/<id>")
@login_required
def issue(appid, id):
    try:
        NAV['curpage'] = {"name": "Issue Details"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        key = 'ServiceTickets.ID'
        val = id
        filter_list = f"{key} = '{val}'"
        assets_all = ServiceTickets.query \
            .with_entities(ServiceTickets.ID, ServiceTickets.TicketName, ServiceTickets.AddDate,
                           ServiceTickets.Source, ServiceTickets.Status, BusinessApplications.ApplicationName,
                           ServiceTickets.Description, ServiceTickets.Reporter, ServiceTickets.Assignee) \
            .join(ReleaseVersions, ServiceTickets.ReleaseID == ReleaseVersions.ID, isouter=True) \
            .join(BusinessApplications, BusinessApplications.ID == ReleaseVersions.ApplicationID, isouter=True) \
            .filter(text(filter_list)) \
            .first()
        NAV['appbar'] = 'workflows'
        app = BusinessApplications.query\
            .filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName}
        return render_template('view_service_ticket.html', details=assets_all, app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500


@sourcecode.route("/add_service_ticket/<app_id>", methods=['GET', 'POST'])
@login_required
def add_service_ticket(app_id):
    try:
        NAV['curpage'] = {"name": "Add Integration"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        if request.method == 'POST':
            issueTitle = request.form.get('issueTitle')
            issueDescription = request.form.get('issueDescription')
            appIntegrationId = request.form.get('appIntegrationId')

            asset = db.session.query(AppIntegrations, Integrations)\
                  .filter(AppIntegrations.ID == appIntegrationId)\
                  .filter(Integrations.ID == AppIntegrations.IntegrationID)\
                  .first()

            status = create_jira_issue(
                asset.Integrations.Url,
                asset.AppIntegrations.AppEntity,
                decrypt_with_priv_key(asset.Integrations.Username),
                decrypt_with_priv_key(asset.Integrations.Password),
                issueTitle,
                issueDescription
            )

            if status:
                new_ticket = ServiceTickets(
                    TicketName = issueTitle,
                    Description = issueDescription,
                    Source = "JIRA",
                    SourceID = asset.Integrations.ID,
                    Reporter = user.username,
                    Status = "New",
                    IssueKey = status,
                    AppID = app_id
                )
                db.session.add(new_ticket)
                db_connection_handler(db)
                return {"status": "success"}, 200
            else:
                return render_template('500.html'), 500
    except RuntimeError:
        return render_template('500.html'), 500


def create_jira_issue(url, project_key, username, api_token, title, description):
    # Variables
    api_path = "/rest/api/3/issue"

    # Headers
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    # Issue data
    issue_data = {
        "fields": {
            "project": {
                "key": project_key
            },
            "summary": title,
            "description": {
                "version": 1,
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "text": description,
                                "type": "text"
                            }
                        ]
                    }
                ]
            },
            "issuetype": {
                "name": "Task"
            }
        }
    }

    # Make the request
    response = requests.post(
        f"{url}{api_path}",
        headers=headers,
        json=issue_data,
        auth=HTTPBasicAuth(username, api_token)
    )

    # Check if the issue was created successfully
    status = None
    if response.status_code == 201:
        status = response.json()['key']
    else:
        print(f"Failed to create issue. Server responded with: {response.status_code} {response.reason}")
        print(response.text)

    return status
