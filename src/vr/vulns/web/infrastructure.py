from vr.vulns import vulns
from math import ceil
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from sqlalchemy import text, func, and_
from flask import render_template, session, redirect, url_for, request
from flask_login import login_required
from vr.functions.table_functions import load_table, update_table
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.vulns.model.applicationendpoints import ApplicationEndpoints, ApplicationEndpointsSchema
from vr.vulns.model.vulnerabilities import Vulnerabilities, VulnerabilitiesSchema
from vr.assets.model.ipassets import IPAssets, IPAssetsSchema
from vr.assets.model.assetapplications import AssetApplications


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"
APP_VIEWER = "Application Viewer"
ADMIN_LOGIN = "admin.login"
UNAUTH_STATUS = "403.html"
SERVER_ERR_STATUS = "500.html"


@vulns.route("/endpoint/<appid>/<id>")
@login_required
def endpoint(appid, id):
    try:
        NAV['curpage'] = {"name": "Endpoint"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        details = {}
        key = 'ID'
        val = id
        filter_list = [f"{key} = '{val}'"]
        endpoints_all = ApplicationEndpoints.query.filter(text("".join(filter_list))).all()
        schema = ApplicationEndpointsSchema(many=True)
        assets = schema.dump(endpoints_all)
        details['details'] = assets[0]
        vulns_all = Vulnerabilities.query \
            .join(ApplicationEndpoints, and_(ApplicationEndpoints.Endpoint == Vulnerabilities.Uri, ApplicationEndpoints.ApplicationID == appid)) \
            .all()
        details['vulns_all'] = vulns_all

        NAV['appbar'] = 'endpoints'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName}

        return render_template('endpoint.html', details=details, app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500

@vulns.route("/endpoint/host/<id>")
@login_required
def endpoint_host(id):
    try:
        NAV['curpage'] = {"name": "Endpoint Host"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        details = {}
        key = 'ID'
        val = id
        filter_list = [f"{key} = '{val}'"]
        endpoints_all = IPAssets.query.filter(text("".join(filter_list))).all()
        schema = IPAssetsSchema(many=True)
        assets = schema.dump(endpoints_all)
        details['details'] = assets[0]
        key = 'AssetID'
        val = id
        filter_list = [f"{key} = '{val}'"]
        endpoints_all = ApplicationEndpoints.query.filter(text("".join(filter_list))).all()
        schema = ApplicationEndpointsSchema(many=True)
        assets = schema.dump(endpoints_all)
        details['endpoints'] = assets

        vulns_all = Vulnerabilities.query\
            .join(ApplicationEndpoints, Vulnerabilities.Uri == ApplicationEndpoints.Endpoint, isouter=True) \
            .filter(text(f"ApplicationEndpoints.AssetID = {id}")).all()
        details['vulns_all'] = vulns_all


        return render_template('endpoint_host.html', details=details, user=user, NAV=NAV)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500

@vulns.route("/application_endpoints/<id>", methods=['GET', 'POST'])
@login_required
def application_endpoints(id):
    try:
        NAV['curpage'] = {"name": "Application Endpoints"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)

        key = 'Vulnerabilities.ApplicationId'
        val = id
        filter_list = f"{key} = '{val}'"

        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "findings_cnt"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict, aggregate_field=True, direction="desc")
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict, aggregate_field=True, direction="desc")

        components_all = Vulnerabilities.query.with_entities(
            Vulnerabilities.Uri,
            func.count(Vulnerabilities.VulnerabilityID).label('findings_cnt')
        ).join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
            .filter(text(filter_list)) \
            .filter(text("Vulnerabilities.Classification LIKE 'DAST%'")) \
            .group_by(Vulnerabilities.Uri) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((components_all.total / per_page))
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(components_all.items)

        NAV['appbar'] = 'endpoints'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName}
        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": components_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < components_all.total else components_all.total
        }
        return render_template('application_endpoints.html', entities=assets, app_data=app_data, user=user, NAV=NAV,
                               table_details=table_details)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500

@vulns.route("/application_hosts/<id>")
@login_required
def application_hosts(id):
    try:
        NAV['curpage'] = {"name": "Application Hosts"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)

        key = 'AssetApplications.ApplicationID'
        val = id
        filter_list = [f"{key} = '{val}'"]
        components_all = AssetApplications.query.with_entities(
            AssetApplications.ID,
            IPAssets.Hostname,
            func.count(Vulnerabilities.VulnerabilityID).label('findings_cnt'),
        ) \
            .join(Vulnerabilities, Vulnerabilities.HostId == AssetApplications.TechnologyID, isouter=True) \
            .join(IPAssets, IPAssets.ID == AssetApplications.TechnologyID) \
            .group_by(AssetApplications.ID) \
            .filter(text("".join(filter_list))).all()
        NAV['appbar'] = 'endpoints'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName}
        return render_template('application_hosts.html', entities=components_all, app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500

