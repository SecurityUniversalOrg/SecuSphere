from vr.assets import assets
from math import ceil
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from sqlalchemy import text, func
from flask import render_template, session, redirect, url_for, request
from flask_login import login_required
from vr.functions.table_functions import load_table, update_table
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.vulns.model.vulnerabilities import Vulnerabilities, VulnerabilitiesSchema


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"
APP_VIEWER = "Application Viewer"
ADMIN_LOGIN = "admin.login"
UNAUTH_STATUS = "403.html"
SERVER_ERR_STATUS = "500.html"


@assets.route("/application_endpoints/<id>", methods=['GET', 'POST'])
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
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": components_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < components_all.total else components_all.total
        }
        return render_template('assets/application_endpoints.html', entities=assets, app_data=app_data, user=user, NAV=NAV,
                               table_details=table_details)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500



