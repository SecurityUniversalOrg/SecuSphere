from math import ceil
from vr.sourcecode import sourcecode
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import request, render_template, session, redirect, url_for, jsonify
from flask_login import login_required
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema
from vr.vulns.model.vulnerabilityscans import VulnerabilityScans, VulnerabilityScansSchema
from vr.sourcecode.model.releaseversions import ReleaseVersions, MakeReleaseVersionsSchema, ReleaseVersionsSchema
from sqlalchemy import text, func, and_
from vr.functions.table_functions import load_table, update_table
from vr.assets.model.businessapplications import BusinessApplications


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"


@sourcecode.route("/branches/<id>")
@login_required
def branches(id):
    try:
        NAV['curpage'] = {"name": "Release Versions"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        key = 'VulnerabilityScans.ApplicationId'
        val = id
        filter_list = [f"{key} = '{val}'"]

        new_dict = {
            'db_name': 'VulnerabilityScans',
            "sort_field": "Branch"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        branches = VulnerabilityScans.query\
            .with_entities(
            VulnerabilityScans.Branch,
            func.count(Vulnerabilities.VulnerabilityID).label('findings_cnt')
        ) \
            .join(Vulnerabilities, Vulnerabilities.ScanId==VulnerabilityScans.ID, isouter=True) \
            .group_by(VulnerabilityScans.Branch) \
            .filter(text("Vulnerabilities.Status != 'Closed'")) \
            .filter(text("".join(filter_list))) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((branches.total / per_page))
        schema = VulnerabilityScansSchema(many=True)
        assets = schema.dump(branches.items)

        NAV['appbar'] = 'branches'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName}

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": branches.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < branches.total else branches.total
        }

        return render_template('versions.html', app_data=app_data, entities=assets, user=user, NAV=NAV,
                               table_details= table_details)
    except RuntimeError:
        return render_template('500.html'), 500


@sourcecode.route("/version/<appid>/<id>")
@login_required
def version(appid, id):
    try:
        NAV['curpage'] = {"name": "Version"}
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
        details = {}
        key = 'ID'
        val = id
        filter_list = [f"{key} = '{val}'"]
        endpoints_all = ReleaseVersions.query.filter(text("".join(filter_list))).all()
        schema = ReleaseVersionsSchema(many=True)
        assets = schema.dump(endpoints_all)
        details['details'] = assets[0]
        vulns_all = Vulnerabilities.query \
            .join(BusinessApplications, Vulnerabilities.ApplicationId==BusinessApplications.ID, isouter=True) \
            .all()
        details['vulns_all'] = vulns_all

        NAV['appbar'] = 'branches'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName}

        return render_template('version.html', details=details, app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500
