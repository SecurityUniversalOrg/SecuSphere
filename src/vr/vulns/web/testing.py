from math import ceil
from sqlalchemy.sql.expression import case
from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from sqlalchemy import text, func
from flask import render_template, session, redirect, url_for, request
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.vulns.model.vulnerabilities import Vulnerabilities, VulnerabilitiesSchema
from vr.vulns.model.vulnerabilityscans import VulnerabilityScans, VulnerabilityScansSchema
from vr.functions.table_functions import load_table, update_table


NAV = {
    'CAT': { "name": "Vulnerabilities", "url": "sourcecode.dashboard"}
}

@vulns.route("/vulnerability_scans/<id>", methods=['GET', 'POST'])
@login_required
def vulnerability_scans(id):
    try:
        NAV['curpage'] = {"name": "Vulnerability Scans"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
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
            "sort_field": "ID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        vuln_all = VulnerabilityScans.query \
            .with_entities(VulnerabilityScans.ID, VulnerabilityScans.ScanName, VulnerabilityScans.ScanType,
                           VulnerabilityScans.ScanTargets, VulnerabilityScans.ScanStartDate,
                           func.count(Vulnerabilities.VulnerabilityID).label('issue_cnt'),
                           func.sum(case([(Vulnerabilities.Status.like("Open-%"), 1)], else_=0)).label('open_issue_cnt'),
                           func.sum(case([(Vulnerabilities.Status.like("Closed-%"), 1)], else_=0)).label('closed_issue_cnt'),
                           func.sum(case([(Vulnerabilities.Status.like("Open-RiskAccepted%"), 1)], else_=0)).label('ra_issue_cnt')
                           ) \
            .join(Vulnerabilities, Vulnerabilities.InitialScanId == VulnerabilityScans.ID, isouter=True) \
            .group_by(VulnerabilityScans.ID) \
            .filter(text("".join(filter_list))) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)
        pg_cnt = ceil((vuln_all.total / per_page))
        schema = VulnerabilityScansSchema(many=True)
        assets = schema.dump(vuln_all.items)

        NAV['appbar'] = 'scans'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName}
        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": vuln_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < vuln_all.total else vuln_all.total
        }
        return render_template('vulnerability_scans.html',  entities=assets, app_data=app_data, user=user, NAV=NAV,
                               table_details= table_details)
    except RuntimeError:
        return render_template('500.html'), 500
