from math import ceil
from vr.sourcecode import sourcecode
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import request, render_template, session, redirect, url_for
from flask_login import login_required
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema
from vr.vulns.model.vulnerabilityscans import VulnerabilityScans, VulnerabilityScansSchema
from sqlalchemy import text, func, case, not_
from vr.functions.table_functions import load_table, update_table
from vr.assets.model.businessapplications import BusinessApplications


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"


@sourcecode.route("/branches/<id>", methods=['GET', 'POST'])
@login_required
def branches(id):
    try:
        NAV['curpage'] = {"name": "Branches"}
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

        branches = VulnerabilityScans.query \
            .with_entities(
            VulnerabilityScans.Branch,
            func.count(case([(Vulnerabilities.Status.like('Closed%'), Vulnerabilities.VulnerabilityID)])).label(
                'closed_findings_cnt'),
            func.count(case([(not_(Vulnerabilities.Status.like('Closed%')), Vulnerabilities.VulnerabilityID)])).label(
                'open_findings_cnt')
        ) \
            .join(Vulnerabilities, Vulnerabilities.ScanId == VulnerabilityScans.ID, isouter=True) \
            .group_by(VulnerabilityScans.Branch) \
            .filter(text("".join(filter_list))) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((branches.total / per_page))
        schema = VulnerabilityScansSchema(many=True)
        assets = schema.dump(branches.items)

        NAV['appbar'] = 'branches'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": branches.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < branches.total else branches.total
        }

        return render_template('sourcecode/branches.html', app_data=app_data, entities=assets, user=user, NAV=NAV,
                               table_details= table_details)
    except RuntimeError:
        return render_template('500.html'), 500


