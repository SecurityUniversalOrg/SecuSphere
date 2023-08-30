from vr.sourcecode import sourcecode
from math import ceil
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import request, render_template, session, redirect, url_for
from flask_login import login_required
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema
from sqlalchemy import text, func
from vr.functions.table_functions import load_table, update_table
from vr.assets.model.businessapplications import BusinessApplications


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"


@sourcecode.route("/sourcecode_files/<id>", methods=['GET', 'POST'])
@login_required
def sourcecode_files(id):
    try:
        NAV['curpage'] = {"name": "Source Code Files"}
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

        key = 'Vulnerabilities.ApplicationId'
        val = id
        filter = f"{key} = '{val}'"

        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerableFileName"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        components = Vulnerabilities.query.with_entities(
            Vulnerabilities.VulnerableFileName,
            func.count(Vulnerabilities.VulnerabilityID).label('findings_cnt')
        ).join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
            .filter(text(filter)) \
            .filter(text("Vulnerabilities.Classification LIKE 'IaC%' OR Vulnerabilities.Classification LIKE 'SAST%' OR Vulnerabilities.Classification LIKE 'Secret%'")) \
            .group_by(Vulnerabilities.VulnerableFileName) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((components.total / per_page))
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(components.items)

        NAV['appbar'] = 'components'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": components.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < components.total else components.total
        }

        return render_template('sourcecode/sourcecode_files.html', app_data=app_data, entities=assets, user=user, NAV=NAV,
                               table_details= table_details)
    except RuntimeError:
        return render_template('500.html'), 500


