from vr.sourcecode import sourcecode
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import request, render_template, session, redirect, url_for, jsonify
from flask_login import login_required
from math import ceil
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema
from vr.sourcecode.model.importedcode import ImportedCode, MakeImportedCodeSchema, ImportedCodeSchema
from sqlalchemy import text, func, and_
from vr.assets.model.businessapplications import BusinessApplications
from vr.functions.table_functions import load_table, update_table


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"


@sourcecode.route("/components/<id>")
@login_required
def components(id):
    try:
        NAV['curpage'] = {"name": "Components"}
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
            "sort_field": "findings_cnt"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict, direction="desc")
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict, aggregate_field=True, direction="desc")

        components = Vulnerabilities.query.with_entities(
            func.substring_index(Vulnerabilities.VulnerablePackage, ":", 1).label('pkg_name'),
            func.substring_index(Vulnerabilities.VulnerablePackage, ":", -1).label('pkg_version'),
            func.count(Vulnerabilities.VulnerabilityID).label('findings_cnt')
        ).join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
            .filter(text(filter)) \
            .filter(text("Vulnerabilities.Classification='SCA'")) \
            .group_by('pkg_name', 'pkg_version') \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((components.total / per_page))
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(components.items)

        NAV['appbar'] = 'components'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName}

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": components.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < components.total else components.total
        }

        return render_template('components.html', app_data=app_data, entities=assets, user=user, NAV=NAV,
                               table_details=table_details)
    except RuntimeError:
        return render_template('500.html'), 500


@sourcecode.route("/component/<appid>/<id>")
@login_required
def component(appid, id):
    try:
        NAV['curpage'] = {"name": "Component"}
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
        endpoints_all = ImportedCode.query.filter(text("".join(filter_list))).all()
        schema = ImportedCodeSchema(many=True)
        assets = schema.dump(endpoints_all)
        details['details'] = assets[0]
        vulns_all = Vulnerabilities.query \
            .join(ImportedCode, and_(ImportedCode.ImportFile == Vulnerabilities.VulnerableFileName, ImportedCode.ApplicationID == appid)) \
            .all()
        details['vulns_all'] = vulns_all

        NAV['appbar'] = 'components'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName}

        return render_template('component.html', details=details, app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500

