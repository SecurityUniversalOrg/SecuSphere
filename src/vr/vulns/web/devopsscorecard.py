from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, _add_page_permissions_filter
from sqlalchemy import text
from flask import render_template, session, redirect, url_for
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema


NAV = {
    'CAT': { "name": "Applications", "url": "sourcecode.dashboard"}
}

@vulns.route("/devopsscorecard/<id>", methods=['GET', 'POST'])
@login_required
def devopsscorecard(id):
    try:
        NAV['curpage'] = {"name": "DevOps Scorecard"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'DevOps Scorecard']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        key = 'ID'
        val = id
        filter_list = [f"{key} = '{val}'"]
        assets_all = BusinessApplications.query.filter(text("".join(filter_list))).all()
        schema = BusinessApplicationsSchema(many=True)
        assets = schema.dump(assets_all)
        NAV['appbar'] = 'scorecard'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName}
        return render_template('vulns/devopsscorecard.html', app_data=app_data, entities=assets, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500

