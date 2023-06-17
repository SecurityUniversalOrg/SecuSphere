from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import render_template, session, redirect, url_for
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications
from vr.vulns.model.cicdpipelines import CICDPipelines, CICDPipelinesSchema
from vr.vulns.model.integrations import Integrations, IntegrationsSchema
from sqlalchemy import text


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}

@vulns.route("/all_pipelines")
@login_required
def all_pipelines():
    try:
        NAV['curpage'] = {"name": "All CI/CD Pipelines"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='BusinessApplications.ID')

        assets_all = CICDPipelines.query\
            .with_entities(CICDPipelines.ID, CICDPipelines.Name, CICDPipelines.Description, CICDPipelines.Url,
                           BusinessApplications.ApplicationName, Integrations.Name.label('IntegrationName'))\
            .join(BusinessApplications, BusinessApplications.ID == CICDPipelines.ApplicationID, isouter=True) \
            .join(Integrations, Integrations.ID == CICDPipelines.IntegrationID, isouter=True) \
            .filter(text(sql_filter)) \
            .all()
        return render_template('all_pipelines.html', entities=assets_all, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500


