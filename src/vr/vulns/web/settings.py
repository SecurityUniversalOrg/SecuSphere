from vr import db, app
from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from vr.admin.functions import db_connection_handler
from sqlalchemy import text
from flask import request, render_template, session, redirect, url_for
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.vulns.model.vulntoolapppairs import VulnToolAppPairs
from vr.vulns.model.integrations import Integrations
from vr.vulns.model.vulnerabilityslaapppair import VulnerabilitySLAAppPair
from vr.vulns.model.vulnerabilityslas import VulnerabilitySLAs
from vr.vulns.model.regulations import Regulations


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"
APP_VIEWER = "Application Viewer"
ADMIN_LOGIN = "admin.login"
UNAUTH_STATUS = "403.html"
SERVER_ERR_STATUS = "500.html"


@vulns.route("/tool_configurations/<id>")
@login_required
def tool_configurations(id):
    try:
        NAV['curpage'] = {"name": "Tool Configurations"}
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

        key = 'VulnToolAppPairs.ApplicationID'
        val = id
        filter_list = [f"{key} = '{val}'"]
        components_all = VulnToolAppPairs.query.with_entities(
            VulnToolAppPairs.ID,
            Integrations.Name,
            Integrations.AuthenticationType,
            Integrations.ToolType
        ) \
            .join(Integrations, Integrations.ID == VulnToolAppPairs.ToolID, isouter=True) \
            .filter(text("".join(filter_list))).all()
        NAV['appbar'] = 'settings'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName}
        return render_template('tool_configurations.html', entities=components_all, app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500

@vulns.route("/tool_configurations/<id>/add", methods=['GET', 'POST'])
@login_required
def tool_configurations_add(id):
    try:
        NAV['curpage'] = {"name": "Tool Configurations"}
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
        if request.method == 'POST':
            tool_id = request.form.get('tool_configuration')
            tool_project_id = request.form.get('tool_project_id')
            new_app = VulnToolAppPairs(
                ApplicationID=id,
                ToolID=tool_id,
                ToolProjectID=tool_project_id
            )
            db.session.add(new_app)
            db_connection_handler(db)
            return redirect(url_for('vulns.tool_configurations', id=id))
        components_all = Integrations.query.with_entities(
            Integrations.ID, Integrations.AuthenticationType, Integrations.ToolType, Integrations.Name,
            VulnToolAppPairs.ID
        )\
            .join(VulnToolAppPairs, Integrations.ID == VulnToolAppPairs.ToolID, isouter=True) \
            .filter(text(f"VulnToolAppPairs.ApplicationID <> {id}")).all()
        NAV['appbar'] = 'settings'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName}
        return render_template('tool_configurations_add.html', entities=components_all, app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500

@vulns.route("/edit_application/<id>", methods=['GET', 'POST'])
@login_required
def edit_application(id):
    try:
        NAV['curpage'] = {"name": "Edit Application"}
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
        if request.method == 'POST':
            _set_application_config(request)
            return str(200)
        app = BusinessApplications.query.with_entities(
            BusinessApplications.ID, BusinessApplications.ApplicationName, BusinessApplications.Description,
            BusinessApplications.AppValue, BusinessApplications.Version, BusinessApplications.InHouseDev,
            BusinessApplications.VendorDev, BusinessApplications.PHI, BusinessApplications.PII, BusinessApplications.PCI,
            BusinessApplications.MiscCustomerData, BusinessApplications.Type, BusinessApplications.WebEnabled,
            BusinessApplications.RepoURL, BusinessApplications.ApplicationType, BusinessApplications.ProductType,
            BusinessApplications.Lifecycle, BusinessApplications.Origin, BusinessApplications.UserRecords,
            BusinessApplications.Revenue, VulnerabilitySLAAppPair.SlaID
        )\
            .join(VulnerabilitySLAAppPair, VulnerabilitySLAAppPair.ApplicationID==BusinessApplications.ID)\
            .filter(text(f'BusinessApplications.ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Description': app.Description, 'AppValue': app.AppValue,
                    'Version': app.Version, 'InHouseDev': app.InHouseDev, 'VendorDev': app.VendorDev, 'PHI': app.PHI,
                    'PII': app.PII, 'PCI': app.PCI, 'MiscCustomerData': app.MiscCustomerData, 'Type': app.Type,
                    'WebEnabled': app.WebEnabled, 'RepoURL': app.RepoURL, 'ApplicationType': app.ApplicationType,
                    'ProductType': app.ProductType, 'Lifecycle': app.Lifecycle, 'Origin': app.Origin, 'UserRecords': app.UserRecords,
                    'Revenue': app.Revenue, 'SlaID': app.SlaID
                    }
        product_types = ['Billing', 'Commerce', 'Internal', 'Research and Development', 'Security']
        all_slas = VulnerabilitySLAs.query.all()
        all_regs = Regulations.query.all()
        return render_template('edit_application.html', user=user, NAV=NAV, app_data=app_data,
                               product_types=product_types, all_slas=all_slas, all_regs=all_regs)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


def _set_application_config(request):
    app_name = request.form.get('name')
    description = request.form.get('description')
    app_value = request.form.get('business_criticality')
    version = request.form.get('initial_version')
    data_types = request.form.get('data_types')
    platform = request.form.get('platform')
    internet_access = request.form.get('internet_accessible')
    repo_url = request.form.get('repo_url')
    prod_type = request.form.get('prod_type')
    lifecycle = request.form.get('lifecycle')
    origin = request.form.get('origin')
    user_records = request.form.get('user_records')
    revenue = request.form.get('revenue')
    db.session.query(BusinessApplications).filter(text(f"BusinessApplications.ID={id}")).update(
        {
            BusinessApplications.ApplicationName: app_name,
            BusinessApplications.Description: description,
            BusinessApplications.AppValue: app_value,
            BusinessApplications.Version: version,
            BusinessApplications.InHouseDev: 1 if origin == 'internal' else 0,
            BusinessApplications.VendorDev: 0 if origin == 'internal' else 1,
            BusinessApplications.Customization: 1,
            BusinessApplications.PHI: 1 if 'PHI' in data_types else 0,
            BusinessApplications.PII: 1 if 'PII' in data_types else 0,
            BusinessApplications.PCI: 1 if 'PCI' in data_types else 0,
            BusinessApplications.MiscCustomerData: 1 if 'MiscCustomerData' in data_types else 0,
            BusinessApplications.Type: platform,
            BusinessApplications.WebEnabled: 1 if internet_access == 'on' else 0,
            BusinessApplications.RepoURL: repo_url,
            BusinessApplications.ApplicationType: platform,
            BusinessApplications.ProductType: prod_type,
            BusinessApplications.Lifecycle: lifecycle,
            BusinessApplications.Origin: origin,
            BusinessApplications.UserRecords: user_records,
            BusinessApplications.Revenue: revenue
        },
        synchronize_session=False)
    db_connection_handler(db)


@vulns.route("/add_application_integrations", methods=['POST'])
@login_required
def add_application_integrations():
    try:
        NAV['curpage'] = {"name": "Add Application Integrations"}
        role_req = [APP_ADMIN]
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        if request.method == 'POST':
            app_id = request.form.get('new_id')
            source_code_int_id = request.form.get('source_code')
            github_repo_name = request.form.get('github_repo_name')
            cicd_int_id= request.form.get('cicd')
            jenkins_pipeline_name = request.form.get('jenkins_pipeline_name')
            issue_management_int_id = request.form.get('issue_management')
            jira_project_key = request.form.get('jira_project_key')
            sast_int_id = request.form.get('sast')
            sonarqube_project_name = request.form.get('sonarqube_project_name')
            container_int_id = request.form.get('container')
            anchore_project_name = request.form.get('anchore_project_name')

            if source_code_int_id:
                new_pair = VulnToolAppPairs(
                    ApplicationID=app_id,
                    ToolID = source_code_int_id,
                    KeyValuePairs = f"github_repo_name={github_repo_name},"
                )
                db.session.add(new_pair)
                db_connection_handler(db)
            if cicd_int_id:
                new_pair = VulnToolAppPairs(
                    ApplicationID=app_id,
                    ToolID = cicd_int_id,
                    KeyValuePairs = f"jenkins_pipeline_name={jenkins_pipeline_name},"
                )
                db.session.add(new_pair)
                db_connection_handler(db)
            if issue_management_int_id:
                new_pair = VulnToolAppPairs(
                    ApplicationID=app_id,
                    ToolID = issue_management_int_id,
                    KeyValuePairs = f"jira_project_key={jira_project_key},"
                )
                db.session.add(new_pair)
                db_connection_handler(db)
            if sast_int_id:
                new_pair = VulnToolAppPairs(
                    ApplicationID=app_id,
                    ToolID = sast_int_id,
                    KeyValuePairs = f"sonarqube_project_name={sonarqube_project_name},"
                )
                db.session.add(new_pair)
                db_connection_handler(db)
            if container_int_id:
                new_pair = VulnToolAppPairs(
                    ApplicationID=app_id,
                    ToolID = container_int_id,
                    KeyValuePairs = f"anchore_project_name={anchore_project_name},"
                )
                db.session.add(new_pair)
                db_connection_handler(db)
            return redirect(url_for('vulns.all_applications'))
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500
