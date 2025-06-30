import json
from vr import db, app
from vr.assets import assets
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, _add_page_permissions_filter
from vr.admin.functions import db_connection_handler
from sqlalchemy import text
from flask import request, render_template, session, redirect, url_for
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.assets.model.integrations import Integrations
from vr.vulns.model.vulnerabilityslaapppair import VulnerabilitySLAAppPair
from vr.vulns.model.vulnerabilityslas import VulnerabilitySLAs
from vr.assets.model.regulations import Regulations
from vr.assets.model.appenvironmentdata import AppEnvironmentData, AppEnvironmentDataSchema
from vr.orchestration.model.cicdpipelines import CICDPipelines, CICDPipelinesSchema
from vr.assets.model.appintegrations import AppIntegrations
from vr.assessments.model.applicationregulations import ApplicationRegulations


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"
APP_VIEWER = "Application Viewer"
ADMIN_LOGIN = "admin.login"
UNAUTH_STATUS = "403.html"
SERVER_ERR_STATUS = "500.html"


@assets.route("/edit_application/<id>", methods=['GET', 'POST'])
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
            _set_application_config(request, id)
            return redirect(url_for('assets.edit_application', id=id))
        app = BusinessApplications.query.with_entities(
            BusinessApplications.ID, BusinessApplications.ApplicationName, BusinessApplications.Description,
            BusinessApplications.AppValue, BusinessApplications.Version, BusinessApplications.InHouseDev,
            BusinessApplications.VendorDev, BusinessApplications.PHI, BusinessApplications.PII, BusinessApplications.PCI,
            BusinessApplications.MiscCustomerData, BusinessApplications.Type, BusinessApplications.WebEnabled,
            BusinessApplications.RepoURL, BusinessApplications.ApplicationType, BusinessApplications.ProductType,
            BusinessApplications.Lifecycle, BusinessApplications.Origin, BusinessApplications.UserRecords,
            BusinessApplications.Revenue, VulnerabilitySLAAppPair.SlaID, BusinessApplications.ApplicationAcronym
        )\
            .join(VulnerabilitySLAAppPair, VulnerabilitySLAAppPair.ApplicationID==BusinessApplications.ID)\
            .filter(text(f'BusinessApplications.ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Description': app.Description, 'AppValue': app.AppValue,
                    'Version': app.Version, 'InHouseDev': app.InHouseDev, 'VendorDev': app.VendorDev, 'PHI': app.PHI,
                    'PII': app.PII, 'PCI': app.PCI, 'MiscCustomerData': app.MiscCustomerData, 'Type': app.Type,
                    'WebEnabled': app.WebEnabled, 'RepoURL': app.RepoURL, 'ApplicationType': app.ApplicationType,
                    'ProductType': app.ProductType, 'Lifecycle': app.Lifecycle, 'Origin': app.Origin, 'UserRecords': app.UserRecords,
                    'Revenue': app.Revenue, 'SlaID': app.SlaID, 'Component': app.ApplicationAcronym
                    }
        product_types = ['Billing', 'Commerce', 'Internal', 'Research and Development', 'Security']
        all_slas = VulnerabilitySLAs.query.all()
        all_regs = Regulations.query.all()

        app_regs = ApplicationRegulations.query.filter(ApplicationRegulations.ApplicationID==id).all()

        NAV['appbar'] = 'settings'
        return render_template('assets/edit_application.html', user=user, NAV=NAV, app_data=app_data,
                               product_types=product_types, all_slas=all_slas, all_regs=all_regs, app_regs=app_regs)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


def _set_application_config(request, app_id):
    all = request.form
    app_name = request.form.get('name')
    component_name = request.form.get('componentname')
    description = request.form.get('description').replace('None', '')
    app_value = request.form.get('business_criticality')
    version = request.form.get('initial_version').replace('None', '')
    data_types = request.form.getlist('data_types')
    regulations = request.form.getlist('regulations')
    platform = request.form.get('platform')
    internet_access = request.form.get('internet_accessible')
    repo_url = request.form.get('repo_url')
    prod_type = request.form.get('prod_type')
    lifecycle = request.form.get('lifecycle')
    origin = request.form.get('origin')
    user_records = request.form.get('user_records')
    revenue = request.form.get('revenue')
    db.session.query(BusinessApplications).filter(text(f"BusinessApplications.ID={app_id}")).update(
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
            BusinessApplications.Revenue: revenue,
            BusinessApplications.ApplicationAcronym: component_name
        },
        synchronize_session=False)
    db_connection_handler(db)

    _set_regulations_config(regulations, app_id)

def _set_regulations_config(regulations, app_id):
    app_regs = ApplicationRegulations.query.filter(ApplicationRegulations.ApplicationID==app_id).all()
    for i in app_regs:
        if str(i.RegulationID) not in regulations:
            db.session.delete(i)
            db.session.commit()
    for i in regulations:
        new = True
        for j in app_regs:
            if int(i) == j.RegulationID:
                new = False
        if new:
            new_reg = ApplicationRegulations(
                ApplicationID=app_id,
                RegulationID=int(i)
            )
            db.session.add(new_reg)
            db.session.commit()

@assets.route("/add_application_environment/<app_id>", methods=['GET', 'POST'])
@login_required
def add_application_environment(app_id):
    try:
        NAV['curpage'] = {"name": "Add Application Environment"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _add_page_permissions_filter(session, admin_role)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        if request.method == 'POST':
            all_form = request.form
            EnvironmentName = request.form.get('EnvironmentName')
            EnvironmentClassification = request.form.get('EnvironmentClassification')
            Status = request.form.get('Status')
            ImplementsWebApp = request.form.get('ImplementsWebApp')
            ImplementsAPI = request.form.get('ImplementsAPI')
            PublicFacingWebApp = request.form.get('PublicFacingWebApp')
            PublicFacingAPI = request.form.get('PublicFacingAPI')
            WebURL = request.form.get('WebURL')
            OpenAPISpecURL = request.form.get('OpenAPISpecURL')
            AuthType = request.form.get('AuthType')
            TestUsername = request.form.get('TestUsername')
            TestPasswordReference = request.form.get('TestPasswordReference')
            new_env = AppEnvironmentData(
                AppID=app_id,
                EnvironmentName=EnvironmentName,
                EnvironmentClassification=EnvironmentClassification,
                Status=Status,
                ImplementsWebApp=ImplementsWebApp,
                ImplementsAPI=ImplementsAPI,
                PublicFacingWebApp=PublicFacingWebApp,
                PublicFacingAPI=PublicFacingAPI,
                WebURL=WebURL,
                OpenAPISpecURL=OpenAPISpecURL,
                AuthType=AuthType,
                TestUsername=TestUsername,
                TestPasswordReference=TestPasswordReference
            )
            db.session.add(new_env)
            db_connection_handler(db)

            return redirect(url_for('assets.all_application_environments', app_id=app_id))

        app = BusinessApplications.query.filter(text(f'ID={app_id}')).first()
        app_data = {'ID': app_id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}

        return render_template('assets/add_application_environment.html', app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500


@assets.route("/all_application_environments/<app_id>")
@login_required
def all_application_environments(app_id):
    try:
        NAV['curpage'] = {"name": "All Application Environments"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        assets_all = AppEnvironmentData.query.filter(AppEnvironmentData.AppID==app_id).all()
        schema = AppEnvironmentDataSchema(many=True)
        assets = schema.dump(
            filter(lambda t: t.ID != '', assets_all)
        )
        app = BusinessApplications.query.filter(text(f'ID={app_id}')).first()
        app_data = {'ID': app_id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
        NAV['appbar'] = 'settings'
        return render_template('assets/all_application_environments.html', entities=assets, user=user,
                               NAV=NAV, app_data=app_data)
    except RuntimeError:
        return render_template('500.html'), 500


@assets.route("/remove_application_environment", methods=['POST'])
@login_required
def remove_application_environment():
    try:
        NAV['curpage'] = {"name": "All Users"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        env_id = request.form.get('env_id')
        del_pair = AppEnvironmentData.query\
            .filter(text(f"AppEnvironmentData.ID={env_id}")).first()
        if del_pair:
            db.session.delete(del_pair)
            db_connection_handler(db)
        rsp_json = {'status': 'success'}
        response = app.response_class(
            response=json.dumps(rsp_json),
            status=200,
            mimetype='application/json'
        )
        return response
    except RuntimeError:
        return render_template('500.html'), 500


@assets.route("/edit_application_environment/<app_id>/<env_id>", methods=['GET', 'POST'])
@login_required
def edit_application_environment(app_id, env_id):
    try:
        NAV['curpage'] = {"name": "Edit Application"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(app_id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        if request.method == 'POST':
            _set_application_env_config(request, app_id, env_id)
            return str(200)
        app = AppEnvironmentData.query.with_entities(
            AppEnvironmentData.ID, AppEnvironmentData.AppID, AppEnvironmentData.EnvironmentName,
            AppEnvironmentData.AddDate, AppEnvironmentData.EnvironmentClassification, AppEnvironmentData.Status,
            AppEnvironmentData.ImplementsWebApp, AppEnvironmentData.ImplementsAPI, AppEnvironmentData.PublicFacingWebApp,
            AppEnvironmentData.PublicFacingAPI,
            AppEnvironmentData.WebURL, AppEnvironmentData.OpenAPISpecURL, AppEnvironmentData.AuthType,
            AppEnvironmentData.TestUsername, AppEnvironmentData.TestPasswordReference, BusinessApplications.ApplicationAcronym
        )\
            .join(BusinessApplications, BusinessApplications.ID==AppEnvironmentData.AppID)\
            .filter(text(f'AppEnvironmentData.ID={env_id}')).first()
        app_data = {'envID': app.ID, 'ID': app.AppID, 'EnvironmentName': app.EnvironmentName, 'AddDate': app.AddDate,
                    'EnvironmentClassification': app.EnvironmentClassification, 'Status': app.Status,
                    'ImplementsWebApp': app.ImplementsWebApp, 'ImplementsAPI': app.ImplementsAPI,
                    'PublicFacingWebApp': app.PublicFacingWebApp, 'PublicFacingAPI': app.PublicFacingAPI,
                    'WebURL': app.WebURL, 'OpenAPISpecURL': app.OpenAPISpecURL,
                    'AuthType': app.AuthType, 'TestUsername': app.TestUsername, 'TestPasswordReference': app.TestPasswordReference,
                    'Component': app.ApplicationAcronym
                    }
        all_env_class = ['Development', 'Test', 'Staging', 'Production', 'Other']
        all_status = ['Active', 'Planned', 'Retired', 'Other']
        all_yes_no = ['No', 'Yes']
        all_auth_type = ["None","Basic Authentication","Form-Based Authentication",
                         "Token-Based Authentication","Certificate-Based Authentication",
                         "OAuth 2.0","OpenID Connect","SAML (Security Assertion Markup Language)",
                         "LDAP (Lightweight Directory Access Protocol)","Kerberos",
                         "Biometric Authentication","Social Login","Single Sign-On (SSO)",
                         "JSON Web Tokens (JWT)","Session-Based Authentication","Digest Authentication",
                         "Adaptive Authentication","API Keys","Bearer Token Authentication",
                         "API Gateway Authentication","Custom Authentication","Other"
                         ]
        return render_template('assets/edit_application_environment.html', user=user, NAV=NAV, app_data=app_data,
                               all_env_class=all_env_class, all_status=all_status,
                               all_yes_no=all_yes_no, all_auth_type=all_auth_type)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


def _set_application_env_config(request, app_id, env_id):
    EnvironmentName = request.form.get('EnvironmentName')
    EnvironmentClassification = request.form.get('EnvironmentClassification')
    Status = request.form.get('Status')
    ImplementsWebApp = request.form.get('ImplementsWebApp')
    PublicFacingWebApp = request.form.get('PublicFacingWebApp')
    ImplementsAPI = request.form.get('ImplementsAPI')
    PublicFacingAPI = request.form.get('PublicFacingAPI')
    WebURL = request.form.get('WebURL')
    OpenAPISpecURL = request.form.get('OpenAPISpecURL')
    AuthType = request.form.get('AuthType')
    TestUsername = request.form.get('TestUsername')
    TestPasswordReference = request.form.get('TestPasswordReference')
    db.session.query(AppEnvironmentData).filter(text(f"AppEnvironmentData.ID={env_id}")).update(
        {
            AppEnvironmentData.AppID: app_id,
            AppEnvironmentData.EnvironmentName: EnvironmentName,
            AppEnvironmentData.EnvironmentClassification: EnvironmentClassification,
            AppEnvironmentData.Status: Status,
            AppEnvironmentData.ImplementsWebApp: ImplementsWebApp,
            AppEnvironmentData.PublicFacingWebApp: PublicFacingWebApp,
            AppEnvironmentData.ImplementsAPI: ImplementsAPI,
            AppEnvironmentData.PublicFacingAPI: PublicFacingAPI,
            AppEnvironmentData.WebURL: WebURL,
            AppEnvironmentData.OpenAPISpecURL: OpenAPISpecURL,
            AppEnvironmentData.AuthType: AuthType,
            AppEnvironmentData.TestUsername: TestUsername,
            AppEnvironmentData.TestPasswordReference: TestPasswordReference
        },
        synchronize_session=False)
    db_connection_handler(db)


@assets.route("/add_cicd_pipeline/<app_id>", methods=['GET', 'POST'])
@login_required
def add_cicd_pipeline(app_id):
    try:
        NAV['curpage'] = {"name": "Add CI/CD Pipeline Integration"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _add_page_permissions_filter(session, admin_role)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        sources = (
            AppIntegrations.query
                .with_entities(Integrations.ID, Integrations.Name, AppIntegrations.ID, AppIntegrations.AppEntity)
                .join(Integrations, Integrations.ID == AppIntegrations.IntegrationID)  # Explicit join condition
                .filter(text("Integrations.ToolType='Jenkins' AND AppIntegrations.AppID=:app_id").params(app_id=app_id))
                .first()
        )
        if request.method == 'POST':
            project_name = request.form.get('project_name')
            url = request.form.get('url')
            description = request.form.get('description')
            source = request.form.get('source')

            new_pipeline = CICDPipelines(
                ApplicationID=app_id,
                IntegrationID=sources[0],
                Name=project_name,
                Description=description,
                Url=url,
                Source="Jenkins"
            )
            db.session.add(new_pipeline)
            db_connection_handler(db)

            return redirect(url_for('vulns.all_cicd_pipelines', app_id=app_id))

        app = BusinessApplications.query.filter(text('ID=:app_id')).params(app_id=app_id).first()
        app_data = {'ID': app_id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}

        return render_template('assets/add_cicd_pipeline.html', app_data=app_data, user=user, NAV=NAV, all_sources=sources)
    except RuntimeError:
        return render_template('500.html'), 500


@assets.route("/all_cicd_pipelines/<app_id>")
@login_required
def all_cicd_pipelines(app_id):
    try:
        NAV['curpage'] = {"name": "All Application Environments"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        assets_all = CICDPipelines.query.filter(CICDPipelines.ApplicationID==app_id).all()
        schema = CICDPipelinesSchema(many=True)
        assets = schema.dump(
            filter(lambda t: t.ID != '', assets_all)
        )
        app = BusinessApplications.query.filter(text("ID=:app_id").params(app_id=app_id)).first()
        app_data = {'ID': app_id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
        NAV['appbar'] = 'settings'
        return render_template('assets/all_cicd_pipelines.html', entities=assets, user=user,
                               NAV=NAV, app_data=app_data)
    except RuntimeError:
        return render_template('500.html'), 500


@assets.route("/remove_cicd_pipeline", methods=['POST'])
@login_required
def remove_cicd_pipeline():
    try:
        NAV['curpage'] = {"name": "All Users"}
        role_req = ['Admin']
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        pipeline_id = request.form.get('pipeline_id')
        if not pipeline_id.isdigit():
            return render_template('400.html'), 400
        del_pair = CICDPipelines.query\
            .filter(CICDPipelines.ID == pipeline_id).first()
        if del_pair:
            db.session.delete(del_pair)
            db_connection_handler(db)
        rsp_json = {'status': 'success'}
        response = app.response_class(
            response=json.dumps(rsp_json),
            status=200,
            mimetype='application/json'
        )
        return response
    except RuntimeError:
        return render_template('500.html'), 500
