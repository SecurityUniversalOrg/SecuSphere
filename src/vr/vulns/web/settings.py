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
            _set_application_config(request, id)
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


def _set_application_config(request, app_id):
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
            BusinessApplications.Revenue: revenue
        },
        synchronize_session=False)
    db_connection_handler(db)


