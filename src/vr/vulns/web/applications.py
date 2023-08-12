from vr import db, app
from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, _add_page_permissions_filter
from sqlalchemy import text, desc, func, and_
from flask import request, render_template, session, redirect, url_for, send_file, Response
from flask_login import login_required
from vr.functions.table_functions import load_table, update_table
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema
from vr.vulns.model.applicationregulations import ApplicationRegulations
from vr.vulns.model.regulations import Regulations
from vr.vulns.model.integrations import Integrations
from vr.vulns.model.vulnerabilityslas import VulnerabilitySLAs
from vr.vulns.model.vulnerabilityslaapppair import VulnerabilitySLAAppPair
from vr.sourcecode.model.appcodecomposition import AppCodeComposition
from vr.sourcecode.model.servicetickets import ServiceTickets, ServiceTicketsSchema
from vr.assets.model.supportcontacts import SupportContacts, SupportContactsSchema, SupportContactsSchema
from vr.assets.model.apptosupportcontactassociations import AppToSupportContactAssociations
from vr.assets.model.apptoappassociations import AppToAppAssociations
from vr.assets.model.apptoserversandclusters import AppToServersAndClusters
from vr.assets.model.ipassets import IPAssets
from vr.assets.model.dbtoappassociations import DbToAppAssociations
from vr.assets.model.sudatabases import SUDatabases
from vr.vulns.model.assessmentbenchmarks import AssessmentBenchmarks
from vr.vulns.model.assessmentbenchmarkruleaudits import AssessmentBenchmarkRuleAudits
from vr.vulns.model.assessmentbenchmarkassessments import AssessmentBenchmarkAssessments
from vr.admin.functions import db_connection_handler
from vr.admin.models import User
from math import ceil
from io import BytesIO
from xhtml2pdf import pisa
import csv
from io import StringIO
from flask import Response
from datetime import datetime


NAV = {
    'CAT': { "name": "Applications", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"
APP_VIEWER = "Application Viewer"
ADMIN_LOGIN = 'admin.login'
UNAUTH_STATUS = "403.html"
SERVER_ERR_STATUS = "500.html"
VULN_OPEN_STATUS = "Vulnerabilities.Status NOT LIKE 'Closed-%' AND Vulnerabilities.Status NOT LIKE 'Open-RiskAccepted-%'"


@vulns.route("/all_applications", methods=['GET', 'POST'])
@login_required
def all_applications():
    app.logger.info('all_applications endpoint accessed')
    try:
        NAV['curpage'] = {"name": "All Applications"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req, permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        new_dict = {
            'db_name': 'BusinessApplications',
            "sort_field": "ApplicationName"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)
        sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='BusinessApplications.ID')

        assets_all = BusinessApplications.query.with_entities(
            BusinessApplications.ID,
            BusinessApplications.TechnologyID,
            BusinessApplications.ApplicationName,
            BusinessApplications.Version,
            BusinessApplications.Vendor,
            BusinessApplications.Language,
            BusinessApplications.InHouseDev,
            BusinessApplications.VendorDev,
            BusinessApplications.Customization,
            BusinessApplications.DatabaseName,
            BusinessApplications.AppValue,
            BusinessApplications.Owner,
            BusinessApplications.Custodian,
            BusinessApplications.Hosting,
            BusinessApplications.Description,
            BusinessApplications.PHI,
            BusinessApplications.PII,
            BusinessApplications.PCI,
            BusinessApplications.MiscCustomerData,
            BusinessApplications.Type,
            BusinessApplications.RegDate,
            BusinessApplications.Edition,
            BusinessApplications.WebEnabled,
            BusinessApplications.ApplicationURL,
            BusinessApplications.RepoURL,
            BusinessApplications.ApplicationType,
            BusinessApplications.ProductType,
            BusinessApplications.Lifecycle,
            BusinessApplications.Origin,
            BusinessApplications.UserRecords,
            BusinessApplications.Revenue,
            BusinessApplications.SysgenID,
            BusinessApplications.ApplicationAcronym,
            BusinessApplications.LctlAppID,
            BusinessApplications.Assignment,
            BusinessApplications.AssignmentChangedDate,
            BusinessApplications.LifecycleStatus,
            BusinessApplications.Disposition,
            BusinessApplications.TAWG,
            BusinessApplications.Criticality,
            BusinessApplications.PrioritizedForStability,
            BusinessApplications.BiaCritical,
            BusinessApplications.SoxCritical,
            BusinessApplications.Region,
            BusinessApplications.HostingPlatform,
            BusinessApplications.PrimaryLob,
            BusinessApplications.UsedByMultipleLob,
            BusinessApplications.MalListingAddDate,
            BusinessApplications.PreprodDate,
            BusinessApplications.ProductionDate,
            BusinessApplications.RetirementDate,
            BusinessApplications.TargetRetirementDate,
            BusinessApplications.AppSupportType,
            BusinessApplications.BusinessImpactDesc,
            BusinessApplications.WorkaroundDesc,
            BusinessApplications.AssetSystem,
            BusinessApplications.LogicalAccessControlUrl,
            BusinessApplications.MalAddReason,
            BusinessApplications.MalAddReasonDetails,
            BusinessApplications.SupportEngApprReq,
            BusinessApplications.QaActivelyTested,
            BusinessApplications.PrimaryProdUrl,
            BusinessApplications.AppMetricCat,
            BusinessApplications.OfficialBusinessRecord,
            BusinessApplications.RetentionPeriod,
            BusinessApplications.SubjectToLegalHold,
            BusinessApplications.EmployeeData,
            BusinessApplications.UserAccessRestrictions,
            BusinessApplications.UserAccessControl,
            BusinessApplications.PMUCNUSGOVT,
            BusinessApplications.RopaExists,
            BusinessApplications.AccountProvisionAndDeprovision,
            BusinessApplications.AccountProvisionSupportGrp,
            BusinessApplications.CicdStatus
        ) \
            .filter(text(sql_filter)) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)
        pg_cnt = ceil((assets_all.total / per_page))
        entity_details = {}
        for i in assets_all.items:
            entity_details[i.ID] = {'finding_cnt': 0, 'endpoint_cnt': 0}
        sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='Vulnerabilities.ApplicationId')
        sql_filter = f"({sql_filter}) AND ({VULN_OPEN_STATUS})"
        vuln_all = Vulnerabilities.query.filter(text(sql_filter)).all()
        for vuln in vuln_all:
            if vuln.ApplicationId in entity_details:
                entity_details[vuln.ApplicationId]['finding_cnt'] += 1
        sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='Vulnerabilities.ApplicationId')
        sql_filter = f"({sql_filter}) AND ({VULN_OPEN_STATUS})"
        endpoints_all = Vulnerabilities.query.with_entities(Vulnerabilities.Uri, Vulnerabilities.ApplicationId).filter(text("Vulnerabilities.Classification LIKE 'DAST%'")).filter(text(sql_filter)).filter(text(VULN_OPEN_STATUS)).group_by(Vulnerabilities.Uri, Vulnerabilities.ApplicationId).all()
        for pair in endpoints_all:
            if pair.ApplicationId in entity_details:
                entity_details[pair.ApplicationId]['endpoint_cnt'] += 1

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": assets_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < assets_all.total else assets_all.total
        }
        return render_template('all_applications.html', entity_details=entity_details, entities=assets_all.items, user=user,
                               NAV=NAV, table_details= table_details, app_data={"ID": 0})
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@vulns.route("/all_applications_filtered/<type>/<val>", methods=['GET', 'POST'])
@login_required
def all_applications_filtered(type, val):
    try:
        NAV['curpage'] = {"name": "All Applications"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req, permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        new_dict = {
            'db_name': 'BusinessApplications',
            "sort_field": "ApplicationName"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)
        sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='BusinessApplications.ID')

        sql_filter = f"({sql_filter}) AND ({type} LIKE '%{val}%')"

        assets_all = BusinessApplications.query.with_entities(
            BusinessApplications.ID,
            BusinessApplications.TechnologyID,
            BusinessApplications.ApplicationName,
            BusinessApplications.Version,
            BusinessApplications.Vendor,
            BusinessApplications.Language,
            BusinessApplications.InHouseDev,
            BusinessApplications.VendorDev,
            BusinessApplications.Customization,
            BusinessApplications.DatabaseName,
            BusinessApplications.AppValue,
            BusinessApplications.Owner,
            BusinessApplications.Custodian,
            BusinessApplications.Hosting,
            BusinessApplications.Description,
            BusinessApplications.PHI,
            BusinessApplications.PII,
            BusinessApplications.PCI,
            BusinessApplications.MiscCustomerData,
            BusinessApplications.Type,
            BusinessApplications.RegDate,
            BusinessApplications.Edition,
            BusinessApplications.WebEnabled,
            BusinessApplications.ApplicationURL,
            BusinessApplications.RepoURL,
            BusinessApplications.ApplicationType,
            BusinessApplications.ProductType,
            BusinessApplications.Lifecycle,
            BusinessApplications.Origin,
            BusinessApplications.UserRecords,
            BusinessApplications.Revenue,
            BusinessApplications.SysgenID,
            BusinessApplications.ApplicationAcronym,
            BusinessApplications.LctlAppID,
            BusinessApplications.Assignment,
            BusinessApplications.AssignmentChangedDate,
            BusinessApplications.LifecycleStatus,
            BusinessApplications.Disposition,
            BusinessApplications.TAWG,
            BusinessApplications.Criticality,
            BusinessApplications.PrioritizedForStability,
            BusinessApplications.BiaCritical,
            BusinessApplications.SoxCritical,
            BusinessApplications.Region,
            BusinessApplications.HostingPlatform,
            BusinessApplications.PrimaryLob,
            BusinessApplications.UsedByMultipleLob,
            BusinessApplications.MalListingAddDate,
            BusinessApplications.PreprodDate,
            BusinessApplications.ProductionDate,
            BusinessApplications.RetirementDate,
            BusinessApplications.TargetRetirementDate,
            BusinessApplications.AppSupportType,
            BusinessApplications.BusinessImpactDesc,
            BusinessApplications.WorkaroundDesc,
            BusinessApplications.AssetSystem,
            BusinessApplications.LogicalAccessControlUrl,
            BusinessApplications.MalAddReason,
            BusinessApplications.MalAddReasonDetails,
            BusinessApplications.SupportEngApprReq,
            BusinessApplications.QaActivelyTested,
            BusinessApplications.PrimaryProdUrl,
            BusinessApplications.AppMetricCat,
            BusinessApplications.OfficialBusinessRecord,
            BusinessApplications.RetentionPeriod,
            BusinessApplications.SubjectToLegalHold,
            BusinessApplications.EmployeeData,
            BusinessApplications.UserAccessRestrictions,
            BusinessApplications.UserAccessControl,
            BusinessApplications.PMUCNUSGOVT,
            BusinessApplications.RopaExists,
            BusinessApplications.AccountProvisionAndDeprovision,
            BusinessApplications.AccountProvisionSupportGrp,
            BusinessApplications.CicdStatus
        ) \
            .filter(text(sql_filter)) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)
        pg_cnt = ceil((assets_all.total / per_page))
        entity_details = {}
        for i in assets_all.items:
            entity_details[i.ID] = {'finding_cnt': 0, 'endpoint_cnt': 0}
        sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='Vulnerabilities.ApplicationId')
        sql_filter = f"({sql_filter}) AND ({VULN_OPEN_STATUS})"
        vuln_all = Vulnerabilities.query.filter(text(sql_filter)).all()
        for vuln in vuln_all:
            if vuln.ApplicationId in entity_details:
                entity_details[vuln.ApplicationId]['finding_cnt'] += 1
        sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='Vulnerabilities.ApplicationId')
        sql_filter = f"({sql_filter}) AND ({VULN_OPEN_STATUS})"
        endpoints_all = Vulnerabilities.query.with_entities(Vulnerabilities.Uri, Vulnerabilities.ApplicationId).filter(text("Vulnerabilities.Classification LIKE 'DAST%'")).filter(text(sql_filter)).filter(text(VULN_OPEN_STATUS)).group_by(Vulnerabilities.Uri, Vulnerabilities.ApplicationId).all()
        for pair in endpoints_all:
            if pair.ApplicationId in entity_details:
                entity_details[pair.ApplicationId]['endpoint_cnt'] += 1

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": assets_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < assets_all.total else assets_all.total
        }
        return render_template('all_applications.html', entity_details=entity_details, entities=assets_all.items, user=user,
                               NAV=NAV, table_details= table_details, app_data={"ID": 0})
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500



@vulns.route("/application/<component_id>/<app_type>/<entity_name>")
@login_required
def application(component_id, app_type, entity_name):
    try:
        data_map = _application_data_handler(component_id, app_type, entity_name)
        return render_template('application.html', regs_all=data_map['regs_all'], vuln_data=data_map['vuln_data'], app_data=data_map['app_data'],
                               sla_data=data_map['sla_data'], ld=data_map['ld'], color_wheel=data_map['color_wheel'],
                               user=data_map['user'], NAV=data_map['NAV'], contacts=data_map['contacts'], dependency_map=data_map['dependency_map'],
                               bm_assessments=data_map['bm_assessments'], app_type=app_type)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@vulns.route("/application/<id>/export")
@login_required
def application_export(id):
    data_map = _application_data_handler(id)

    now = datetime.utcnow()

    # Render the data in an HTML template for the PDF
    html = render_template('application_pdf.html', regs_all=data_map['regs_all'], vuln_data=data_map['vuln_data'], app_data=data_map['app_data'],
                               sla_data=data_map['sla_data'], ld=data_map['ld'], color_wheel=data_map['color_wheel'],
                               user=data_map['user'], NAV=data_map['NAV'], contacts=data_map['contacts'], dependency_map=data_map['dependency_map'],
                               bm_assessments=data_map['bm_assessments'], now=now)

    # Create a BytesIO buffer to store the generated PDF
    pdf_buffer = BytesIO()

    # Convert the HTML to PDF using xhtml2pdf
    pisa.CreatePDF(html, dest=pdf_buffer)

    # Reset the buffer's file pointer to the beginning
    pdf_buffer.seek(0)

    # Send the PDF as a file response
    response = send_file(pdf_buffer, as_attachment=True, download_name='report.pdf', mimetype='application/pdf')
    return response


@vulns.route("/application/<id>/csv")
@login_required
def application_csv(id):
    try:
        # Get the data
        data_map = _application_data_handler(id)

        now = datetime.utcnow()

        # Process the data and create the CSV
        csv_buffer = StringIO()
        csv_writer = csv.writer(csv_buffer)

        csv_writer.writerow(["Application Name", "Report Date"])
        headers = [data_map['app_data']['ApplicationName'], now]
        csv_writer.writerow(headers)
        csv_writer.writerow([])
        # Write headers
        csv_writer.writerow(["Vulnerability Findings By Severity"])
        headers = ["Total", "Informational", "Low", "Medium", "High", "Critical"]
        csv_writer.writerow(headers)

        row = [data_map['vuln_data']['total'], data_map['vuln_data']['informational'], data_map['vuln_data']['low'],
               data_map['vuln_data']['medium'], data_map['vuln_data']['high'], data_map['vuln_data']['critical']]
        csv_writer.writerow(row)

        # Write headers (customize these based on your data)
        csv_writer.writerow(["Vulnerability Findings By Assessment Type"])
        headers = ["Secret Scanning", "SCA", "SAST", "IaC", "Container", "DAST", "DAST API", "Infrastructure"]
        csv_writer.writerow(headers)

        row = [data_map['vuln_data']['secrets'], data_map['vuln_data']['sca'], data_map['vuln_data']['sast'],
               data_map['vuln_data']['iac'], data_map['vuln_data']['container'], data_map['vuln_data']['dast'],
               data_map['vuln_data']['dastapi'] if 'dastapi' in data_map['vuln_data'] else 0,
               data_map['vuln_data']['infrastructure'] if 'infrastructure' in data_map['vuln_data'] else 0]
        csv_writer.writerow(row)

        # Write headers (customize these based on your data)
        csv_writer.writerow(["Benchmark Assessment Results"])
        headers = ["Date", "Type", "Name", "Version", "Score"]
        csv_writer.writerow(headers)

        # Write data rows (customize these based on your data)
        for item in data_map['bm_assessments']:
            row = [item.AddDate, item.Type, item.Name, item.Version, item.findings_cnt]
            csv_writer.writerow(row)

        # Reset the buffer's file pointer to the beginning
        csv_buffer.seek(0)

        # Send the CSV as a file response
        response = Response(csv_buffer.getvalue(),
                            mimetype="text/csv",
                            headers={"Content-Disposition": "attachment;filename=report.csv"})
        return response
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


def _application_data_handler(id, app_type=None, entity_name=None):
    if app_type == 'App':
        NAV['curpage'] = {"name": "Application Details"}
    else:
        NAV['curpage'] = {"name": "Application Component Details"}
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
    if app_type == 'App':
        key = 'ApplicationName'
        val = entity_name
    else:
        key = 'ID'
        val = id
    filter_list = [f"{key} = '{val}'"]
    assets_all = BusinessApplications.query.filter(text("".join(filter_list))).all()
    schema = BusinessApplicationsSchema(many=True)
    assets = schema.dump(assets_all)
    if assets:
        response = assets[0]
    else:
        response = []
    if app_type == 'App':
        field_filter = f"BusinessApplications.ApplicationName='{entity_name}'"
        vuln_all = Vulnerabilities.query.filter(text(VULN_OPEN_STATUS)) \
            .join(BusinessApplications, Vulnerabilities.ApplicationId == BusinessApplications.ID, isouter=True) \
            .filter(text(field_filter)).all()
    else:
        field_filter = f"ApplicationId={id}"
        vuln_all = Vulnerabilities.query.filter(text(VULN_OPEN_STATUS)).filter(text(field_filter)).all()
    vuln_data = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0, 'total': 0, 'secrets': 0,
                 'sca': 0, 'sast': 0, 'iac': 0, 'container': 0, 'dast': 0, 'dastapi': 0}
    for vuln in vuln_all:
        severity = vuln.Severity
        if severity.lower() == 'critical':
            vuln_data['critical'] +=1
        elif severity.lower() == 'high':
            vuln_data['high'] +=1
        elif severity.lower() == 'medium':
            vuln_data['medium'] +=1
        elif severity.lower() == 'low':
            vuln_data['low'] +=1
        else:
            vuln_data['informational'] += 1
        vuln_data['total'] += 1
        vuln_type = vuln.Classification
        if vuln_type == 'Secret':
            vuln_data['secrets'] +=1
        elif vuln_type == 'SCA':
            vuln_data['sca'] += 1
        elif vuln_type == 'SAST':
            vuln_data['sast'] += 1
        elif vuln_type == 'IaC':
            vuln_data['iac'] += 1
        elif vuln_type == 'Container':
            vuln_data['container'] += 1
        elif vuln_type == 'DAST':
            vuln_data['dast'] += 1
        elif vuln_type == 'DASTAPI':
            vuln_data['dastapi'] += 1
    app_components = []
    if app_type == 'App':
        regs_all = ApplicationRegulations.query \
            .with_entities(ApplicationRegulations.ID, Regulations.ID, Regulations.Regulation,
                           Regulations.Acronym, Regulations.Category,
                           Regulations.Jurisdiction) \
            .join(Regulations, ApplicationRegulations.RegulationID == Regulations.ID, isouter=True) \
            .join(BusinessApplications, ApplicationRegulations.ApplicationID == BusinessApplications.ID, isouter=True) \
            .filter(text(field_filter)).all()
        sla_data = VulnerabilitySLAs.query \
            .with_entities(VulnerabilitySLAAppPair.ID, VulnerabilitySLAs.ID, VulnerabilitySLAs.Name,
                           VulnerabilitySLAs.Description, VulnerabilitySLAs.CriticalSetting,
                           VulnerabilitySLAs.HighSetting, VulnerabilitySLAs.MediumSetting, VulnerabilitySLAs.LowSetting) \
            .join(VulnerabilitySLAAppPair, VulnerabilitySLAAppPair.SlaID == VulnerabilitySLAs.ID, isouter=True) \
            .join(BusinessApplications, VulnerabilitySLAAppPair.ApplicationID == BusinessApplications.ID, isouter=True) \
            .filter(text(field_filter)).first()
        loc_data = AppCodeComposition.query \
            .join(BusinessApplications, AppCodeComposition.ApplicationID == BusinessApplications.ID, isouter=True) \
            .filter(text(field_filter)) \
            .order_by(desc(AppCodeComposition.AddDate)).first()
        ld = calculate_loc_stats(loc_data)
        color_wheel = {
            "JSON": 'green',
            "Javascript": 'red',
            "Python": 'blue',
            "YAML": 'yellow',
            "CONF": 'purple',
            "XML": 'grey'
        }
        contacts = SupportContacts.query \
            .with_entities(
            SupportContacts.ID,
            AppToSupportContactAssociations.AddDate,
            SupportContacts.Assignment,
            SupportContacts.CUID,
            SupportContacts.Name,
            SupportContacts.Email,
            SupportContacts.Role,

            BusinessApplications.ApplicationName
        ) \
            .join(AppToSupportContactAssociations,
                  AppToSupportContactAssociations.SupportContactID == SupportContacts.ID) \
            .join(BusinessApplications, AppToSupportContactAssociations.ApplicationID == BusinessApplications.ID,
                  isouter=True) \
            .filter(text(f"BusinessApplications.ApplicationName = '{entity_name}'")).all()

        ## Relationships
        # These apps depend on this app
        app2app_rels_downstream = AppToAppAssociations.query \
            .with_entities(
            AppToAppAssociations.ID,
            BusinessApplications.ApplicationName
        ) \
            .join(BusinessApplications, BusinessApplications.ID == AppToAppAssociations.AppIDB) \
            .filter(text(f"BusinessApplications.ApplicationName = '{entity_name}'")).all()
        app_components = BusinessApplications.query.with_entities(
            BusinessApplications.ID,
            BusinessApplications.ApplicationAcronym
        ).filter(text(f"BusinessApplications.ApplicationName = '{entity_name}'")).all()
        # This app depends on these apps
        app2app_rels_upstream = AppToAppAssociations.query \
            .with_entities(
            AppToAppAssociations.ID,
            BusinessApplications.ApplicationName
        ) \
            .join(BusinessApplications, BusinessApplications.ID == AppToAppAssociations.AppIDA) \
            .filter(text(f"BusinessApplications.ApplicationName = '{entity_name}'")).all()
        # Server and cluster dependencies
        app2server_rels = AppToServersAndClusters.query \
            .with_entities(
            AppToServersAndClusters.ID,
            IPAssets.ServerName,
            AppToServersAndClusters.EnvAssociation
        ) \
            .join(IPAssets, IPAssets.ID == AppToServersAndClusters.ServerID) \
            .join(BusinessApplications, BusinessApplications.ID == AppToServersAndClusters.ApplicationID) \
            .filter(text(f"BusinessApplications.ApplicationName = '{entity_name}'")).all()
        # Database dependencies
        app2db_rels = DbToAppAssociations.query \
            .with_entities(
            DbToAppAssociations.ID,
            SUDatabases.DatabaseName,
            DbToAppAssociations.Environment
        ) \
            .join(SUDatabases, SUDatabases.ID == DbToAppAssociations.DatabaseID) \
            .join(BusinessApplications, BusinessApplications.ID == DbToAppAssociations.ApplicationID) \
            .filter(text(f"BusinessApplications.ApplicationName = '{entity_name}'")).all()
        dependency_map = {
            "app2app_rels_downstream": app2app_rels_downstream,
            "app2app_rels_upstream": app2app_rels_upstream,
            "app2server_rels": app2server_rels,
            "app2db_rels": app2db_rels,
            "app_components": app_components
        }
        key = 'BusinessApplications.ApplicationName'
        val = entity_name
        filter_list = [f"{key} = '{val}'"]
        bm_assessments = AssessmentBenchmarkAssessments.query \
            .with_entities(
            AssessmentBenchmarks.Name,
            AssessmentBenchmarks.Version,
            AssessmentBenchmarkAssessments.ID,
            AssessmentBenchmarkAssessments.AddDate,
            AssessmentBenchmarkAssessments.Type,
            User.username,
            func.count(AssessmentBenchmarkRuleAudits.ID).label('findings_cnt')
        ) \
            .join(AssessmentBenchmarks, AssessmentBenchmarkAssessments.BenchmarkID == AssessmentBenchmarks.ID,
                  isouter=True) \
            .join(User, AssessmentBenchmarkAssessments.UserID == User.id, isouter=True) \
            .join(AssessmentBenchmarkRuleAudits,
                  and_(AssessmentBenchmarkRuleAudits.AssessmentID == AssessmentBenchmarkAssessments.ID,
                       AssessmentBenchmarkRuleAudits.PassingLevels != ""), isouter=True) \
            .join(BusinessApplications, AssessmentBenchmarkAssessments.ApplicationID == BusinessApplications.ID,
                  isouter=True) \
            .group_by(AssessmentBenchmarkAssessments.ID) \
            .filter(text("".join(filter_list))) \
            .all()
    else:
        regs_all = ApplicationRegulations.query\
            .with_entities(ApplicationRegulations.ID, Regulations.ID, Regulations.Regulation,
                           Regulations.Acronym, Regulations.Category,
                           Regulations.Jurisdiction)\
            .join(Regulations, ApplicationRegulations.RegulationID==Regulations.ID, isouter=True)\
            .filter(text(f"ApplicationRegulations.ApplicationID={id}")).all()
        sla_data = VulnerabilitySLAs.query\
            .with_entities(VulnerabilitySLAAppPair.ID, VulnerabilitySLAs.ID, VulnerabilitySLAs.Name,
                           VulnerabilitySLAs.Description, VulnerabilitySLAs.CriticalSetting,
                           VulnerabilitySLAs.HighSetting, VulnerabilitySLAs.MediumSetting, VulnerabilitySLAs.LowSetting)\
            .join(VulnerabilitySLAAppPair, VulnerabilitySLAAppPair.SlaID==VulnerabilitySLAs.ID, isouter=True)\
            .filter(text(f"VulnerabilitySLAAppPair.ApplicationID={id}")).first()
        loc_data = AppCodeComposition.query \
            .filter(text(f"AppCodeComposition.ApplicationID={id}"))\
            .order_by(desc(AppCodeComposition.AddDate)).first()
        ld = calculate_loc_stats(loc_data)
        color_wheel = {
            "JSON": 'green',
            "Javascript": 'red',
            "Python": 'blue',
            "YAML": 'yellow',
            "CONF": 'purple',
            "XML": 'grey'
        }
        contacts = SupportContacts.query \
            .with_entities(
            SupportContacts.ID,
            AppToSupportContactAssociations.AddDate,
            SupportContacts.Assignment,
            SupportContacts.CUID,
            SupportContacts.Name,
            SupportContacts.Email,
            SupportContacts.Role,

            BusinessApplications.ApplicationName
        ) \
            .join(AppToSupportContactAssociations, AppToSupportContactAssociations.SupportContactID == SupportContacts.ID) \
            .join(BusinessApplications, AppToSupportContactAssociations.ApplicationID == BusinessApplications.ID,
                  isouter=True) \
            .filter(text("".join([f"BusinessApplications.ID = '{id}'"]))).all()

        ## Relationships
        # These apps depend on this app
        app2app_rels_downstream = AppToAppAssociations.query \
            .with_entities(
            AppToAppAssociations.ID,
            BusinessApplications.ApplicationName
        )\
            .join(BusinessApplications, BusinessApplications.ID==AppToAppAssociations.AppIDB)\
            .filter(text("".join([f"AppToAppAssociations.AppIDA = '{id}'"]))).all()
        # This app depends on these apps
        app2app_rels_upstream = AppToAppAssociations.query \
            .with_entities(
            AppToAppAssociations.ID,
            BusinessApplications.ApplicationName
        ) \
            .join(BusinessApplications, BusinessApplications.ID == AppToAppAssociations.AppIDA) \
            .filter(text("".join([f"AppToAppAssociations.AppIDB = '{id}'"]))).all()
        # Server and cluster dependencies
        app2server_rels = AppToServersAndClusters.query \
            .with_entities(
            AppToServersAndClusters.ID,
            IPAssets.ServerName,
            AppToServersAndClusters.EnvAssociation
        ) \
            .join(IPAssets, IPAssets.ID == AppToServersAndClusters.ServerID) \
            .filter(text("".join([f"AppToServersAndClusters.ApplicationID = '{id}'"]))).all()
        # Database dependencies
        app2db_rels = DbToAppAssociations.query \
            .with_entities(
            DbToAppAssociations.ID,
            SUDatabases.DatabaseName,
            DbToAppAssociations.Environment
        ) \
            .join(SUDatabases, SUDatabases.ID == DbToAppAssociations.DatabaseID) \
            .filter(text("".join([f"DbToAppAssociations.ApplicationID = '{id}'"]))).all()
        dependency_map = {
            "app2app_rels_downstream": app2app_rels_downstream,
            "app2app_rels_upstream": app2app_rels_upstream,
            "app2server_rels": app2server_rels,
            "app2db_rels": app2db_rels,
            "app_components": app_components
        }
        key = 'AssessmentBenchmarkAssessments.ApplicationID'
        val = id
        filter_list = [f"{key} = '{val}'"]
        bm_assessments = AssessmentBenchmarkAssessments.query \
            .with_entities(
            AssessmentBenchmarks.Name,
            AssessmentBenchmarks.Version,
            AssessmentBenchmarkAssessments.ID,
            AssessmentBenchmarkAssessments.AddDate,
            AssessmentBenchmarkAssessments.Type,
            User.username,
            func.count(AssessmentBenchmarkRuleAudits.ID).label('findings_cnt')
        ) \
            .join(AssessmentBenchmarks, AssessmentBenchmarkAssessments.BenchmarkID == AssessmentBenchmarks.ID, isouter=True) \
            .join(User, AssessmentBenchmarkAssessments.UserID == User.id, isouter=True) \
            .join(AssessmentBenchmarkRuleAudits,
                  and_(AssessmentBenchmarkRuleAudits.AssessmentID == AssessmentBenchmarkAssessments.ID,
                       AssessmentBenchmarkRuleAudits.PassingLevels != ""), isouter=True) \
            .group_by(AssessmentBenchmarkAssessments.ID) \
            .filter(text("".join(filter_list))) \
            .all()
    NAV['appbar'] = 'application'
    data_map = {
        "regs_all": regs_all,
        "vuln_data": vuln_data,
        "app_data": response,
        "sla_data": sla_data,
        "ld": ld,
        "color_wheel": color_wheel,
        "user": user,
        "NAV": NAV,
        "contacts": contacts,
        "dependency_map": dependency_map,
        "bm_assessments": bm_assessments
    }
    NAV['CAT']['url'] = '/all_applications'
    return data_map


def calculate_loc_stats(ld):
    tot_files = 0
    tot_loc = 0
    active_languages = []
    if ld:
        tot_loc, active_languages, tot_files = _parse_languages(ld, tot_files, active_languages, tot_loc)
    sorted_active_languages = sorted(active_languages, key=lambda d: d[list(d.keys())[0]], reverse=True)
    return {"total_files": tot_files, "total_loc": tot_loc, "active_languages": sorted_active_languages}


def _parse_languages(ld, tot_files, active_languages, tot_loc):
    if ld.CFiles:
        tot_files += ld.CFiles
    if ld.GoFiles:
        tot_files += ld.GoFiles
    if ld.JavaFiles:
        tot_files += ld.JavaFiles
    if ld.JavascriptFiles:
        tot_files += ld.JavascriptFiles
    if ld.PerlFiles:
        tot_files += ld.PerlFiles
    if ld.PythonFiles:
        tot_files += ld.PythonFiles
    if ld.CLoc:
        tot_loc += ld.CLoc
        active_languages.append({"C": ld.Cloc})
    if ld.GoLoc:
        tot_loc += ld.GoLoc
        active_languages.append({"Go": ld.GoLoc})
    if ld.JavaLoc:
        tot_loc += ld.JavaLoc
        active_languages.append({"Java": ld.JavaLoc})
    if ld.JavascriptLoc:
        tot_loc += ld.JavascriptLoc
        active_languages.append({"Javascript": ld.JavascriptLoc})
    if ld.PerlLoc:
        tot_loc += ld.PerlLoc
        active_languages.append({"Perl": ld.PerlLoc})
    if ld.PythonLoc:
        tot_loc += ld.PythonLoc
        active_languages.append({"Python": ld.PythonLoc})
    return tot_loc, active_languages, tot_files


@vulns.route("/add_application", methods=['GET', 'POST'])
@login_required
def add_application():
    try:
        NAV['curpage'] = {"name": "Add Application"}
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
            new_app, app_name, sla_configuration, regulations = _setup_new_app(request)
            db.session.add(new_app)
            db_connection_handler(db)
            new_sla = VulnerabilitySLAAppPair(
                ApplicationID = new_app.ID,
                SlaID = sla_configuration
            )
            db.session.add(new_sla)
            db_connection_handler(db)
            for i in regulations.split(','):
                new_reg = ApplicationRegulations(
                    ApplicationID = new_app.ID,
                    RegulationID = i
                )
                db.session.add(new_reg)
                db_connection_handler(db)

            all_integrations = Integrations.query.all()
            return render_template('add_application_integrations.html', user=user, NAV=NAV, new_app_name=app_name,
                                   all_integrations=all_integrations, new_id=new_app.ID)
        product_types = ['Billing', 'Commerce', 'Internal', 'Research and Development', 'Security']
        all_slas = VulnerabilitySLAs.query.all()
        all_regs = Regulations.query.all()

        return render_template('add_application.html', user=user, NAV=NAV, product_types=product_types, all_slas=all_slas,
                               all_regs=all_regs)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


def _setup_new_app(request):
    now = datetime.utcnow()
    app_name = request.form.get('name')
    component_name = request.form.get('component_name')
    component_type = request.form.get('component_type')
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
    sla_configuration = request.form.get('sla_configuration')
    regulations = request.form.get('regulations')
    new_app = BusinessApplications(
        ApplicationName=app_name,
        ApplicationAcronym=component_name,
        Description=description,
        AppValue=app_value,
        Version=version,
        InHouseDev=1 if origin == 'internal' else 0,
        VendorDev=0 if origin == 'internal' else 1,
        Customization=1,
        PHI=1 if 'PHI' in data_types else 0,
        PII=1 if 'PII' in data_types else 0,
        PCI=1 if 'PCI' in data_types else 0,
        MiscCustomerData=1 if 'MiscCustomerData' in data_types else 0,
        Type=component_type,
        WebEnabled=1 if internet_access == 'on' else 0,
        RepoURL=repo_url,
        ApplicationType=platform,
        ProductType=prod_type,
        Lifecycle=lifecycle,
        Origin=origin,
        UserRecords=user_records,
        Revenue=revenue,
        AssignmentChangedDate=now,
        RegDate=now,
        MalListingAddDate=now
    )
    return new_app, app_name, sla_configuration, regulations


@vulns.route("/application_issues/<id>", methods=['GET', 'POST'])
@login_required
def application_issues(id):
    try:
        NAV['curpage'] = {"name": "Application Issues"}
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

        key = 'BusinessApplications.ID'
        val = id
        filter_list = [f"{key} = '{val}'"]

        new_dict = {
            'db_name': 'ServiceTickets',
            "sort_field": "ID"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict, direction="desc")
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict, direction="desc")

        assets_all = ServiceTickets.query \
            .with_entities(ServiceTickets.ID, ServiceTickets.TicketName, ServiceTickets.AddDate,
                           ServiceTickets.Source, ServiceTickets.Status, BusinessApplications.ApplicationName) \
            .join(BusinessApplications, BusinessApplications.ID == ServiceTickets.AppID, isouter=True) \
            .filter(text("".join(filter_list))) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((assets_all.total / per_page))
        schema = ServiceTicketsSchema(many=True)
        assets = schema.dump(assets_all.items)

        NAV['appbar'] = 'workflows'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": assets_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < assets_all.total else assets_all.total
        }

        return render_template('application_issues.html', entities=assets, app_data=app_data, user=user, NAV=NAV,
                               table_details=table_details)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@vulns.route("/delete_application/<id>")
@login_required
def delete_application(id):
    try:
        NAV['curpage'] = {"name": "Delete Issue Note"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        app = BusinessApplications.query.filter(text(f"ID={id}")).first()
        if app:
            db.session.delete(app)
            db_connection_handler(db)
            return redirect(url_for('vulns.all_applications'))
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)

