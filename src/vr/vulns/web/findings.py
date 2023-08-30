from vr import db, app
import datetime
from math import ceil
from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, check_if_jira_enabled
from vr.admin.models import User, Messages, MessagesStatus
from sqlalchemy import text, and_
from flask import request, render_template, session, redirect, url_for, send_file
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.functions.table_functions import load_table, update_table
from vr.vulns.model.vulnerabilities import Vulnerabilities, VulnerabilitiesSchema
from vr.vulns.model.vulnerabilityslas import VulnerabilitySLAs
from vr.vulns.model.vulnerabilityslaapppair import VulnerabilitySLAAppPair
from vr.orchestration.model.dockerimages import DockerImages
from vr.sourcecode.model.importedcode import ImportedCode
from vr.vulns.model.issuenotes import IssueNotes
from vr.assets.model.applicationendpoints import ApplicationEndpoints
from vr.vulns.model.vulnerabilityscans import VulnerabilityScans
from vr.admin.functions import db_connection_handler
from io import BytesIO
from xhtml2pdf import pisa
import csv
import base64
from io import StringIO
from flask import Response
from config_engine import ENV
from vr.functions.ml_functions import predict_vuln_validity
from vr.vulns.model.cvssbasescoresv3 import CVSSBaseScoresV3
from vr.vulns.model.cvssbasescoresv3extensions import CVSSBaseScoresV3Extensions
from vr.vulns.model.cwedetails import CWEDetails


NAV = {
    'CAT': { "name": "Vulnerabilities", "url": "sourcecode.dashboard"}
}
OPEN_FINDINGS = 'Open Findings'
APP_ADMIN = "Application Admin"
APP_VIEWER = "Application Viewer"
ADMIN_LOGIN = "admin.login"
UNAUTH_STATUS = "403.html"
SERVER_ERR_STATUS = "500.html"
VULN_STATUS_IS_NOT_CLOSED = "Vulnerabilities.Status NOT LIKE 'Closed-%' AND Vulnerabilities.Status NOT LIKE 'Open-RiskAccepted-%'"
test = ENV
if test == 'test':
    ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
else:
    ISO_FORMAT = '%Y-%m-%dT%H:%M:%S'
ISO_FORMAT_BASE = '%Y-%m-%dT%H:%M:%S'


@vulns.route("/open_findings/<id>", methods=['GET', 'POST'])
@login_required
def open_findings(id):
    NAV['curpage'] = {"name": OPEN_FINDINGS}
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

    key = 'ApplicationId'
    val = id
    filter_list = [f"{key} = '{val}'"]

    new_dict = {
        'db_name': 'Vulnerabilities',
        "sort_field": "VulnerabilityID"
    }
    if request.method == 'POST':
        # sort
        page, per_page, orderby_dict, orderby = update_table(request, new_dict)
    else:
        page, per_page, orderby_dict, orderby = load_table(new_dict)
    vuln_all = Vulnerabilities\
        .query \
        .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
        .filter(text("".join(filter_list))) \
        .order_by(text(orderby)) \
        .yield_per(per_page) \
        .paginate(page=page, per_page=per_page, error_out=False)

    pg_cnt = ceil((vuln_all.total / per_page))
    schema = VulnerabilitiesSchema(many=True)
    assets = schema.dump(vuln_all.items)
    sla_policy = VulnerabilitySLAAppPair.query.with_entities(
        VulnerabilitySLAAppPair.ID, VulnerabilitySLAs.CriticalSetting, VulnerabilitySLAs.HighSetting,
        VulnerabilitySLAs.MediumSetting, VulnerabilitySLAs.LowSetting
    )\
        .join(VulnerabilitySLAs, VulnerabilitySLAs.ID==VulnerabilitySLAAppPair.SlaID)\
        .filter(text(f'ApplicationID={id}')).first()
    NAV['appbar'] = 'findings'
    app = BusinessApplications.query.filter(text(f'ID={id}')).first()
    app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
    now = datetime.datetime.utcnow()
    vulns = []
    for vuln in assets:
        try:
            time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT)).days
        except:
            time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT_BASE)).days
        severity = vuln['Severity']
        if severity == 'Critical':
            sla = sla_policy[1]
        elif severity == 'High':
            sla = sla_policy[2]
        elif severity == 'Medium':
            sla = sla_policy[3]
        else:
            sla = sla_policy[4]
        sla_status = int(sla) - time_since_found
        vuln['SLAStatus'] = sla_status
        vulns.append(vuln)
    table_details = {
        "pg_cnt": pg_cnt,
        "page": int(page),
        "item_tot": vuln_all.total,
        "per_page": per_page,
        "orderby": orderby,
        "rec_start": (int(page)-1) * per_page + 1 if int(page) != 1 else 1,
        "rec_end": int(page) * per_page if (int(page) * per_page) < vuln_all.total else vuln_all.total
    }

    return render_template('vulns/open_findings.html', entities=assets, app_data=app_data, user=user, NAV=NAV,
                           sla_policy=sla_policy, table_details= table_details)


@vulns.route("/open_findings/<id>/export", methods=['GET', 'POST'])
@login_required
def open_findings_export(id):
    NAV['curpage'] = {"name": OPEN_FINDINGS}
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

    key = 'ApplicationId'
    val = id
    filter_list = [f"{key} = '{val}'"]
    new_dict = {
        'db_name': 'Vulnerabilities',
        "sort_field": "VulnerabilityID"
    }
    if request.method == 'POST':
        # sort
        page, per_page, orderby_dict, orderby = update_table(request, new_dict)
    else:
        page, per_page, orderby_dict, orderby = load_table(new_dict)
    per_page = 10000  # limit for performance
    vuln_all = Vulnerabilities\
        .query \
        .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
        .filter(text("".join(filter_list))) \
        .order_by(text(orderby)) \
        .yield_per(per_page) \
        .paginate(page=page, per_page=per_page, error_out=False)
    pg_cnt = ceil((vuln_all.total / per_page))
    schema = VulnerabilitiesSchema(many=True)
    assets = schema.dump(vuln_all.items)
    sla_policy = VulnerabilitySLAAppPair.query.with_entities(
        VulnerabilitySLAAppPair.ID, VulnerabilitySLAs.CriticalSetting, VulnerabilitySLAs.HighSetting,
        VulnerabilitySLAs.MediumSetting, VulnerabilitySLAs.LowSetting
    )\
        .join(VulnerabilitySLAs, VulnerabilitySLAs.ID==VulnerabilitySLAAppPair.SlaID)\
        .filter(text(f'ApplicationID={id}')).first()
    NAV['appbar'] = 'findings'
    app = BusinessApplications.query.filter(text(f'ID={id}')).first()
    app_data = {'ID': id, 'ApplicationName': app.ApplicationName}
    now = datetime.datetime.utcnow()
    vulns = []
    for vuln in assets:
        try:
            time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT)).days
        except:
            time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT_BASE)).days
        severity = vuln['Severity']
        if severity == 'Critical':
            sla = sla_policy[1]
        elif severity == 'High':
            sla = sla_policy[2]
        elif severity == 'Medium':
            sla = sla_policy[3]
        else:
            sla = sla_policy[4]
        sla_status = int(sla) - time_since_found
        vuln['SLAStatus'] = sla_status
        vulns.append(vuln)
    table_details = {
        "pg_cnt": pg_cnt,
        "page": int(page),
        "item_tot": vuln_all.total,
        "per_page": per_page,
        "orderby": orderby,
        "rec_start": (int(page)-1) * per_page + 1 if int(page) != 1 else 1,
        "rec_end": int(page) * per_page if (int(page) * per_page) < vuln_all.total else vuln_all.total
    }
    now = datetime.datetime.utcnow()
    html = render_template('vulns/open_findings_pdf.html', now=now, entities=assets, app_data=app_data, user=user, NAV=NAV, sla_policy=sla_policy, table_details= table_details)
    # Create a BytesIO buffer to store the generated PDF
    pdf_buffer = BytesIO()

    # Convert the HTML to PDF using xhtml2pdf
    cmd_options = {
        '--orientation': 'Landscape'
    }
    pisa.CreatePDF(html, dest=pdf_buffer, options=cmd_options)

    # Reset the buffer's file pointer to the beginning
    pdf_buffer.seek(0)

    # Send the PDF as a file response
    response = send_file(pdf_buffer, as_attachment=True, download_name='report.pdf', mimetype='application/pdf')
    return response


@vulns.route("/open_findings/<id>/csv", methods=['GET', 'POST'])
@login_required
def open_findings_csv(id):
    NAV['curpage'] = {"name": OPEN_FINDINGS}
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

    key = 'ApplicationId'
    val = id
    filter_list = [f"{key} = '{val}'"]
    new_dict = {
        'db_name': 'Vulnerabilities',
        "sort_field": "VulnerabilityID"
    }
    if request.method == 'POST':
        # sort
        page, per_page, orderby_dict, orderby = update_table(request, new_dict)
    else:
        page, per_page, orderby_dict, orderby = load_table(new_dict)
    per_page = 10000  # limit for performance
    vuln_all = Vulnerabilities\
        .query \
        .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
        .filter(text("".join(filter_list))) \
        .order_by(text(orderby)) \
        .yield_per(per_page) \
        .paginate(page=page, per_page=per_page, error_out=False)
    schema = VulnerabilitiesSchema(many=True)
    assets = schema.dump(vuln_all.items)
    sla_policy = VulnerabilitySLAAppPair.query.with_entities(
        VulnerabilitySLAAppPair.ID, VulnerabilitySLAs.CriticalSetting, VulnerabilitySLAs.HighSetting,
        VulnerabilitySLAs.MediumSetting, VulnerabilitySLAs.LowSetting
    )\
        .join(VulnerabilitySLAs, VulnerabilitySLAs.ID==VulnerabilitySLAAppPair.SlaID)\
        .filter(text(f'ApplicationID={id}')).first()
    NAV['appbar'] = 'findings'
    app = BusinessApplications.query.filter(text(f'ID={id}')).first()
    now = datetime.datetime.utcnow()
    vulns = []
    for vuln in assets:
        try:
            time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT)).days
        except:
            time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT_BASE)).days
        severity = vuln['Severity']
        if severity == 'Critical':
            sla = sla_policy[1]
        elif severity == 'High':
            sla = sla_policy[2]
        elif severity == 'Medium':
            sla = sla_policy[3]
        else:
            sla = sla_policy[4]
        sla_status = int(sla) - time_since_found
        vuln['SLAStatus'] = sla_status
        vulns.append(vuln)

    # Process the data and create the CSV
    csv_buffer = StringIO()
    csv_writer = csv.writer(csv_buffer)

    headers = ["Severity", "Name", "CWE", "CVE", "AddDate", "FoundBy", "Status", "Resource Type", "Resource"]
    csv_writer.writerow(headers)

    for vuln in assets:
        if vuln['Classification'].startswith("Secret") or vuln['Classification'] == 'SAST' or vuln['Classification'].startswith("IaC"):
            resource_type = 'File'
        elif vuln['Classification'].startswith("Container"):
            resource_type = 'Container Library'
        elif vuln['Classification'] == "SCA":
            resource_type = 'Source Code Library'
        elif vuln['Classification'] == "DAST":
            resource_type = 'URI'
        else:
            resource_type = 'Unknown'

        if vuln['Classification'].startswith("Secret") or vuln['Classification'] == 'SAST' or vuln['Classification'].startswith("IaC"):
            resource = vuln['VulnerableFileName']
            if vuln['SourceCodeFileStartLine']:
                resource = resource + f":{vuln['SourceCodeFileStartLine']}"
            if vuln['SourceCodeFileEndLine']:
                resource = resource + f":{vuln['SourceCodeFileEndLine']}"
        elif vuln['Classification'].startswith("Container") or vuln['Classification'] == 'SCA':
            resource = vuln['VulnerablePackage']
        elif vuln['Classification'] == "DAST":
            resource = vuln['Uri']
        row = [vuln['Severity'], vuln['VulnerabilityName'], vuln['CWEID'], vuln['CVEID'], vuln['ReleaseDate'], vuln['Source'], vuln['Status'],
               resource_type, resource]
        csv_writer.writerow(row)

    # Reset the buffer's file pointer to the beginning
    csv_buffer.seek(0)

    # Send the CSV as a file response
    response = Response(csv_buffer.getvalue(),
                        mimetype="text/csv",
                        headers={"Content-Disposition": "attachment;filename=report.csv"})
    return response


@vulns.route("/open_findings_for_scan/<appid>/<id>", methods=['GET', 'POST'])
@login_required
def open_findings_for_scan(appid, id):
    try:
        NAV['curpage'] = {"name": OPEN_FINDINGS}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)

        key = 'InitialScanId'
        val = id
        filter_list = [f"{key} = '{val}'"]
        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)
        vuln_all = Vulnerabilities\
            .query \
            .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
            .filter(text("".join(filter_list))) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)
        pg_cnt = ceil((vuln_all.total / per_page))
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all.items)
        sla_policy = VulnerabilitySLAAppPair.query.with_entities(
            VulnerabilitySLAAppPair.ID, VulnerabilitySLAs.CriticalSetting, VulnerabilitySLAs.HighSetting,
            VulnerabilitySLAs.MediumSetting, VulnerabilitySLAs.LowSetting
        )\
            .join(VulnerabilitySLAs, VulnerabilitySLAs.ID==VulnerabilitySLAAppPair.SlaID)\
            .filter(text(f'ApplicationID={appid}')).first()
        NAV['appbar'] = 'findings'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName}
        now = datetime.datetime.utcnow()
        vulns = []
        for vuln in assets:
            try:
                time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT)).days
            except:
                time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT_BASE)).days
            severity = vuln['Severity']
            if severity == 'Critical':
                sla = sla_policy[1]
            elif severity == 'High':
                sla = sla_policy[2]
            elif severity == 'Medium':
                sla = sla_policy[3]
            else:
                sla = sla_policy[4]
            sla_status = int(sla) - time_since_found
            vuln['SLAStatus'] = sla_status
            vulns.append(vuln)
        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": vuln_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page)-1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < vuln_all.total else vuln_all.total
        }
        scan = VulnerabilityScans.query.filter(text(f'ID={id}')).first()
        return render_template('vulns/open_findings_for_scan.html', entities=assets, app_data=app_data, user=user, NAV=NAV,
                               sla_policy=sla_policy, table_details= table_details, scan=scan)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)


@vulns.route("/open_findings_for_scan/<appid>/<id>/export", methods=['GET', 'POST'])
@login_required
def open_findings_for_scan_export(appid, id):
    try:
        NAV['curpage'] = {"name": OPEN_FINDINGS}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)

        key = 'InitialScanId'
        val = id
        filter_list = [f"{key} = '{val}'"]
        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)
        per_page = 10000  # limit for performance
        vuln_all = Vulnerabilities\
            .query \
            .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
            .filter(text("".join(filter_list))) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)
        pg_cnt = ceil((vuln_all.total / per_page))
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all.items)
        sla_policy = VulnerabilitySLAAppPair.query.with_entities(
            VulnerabilitySLAAppPair.ID, VulnerabilitySLAs.CriticalSetting, VulnerabilitySLAs.HighSetting,
            VulnerabilitySLAs.MediumSetting, VulnerabilitySLAs.LowSetting
        )\
            .join(VulnerabilitySLAs, VulnerabilitySLAs.ID==VulnerabilitySLAAppPair.SlaID)\
            .filter(text(f'ApplicationID={appid}')).first()
        NAV['appbar'] = 'findings'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName}
        now = datetime.datetime.utcnow()
        vulns = []
        for vuln in assets:
            try:
                time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT)).days
            except:
                time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT_BASE)).days
            severity = vuln['Severity']
            if severity == 'Critical':
                sla = sla_policy[1]
            elif severity == 'High':
                sla = sla_policy[2]
            elif severity == 'Medium':
                sla = sla_policy[3]
            else:
                sla = sla_policy[4]
            sla_status = int(sla) - time_since_found
            vuln['SLAStatus'] = sla_status
            vulns.append(vuln)
        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": vuln_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page)-1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < vuln_all.total else vuln_all.total
        }
        scan = VulnerabilityScans.query.filter(text(f'ID={id}')).first()
        now = datetime.datetime.utcnow()
        html = render_template('vulns/open_findings_pdf.html', now=now, entities=assets, app_data=app_data, user=user, NAV=NAV,
                               sla_policy=sla_policy, table_details= table_details, scan=scan)
        # Create a BytesIO buffer to store the generated PDF
        pdf_buffer = BytesIO()

        # Convert the HTML to PDF using xhtml2pdf
        cmd_options = {
            '--orientation': 'Landscape'
        }
        pisa.CreatePDF(html, dest=pdf_buffer, options=cmd_options)

        # Reset the buffer's file pointer to the beginning
        pdf_buffer.seek(0)

        # Send the PDF as a file response
        response = send_file(pdf_buffer, as_attachment=True, download_name='report.pdf', mimetype='application/pdf')
        return response
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)


@vulns.route("/open_findings_for_scan/<appid>/<id>/csv", methods=['GET', 'POST'])
@login_required
def open_findings_for_scan_csv(appid, id):
    try:
        NAV['curpage'] = {"name": OPEN_FINDINGS}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)

        key = 'InitialScanId'
        val = id
        filter_list = [f"{key} = '{val}'"]
        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)
        per_page = 10000  # limit for performance
        vuln_all = Vulnerabilities\
            .query \
            .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
            .filter(text("".join(filter_list))) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all.items)
        sla_policy = VulnerabilitySLAAppPair.query.with_entities(
            VulnerabilitySLAAppPair.ID, VulnerabilitySLAs.CriticalSetting, VulnerabilitySLAs.HighSetting,
            VulnerabilitySLAs.MediumSetting, VulnerabilitySLAs.LowSetting
        )\
            .join(VulnerabilitySLAs, VulnerabilitySLAs.ID==VulnerabilitySLAAppPair.SlaID)\
            .filter(text(f'ApplicationID={appid}')).first()
        NAV['appbar'] = 'findings'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
        now = datetime.datetime.utcnow()
        vulns = []
        for vuln in assets:
            try:
                time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT)).days
            except:
                time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT_BASE)).days
            severity = vuln['Severity']
            if severity == 'Critical':
                sla = sla_policy[1]
            elif severity == 'High':
                sla = sla_policy[2]
            elif severity == 'Medium':
                sla = sla_policy[3]
            else:
                sla = sla_policy[4]
            sla_status = int(sla) - time_since_found
            vuln['SLAStatus'] = sla_status
            vulns.append(vuln)

        # Process the data and create the CSV
        csv_buffer = StringIO()
        csv_writer = csv.writer(csv_buffer)

        headers = ["Severity", "Name", "CWE", "CVE", "AddDate", "FoundBy", "Status", "Resource Type", "Resource"]
        csv_writer.writerow(headers)

        for vuln in assets:
            if vuln['Classification'].startswith("Secret") or vuln['Classification'] == 'SAST' or vuln[
                'Classification'].startswith("IaC"):
                resource_type = 'File'
            elif vuln['Classification'].startswith("Container"):
                resource_type = 'Container Library'
            elif vuln['Classification'] == "SCA":
                resource_type = 'Source Code Library'
            elif vuln['Classification'] == "DAST":
                resource_type = 'URI'
            else:
                resource_type = 'Unknown'

            if vuln['Classification'].startswith("Secret") or vuln['Classification'] == 'SAST' or vuln[
                'Classification'].startswith("IaC"):
                resource = vuln['VulnerableFileName']
                if vuln['SourceCodeFileStartLine']:
                    resource = resource + f":{vuln['SourceCodeFileStartLine']}"
                if vuln['SourceCodeFileEndLine']:
                    resource = resource + f":{vuln['SourceCodeFileEndLine']}"
            elif vuln['Classification'].startswith("Container") or vuln['Classification'] == 'SCA':
                resource = vuln['VulnerablePackage']
            elif vuln['Classification'] == "DAST":
                resource = vuln['Uri']
            row = [vuln['Severity'], vuln['VulnerabilityName'], vuln['CWEID'], vuln['CVEID'], vuln['ReleaseDate'],
                   vuln['Source'], vuln['Status'],
                   resource_type, resource]
            csv_writer.writerow(row)

        # Reset the buffer's file pointer to the beginning
        csv_buffer.seek(0)

        # Send the CSV as a file response
        response = Response(csv_buffer.getvalue(),
                            mimetype="text/csv",
                            headers={"Content-Disposition": "attachment;filename=report.csv"})
        return response
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)


@vulns.route("/finding/<appid>/<id>/request_review")
@login_required
def finding_request_review(appid, id):
    try:
        NAV['curpage'] = {"name": "Finding Request Review"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        key = 'VulnerabilityID'
        val = id
        filter_list = [f"{key} = '{val}'"]
        vuln_all = Vulnerabilities.query.with_entities(
            Vulnerabilities.VulnerabilityID, Vulnerabilities.VulnerabilityName
        )\
            .filter(text("".join(filter_list))).all()
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all)
        if assets:
            response = assets[0]
        else:
            response = []

        NAV['appbar'] = 'findings'
        app = BusinessApplications.query\
            .filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName}
        return render_template('vulns/request_review.html', details=response, app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)


@vulns.route("/finding/<appid>/<id>")
@login_required
def finding(appid, id):
    try:
        NAV['curpage'] = {"name": "Vulnerability Finding"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER, "Security"]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        key = 'VulnerabilityID'
        val = id
        filter_list = [f"{key} = '{val}'"]
        vuln_all = Vulnerabilities.query.with_entities(
            Vulnerabilities.VulnerabilityID, Vulnerabilities.VulnerabilityName, Vulnerabilities.CVEID, Vulnerabilities.CWEID,
            Vulnerabilities.Description, Vulnerabilities.ReleaseDate, Vulnerabilities.Severity, Vulnerabilities.Classification,
            Vulnerabilities.Source, Vulnerabilities.LastModifiedDate, Vulnerabilities.ReferenceName,
            Vulnerabilities.ReferenceUrl, Vulnerabilities.ReferenceTags, Vulnerabilities.AddDate,
            Vulnerabilities.SourceCodeFileId, Vulnerabilities.SourceCodeFileStartLine, Vulnerabilities.SourceCodeFileStartCol,
            Vulnerabilities.SourceCodeFileEndLine, Vulnerabilities.SourceCodeFileEndCol, Vulnerabilities.DockerImageId,
            Vulnerabilities.ApplicationId, Vulnerabilities.HostId, Vulnerabilities.Uri, Vulnerabilities.HtmlMethod,
            Vulnerabilities.Param, Vulnerabilities.Attack, Vulnerabilities.Evidence, Vulnerabilities.Solution,
            Vulnerabilities.VulnerablePackage, Vulnerabilities.VulnerableFileName, Vulnerabilities.VulnerableFilePath,
            Vulnerabilities.Status, Vulnerabilities.MitigationDate, Vulnerabilities.ScanId,
            DockerImages.ImageName, DockerImages.ImageTag, DockerImages.ID.label('DockerImageID'),
            ApplicationEndpoints.ID.label('EndpointID'), ImportedCode.ID.label('ImportedCodeID'),
            BusinessApplications.RepoURL, CVSSBaseScoresV3.cvssV3vectorString, CVSSBaseScoresV3.cvssV3attackVector,
            CVSSBaseScoresV3.cvssV3attackComplexity, CVSSBaseScoresV3.cvssV3privilegesRequired,
            CVSSBaseScoresV3.cvssV3userInteraction, CVSSBaseScoresV3.cvssV3scope,
            CVSSBaseScoresV3.cvssV3confidentialityImpact, CVSSBaseScoresV3.cvssV3integrityImpact,
            CVSSBaseScoresV3.cvssV3availabilityImpact, CVSSBaseScoresV3.cvssV3baseScore,
            CVSSBaseScoresV3.cvssV3baseSeverity, CVSSBaseScoresV3.cvssV3exploitabilityScore,
            CVSSBaseScoresV3.cvssV3impactScore,
            CWEDetails.Name.label('CWEName'), CWEDetails.Description.label('CWEDescription'), CWEDetails.ModesOfIntroductionPhase, CWEDetails.ModesOfIntroductionNote,
            CWEDetails.CommonConsequencesScope, CWEDetails.CommonConsequencesImpact, CWEDetails.DetectionMethodsMethod,
            CWEDetails.DetectionMethodsDescription, CWEDetails.PotentialMitigationsPhase,
            CWEDetails.PotentialMitigationsDescription, CWEDetails.FunctionalAreas, CWEDetails.AffectedResources,
            CWEDetails.TaxonomyMappingsName, CWEDetails.TaxonomyMappingsEntryName,
            CVSSBaseScoresV3Extensions.cvssV3exploitCodeMaturity.label('KnownExploit')
        )\
            .join(DockerImages, DockerImages.ID == Vulnerabilities.DockerImageId, isouter=True) \
            .join(ApplicationEndpoints, and_(ApplicationEndpoints.Endpoint == Vulnerabilities.Uri, ApplicationEndpoints.ApplicationID == appid), isouter=True) \
            .join(ImportedCode, and_(ImportedCode.ImportFile == Vulnerabilities.VulnerableFileName, ImportedCode.ApplicationID == appid), isouter=True) \
            .join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId, isouter=True) \
            .join(CVSSBaseScoresV3, CVSSBaseScoresV3.CVEID == Vulnerabilities.CVEID, isouter=True) \
            .join(CVSSBaseScoresV3Extensions, CVSSBaseScoresV3Extensions.CVEID == Vulnerabilities.CVEID, isouter=True) \
            .join(CWEDetails, CWEDetails.CWEID == Vulnerabilities.CWEID, isouter=True) \
            .filter(text("".join(filter_list))).all()
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all)
        if assets:
            response = assets[0]
        else:
            response = []
        issue_notes = IssueNotes.query.with_entities(
            IssueNotes.ID, IssueNotes.AddDate, IssueNotes.Private, IssueNotes.Note,
            User.username
        )\
            .join(User, User.id == IssueNotes.UserID)\
            .filter(text(f'VulnerabilityID={id} AND Private <> 1'))\
            .order_by(text('IssueNotes.AddDate DESC'))\
            .all()
        sla_policy = VulnerabilitySLAAppPair.query.with_entities(
            VulnerabilitySLAAppPair.ID, VulnerabilitySLAs.CriticalSetting, VulnerabilitySLAs.HighSetting,
            VulnerabilitySLAs.MediumSetting, VulnerabilitySLAs.LowSetting
        ) \
            .join(VulnerabilitySLAs, VulnerabilitySLAs.ID == VulnerabilitySLAAppPair.SlaID) \
            .filter(text(f'ApplicationID={appid}')).first()
        NAV['appbar'] = 'findings'
        app = BusinessApplications.query\
            .filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName}
        jira_integrations = check_if_jira_enabled(appid)

        # Call the prediction function with the input data
        prediction_response = predict_vuln_validity(
            response['Severity'],
            response['Classification'],
            len(response['Description']) if response['Description'] else 0,
            len(response['Attack']),
            len(response['Evidence']),
            len(response['Source']),
            len(response['VulnerabilityName'])
        )
        if prediction_response and hasattr(prediction_response, 'json'):
            finding_accuracy = "{:.1f}".format(prediction_response.json['probability'])
        else:
            finding_accuracy = 'N/A'

        return render_template('vulns/view_finding.html', details=response, app_data=app_data, user=user,
                               NAV=NAV, issue_notes=issue_notes, sla_policy=sla_policy, jira=jira_integrations,
                               finding_accuracy=finding_accuracy)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)


@vulns.route("/filtered_findings/<appid>/<type>/<val>", methods=['GET', 'POST'])
@login_required
def filtered_findings(appid, type, val):
    try:
        NAV['curpage'] = {"name": OPEN_FINDINGS}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        # Static (linked) section
        if type == 'severity':
            key = 'Severity'
        elif type == 'status':
            key = 'Status'
        elif type == 'import':
            key = 'VulnerablePackage'
        elif type == 'endpoint':
            key = 'Uri'
            val = base64.b64decode(val.encode()).decode()
        elif type == 'file':
            key = 'VulnerableFileName'
            val = base64.b64decode(val.encode()).decode()
        elif type == 'docker':
            key = 'DockerImageId'
        # Filter Modal section
        elif type == 'Docker Image Name':
            key = 'DockerImageId'
            image = DockerImages.query.filter(text(f"DockerImages.ImageName={val}")).first()
            val = image.ID
        elif type == 'Application Name':
            key = 'ApplicationId'
            app = BusinessApplications.query.filter(text(f"BusinessApplications.ApplicationName='{val}'")).first()
            val = app.ID
        else:
            key = type.capitalize()
        if isinstance(val, str) and val.endswith("-"):
            filter_list = [f"{key} LIKE '{val}%'"]
        elif isinstance(val, str) and val == 'ALL':
            filter_list = [f"{key} LIKE '%-%'"]
        else:
            filter_list = [f"{key} = '{val}'"]
        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        if type == 'Branch':
            branch_type = 'Branch'
        else:
            branch_type = None
        assets, pg_cnt, vuln_all = _get_assets(val, orderby, per_page, page, filter_list, appid, branch_type)

        sla_policy = VulnerabilitySLAAppPair.query.with_entities(
            VulnerabilitySLAAppPair.ID, VulnerabilitySLAs.CriticalSetting, VulnerabilitySLAs.HighSetting,
            VulnerabilitySLAs.MediumSetting, VulnerabilitySLAs.LowSetting
        ) \
            .join(VulnerabilitySLAs, VulnerabilitySLAs.ID == VulnerabilitySLAAppPair.SlaID) \
            .filter(text(f'ApplicationID={appid}')).first()
        NAV['appbar'] = 'findings'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
        table_details = _set_table_details(assets, sla_policy, pg_cnt, page, vuln_all, per_page, orderby)

        return render_template('vulns/open_findings_filtered.html', entities=assets, app_data=app_data, user=user, NAV=NAV,
                               sla_policy=sla_policy, table_details=table_details, filter_type=type, filter_value=val)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)


@vulns.route("/filtered_findings/<appid>/<type>/<val>/export", methods=['GET', 'POST'])
@login_required
def filtered_findings_export(appid, type, val):
    try:
        NAV['curpage'] = {"name": OPEN_FINDINGS}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        # Static (linked) section
        if type == 'severity':
            key = 'Severity'
        elif type == 'status':
            key = 'Status'
        elif type == 'import':
            key = 'VulnerablePackage'
        elif type == 'endpoint':
            key = 'Uri'
            val = base64.b64decode(val.encode()).decode()
        elif type == 'file':
            key = 'VulnerableFileName'
            val = base64.b64decode(val.encode()).decode()
        elif type == 'docker':
            key = 'DockerImageId'
        # Filter Modal section
        elif type == 'Docker Image Name':
            key = 'DockerImageId'
            image = DockerImages.query.filter(text(f"DockerImages.ImageName={val}")).first()
            val = image.ID
        elif type == 'Application Name':
            key = 'ApplicationId'
            app = BusinessApplications.query.filter(text(f"BusinessApplications.ApplicationName={val}")).first()
            val = app.ID
        else:
            key = type.capitalize()
        if val.endswith("-"):
            filter_list = [f"{key} LIKE '{val}%'"]
        elif val == 'ALL':
            filter_list = [f"{key} LIKE '%-%'"]
        else:
            filter_list = [f"{key} = '{val}'"]
        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        per_page = 10000  # limit for performance
        assets, pg_cnt, vuln_all = _get_assets(val, orderby, per_page, page, filter_list, appid)

        sla_policy = VulnerabilitySLAAppPair.query.with_entities(
            VulnerabilitySLAAppPair.ID, VulnerabilitySLAs.CriticalSetting, VulnerabilitySLAs.HighSetting,
            VulnerabilitySLAs.MediumSetting, VulnerabilitySLAs.LowSetting
        ) \
            .join(VulnerabilitySLAs, VulnerabilitySLAs.ID == VulnerabilitySLAAppPair.SlaID) \
            .filter(text(f'ApplicationID={appid}')).first()
        NAV['appbar'] = 'findings'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName}
        table_details = _set_table_details(assets, sla_policy, pg_cnt, page, vuln_all, per_page, orderby)

        now = datetime.datetime.utcnow()
        html = render_template('vulns/open_findings_pdf.html', now=now, entities=assets, app_data=app_data, user=user, NAV=NAV,
                               sla_policy=sla_policy, table_details=table_details, filter_type=type, filter_value=val)
        # Create a BytesIO buffer to store the generated PDF
        pdf_buffer = BytesIO()

        # Convert the HTML to PDF using xhtml2pdf
        cmd_options = {
            '--orientation': 'Landscape'
        }
        pisa.CreatePDF(html, dest=pdf_buffer, options=cmd_options)

        # Reset the buffer's file pointer to the beginning
        pdf_buffer.seek(0)

        # Send the PDF as a file response
        response = send_file(pdf_buffer, as_attachment=True, download_name='report.pdf', mimetype='application/pdf')
        return response
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)


@vulns.route("/filtered_findings/<appid>/<type>/<val>/csv", methods=['GET', 'POST'])
@login_required
def filtered_findings_csv(appid, type, val):
    try:
        NAV['curpage'] = {"name": OPEN_FINDINGS}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        # Static (linked) section
        if type == 'severity':
            key = 'Severity'
        elif type == 'status':
            key = 'Status'
        elif type == 'import':
            key = 'VulnerablePackage'
        elif type == 'endpoint':
            key = 'Uri'
            val = base64.b64decode(val.encode()).decode()
        elif type == 'file':
            key = 'VulnerableFileName'
            val = base64.b64decode(val.encode()).decode()
        elif type == 'docker':
            key = 'DockerImageId'
        # Filter Modal section
        elif type == 'Docker Image Name':
            key = 'DockerImageId'
            image = DockerImages.query.filter(text(f"DockerImages.ImageName={val}")).first()
            val = image.ID
        elif type == 'Application Name':
            key = 'ApplicationId'
            app = BusinessApplications.query.filter(text(f"BusinessApplications.ApplicationName={val}")).first()
            val = app.ID
        else:
            key = type.capitalize()
        if val.endswith("-"):
            filter_list = [f"{key} LIKE '{val}%'"]
        elif val == 'ALL':
            filter_list = [f"{key} LIKE '%-%'"]
        else:
            filter_list = [f"{key} = '{val}'"]
        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        per_page = 10000  # limit for performance

        assets, pg_cnt, vuln_all = _get_assets(val, orderby, per_page, page, filter_list, appid)

        NAV['appbar'] = 'findings'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()

        # Process the data and create the CSV
        csv_buffer = StringIO()
        csv_writer = csv.writer(csv_buffer)

        headers = ["Severity", "Name", "CWE", "CVE", "AddDate", "FoundBy", "Status", "Resource Type", "Resource"]
        csv_writer.writerow(headers)

        for vuln in assets:
            if vuln['Classification'].startswith("Secret") or vuln['Classification'] == 'SAST' or vuln[
                'Classification'].startswith("IaC"):
                resource_type = 'File'
            elif vuln['Classification'].startswith("Container"):
                resource_type = 'Container Library'
            elif vuln['Classification'] == "SCA":
                resource_type = 'Source Code Library'
            elif vuln['Classification'] == "DAST":
                resource_type = 'URI'
            else:
                resource_type = 'Unknown'

            if vuln['Classification'].startswith("Secret") or vuln['Classification'] == 'SAST' or vuln[
                'Classification'].startswith("IaC"):
                resource = vuln['VulnerableFileName']
                if vuln['SourceCodeFileStartLine']:
                    resource = resource + f":{vuln['SourceCodeFileStartLine']}"
                if vuln['SourceCodeFileEndLine']:
                    resource = resource + f":{vuln['SourceCodeFileEndLine']}"
            elif vuln['Classification'].startswith("Container") or vuln['Classification'] == 'SCA':
                resource = vuln['VulnerablePackage']
            elif vuln['Classification'] == "DAST":
                resource = vuln['Uri']
            row = [vuln['Severity'], vuln['VulnerabilityName'], vuln['CWEID'], vuln['CVEID'], vuln['ReleaseDate'],
                   vuln['Source'], vuln['Status'],
                   resource_type, resource]
            csv_writer.writerow(row)

        # Reset the buffer's file pointer to the beginning
        csv_buffer.seek(0)

        # Send the CSV as a file response
        response = Response(csv_buffer.getvalue(),
                            mimetype="text/csv",
                            headers={"Content-Disposition": "attachment;filename=report.csv"})
        return response
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)


def _get_assets(val, orderby, per_page, page, filter_list, app_id, type=None ):
    if type == 'Branch':
        new_val = val.replace('_', '/')
        if filter_list and filter_list[0] == "Status LIKE 'Closed-%'":
            vuln_all = Vulnerabilities \
                .query \
                .with_entities(Vulnerabilities.VulnerabilityName, Vulnerabilities.VulnerabilityID, Vulnerabilities.CWEID,
                               Vulnerabilities.CVEID, Vulnerabilities.ReleaseDate,
                               Vulnerabilities.Source, Vulnerabilities.Status, Vulnerabilities.Classification,
                               Vulnerabilities.VulnerableFileName, Vulnerabilities.SourceCodeFileStartLine,
                               Vulnerabilities.SourceCodeFileEndLine, Vulnerabilities.VulnerablePackage,
                               Vulnerabilities.Uri, Vulnerabilities.AddDate, Vulnerabilities.Severity) \
                .join(VulnerabilityScans, VulnerabilityScans.ID == Vulnerabilities.ScanId) \
                .filter(text(f"VulnerabilityScans.Branch LIKE '{new_val}'")) \
                .filter(text(f"Vulnerabilities.ApplicationId={app_id}")) \
                .order_by(text(orderby)) \
                .yield_per(per_page) \
                .paginate(page=page, per_page=per_page, error_out=False)
        else:
            vuln_all = Vulnerabilities \
                .query \
                .with_entities(Vulnerabilities.VulnerabilityName, Vulnerabilities.VulnerabilityID,
                               Vulnerabilities.CWEID,
                               Vulnerabilities.CVEID, Vulnerabilities.ReleaseDate,
                               Vulnerabilities.Source, Vulnerabilities.Status, Vulnerabilities.Classification,
                               Vulnerabilities.VulnerableFileName, Vulnerabilities.SourceCodeFileStartLine,
                               Vulnerabilities.SourceCodeFileEndLine, Vulnerabilities.VulnerablePackage,
                               Vulnerabilities.Uri, Vulnerabilities.AddDate, Vulnerabilities.Severity) \
                .join(VulnerabilityScans, VulnerabilityScans.ID == Vulnerabilities.ScanId) \
                .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
                .filter(text(f"VulnerabilityScans.Branch LIKE '{new_val}'")) \
                .filter(text(f"Vulnerabilities.ApplicationId={app_id}")) \
                .order_by(text(orderby)) \
                .yield_per(per_page) \
                .paginate(page=page, per_page=per_page, error_out=False)
    else:
        if filter_list and filter_list[0] ==  "Status LIKE 'Closed-%'":
            vuln_all = Vulnerabilities \
                .query \
                .filter(text("".join(filter_list))) \
                .filter(text(f"Vulnerabilities.ApplicationId={app_id}")) \
                .order_by(text(orderby)) \
                .yield_per(per_page) \
                .paginate(page=page, per_page=per_page, error_out=False)
        else:
            vuln_all = Vulnerabilities \
                .query \
                .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
                .filter(text("".join(filter_list))) \
                .filter(text(f"Vulnerabilities.ApplicationId={app_id}")) \
                .order_by(text(orderby)) \
                .yield_per(per_page) \
                .paginate(page=page, per_page=per_page, error_out=False)
    pg_cnt = ceil((vuln_all.total / per_page))
    schema = VulnerabilitiesSchema(many=True)
    assets = schema.dump(vuln_all.items)
    return assets, pg_cnt, vuln_all


def _set_table_details(assets, sla_policy, pg_cnt, page, vuln_all, per_page, orderby):
    now = datetime.datetime.utcnow()
    vulns = []
    for vuln in assets:
        try:
            time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT)).days
        except:
            time_since_found = (now - datetime.datetime.strptime(vuln['AddDate'], ISO_FORMAT_BASE)).days
        severity = vuln['Severity']
        if severity == 'Critical':
            sla = sla_policy[1]
        elif severity == 'High':
            sla = sla_policy[2]
        elif severity == 'Medium':
            sla = sla_policy[3]
        else:
            sla = sla_policy[4]
        sla_status = int(sla) - time_since_found
        vuln['SLAStatus'] = sla_status
        vulns.append(vuln)
    table_details = {
        "pg_cnt": pg_cnt,
        "page": int(page),
        "item_tot": vuln_all.total,
        "per_page": per_page,
        "orderby": orderby,
        "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
        "rec_end": int(page) * per_page if (int(page) * per_page) < vuln_all.total else vuln_all.total
    }
    return table_details


@vulns.route("/add_issue_dispo", methods=['POST'])
@login_required
def add_issue_dispo():
    try:
        NAV['curpage'] = {"name": "Add Finding Disposition"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        if request.method == 'POST':
            dispo = request.form.get('dispo')
            issue_id = request.form.get('issue_id')
            sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='ApplicationId')
            if dispo == 'Deleted':
                dispo_option = request.form.get('deleteOption')
                issue_note = request.form.get('deletenote')
                if issue_note:
                    _add_issue_note_from_dispo('Security', issue_id, user.id, dispo_option, issue_note)

                vulns = Vulnerabilities.query.filter(text(f"VulnerabilityID={issue_id}")).all()
                for vuln in vulns:
                    db.session.delete(vuln)
                db_connection_handler(db)
            else:
                now = datetime.datetime.utcnow()
                # Add Notes and System Messages
                if dispo == 'Closed':
                    db.session.query(Vulnerabilities).filter(text(f"Vulnerabilities.VulnerabilityID={issue_id}")).update(
                        {Vulnerabilities.MitigationDate: now},
                        synchronize_session=False)
                    db_connection_handler(db)
                elif dispo == 'Open-NeedSecReview':
                    dispo_option = request.form.get('peerReviewOption')
                    issue_note = request.form.get('peerReviewnote')
                    if issue_note:
                        _add_issue_note_from_dispo('Development Team', issue_id,user.id, dispo_option, issue_note)

                    msg = f"New Security Review request from USER: {user.username} for FINDING ID: {issue_id}"
                    msg_id = _add_new_system_msg(user, issue_id, 'New Security Review Requests', msg)
                    msg = f"Security Review Submitted for FINDING ID: {issue_id}"
                    msg_id = _add_new_system_msg(user, issue_id, 'Security Review Request Submitted', msg, receiver_id=user.id)
                    _add_new_system_msg_status(msg_id, 'New', user.id)  # Status is always added if receiver is known
                elif dispo == 'Open-Reviewed':
                    dispo_option = request.form.get('devReviewedOption')
                    issue_note = request.form.get('devReviewednote')
                    if issue_note:
                        _add_issue_note_from_dispo('Development Team', issue_id, user.id, dispo_option, issue_note)
                    if dispo_option != "Confirmed" and dispo_option != "Mitigated" and dispo_option != 'Other':
                        msg = f"New Security Review request from USER: {user.username} for FINDING ID: {issue_id}   /n DISPOSITION: {dispo_option}    /n NOTES: {issue_note}"
                        msg_id = _add_new_system_msg(user, issue_id, 'New Security Review Requests', msg)
                        msg = f"Security Review Submitted for FINDING ID: {issue_id}   /n DISPOSITION: {dispo_option}"
                        msg_id = _add_new_system_msg(user, issue_id, 'Security Review Request Submitted', msg,
                                                     receiver_id=user.id)
                        _add_new_system_msg_status(msg_id, 'New',
                                                   user.id)  # Status is always added if receiver is known
                elif dispo == 'Open-SecReview':
                    dispo_option = request.form.get('conductSecurityReviewOption')
                    issue_note = request.form.get('conductSecurityReviewnote')
                    if issue_note:
                        _add_issue_note_from_dispo('Security', issue_id, user.id, dispo_option, issue_note)

                    msg = f"Security Review Started for FINDING ID: {issue_id} - NEW STATUS: Under Security Review"
                    # get messages for issue_id
                    cur_msgs = Messages.query \
                        .filter(text(
                        f"(MessagesStatus.Status IS NULL OR MessagesStatus.Status <> 'Closed') AND (Messages.EntityType='Vulnerability' AND Messages.EntityID={issue_id})")) \
                        .join(MessagesStatus, MessagesStatus.MessageId == Messages.ID, isouter=True) \
                        .all()
                    for i in cur_msgs:
                        if not i.ReceiverUserId:
                            _assign_msg_receiver(i.ID, user.id)

                        if i.MessageType == 'New Security Review Requests':
                            _add_new_system_msg_status(i.ID, 'InProcess',
                                                       user.id)  # Update the status out for the message reciever (current user)
                        elif i.MessageType == 'Security Review Request Submitted':
                            msg_id = _add_new_system_msg(user, issue_id, 'Started Security Review', msg,
                                                         receiver_id=i.ReceiverUserId)
                elif dispo == 'Closed-Manual':
                    dispo_option = request.form.get('closedManualOption')
                    issue_note = request.form.get('closedManualnote')
                    if issue_note:
                        _add_issue_note_from_dispo('Security', issue_id, user.id, dispo_option, issue_note)

                    msg = f"Security Review Complete for FINDING ID: {issue_id} - NEW STATUS: Issue Closed"
                    # get messages for issue_id
                    cur_msgs = Messages.query\
                        .filter(text(f"(MessagesStatus.Status IS NULL OR MessagesStatus.Status <> 'Closed') AND (Messages.EntityType='Vulnerability' AND Messages.EntityID={issue_id})"))\
                        .join(MessagesStatus, MessagesStatus.MessageId==Messages.ID, isouter=True)\
                        .all()
                    for i in cur_msgs:
                        if not i.ReceiverUserId:
                            _assign_msg_receiver(i.ID, user.id)

                        if i.MessageType == 'New Security Review Requests':
                            _add_new_system_msg_status(i.ID, 'Closed', user.id)  # Close the status out for the message reciever (current user)
                        elif i.MessageType == 'Security Review Request Submitted':
                            msg_id = _add_new_system_msg(user, issue_id, 'Completed Security Review Request', msg, receiver_id=i.ReceiverUserId)
                elif dispo == 'Open-RiskAccepted':
                    dispo_option = request.form.get('riskAcceptedOption')
                    issue_note = request.form.get('riskAcceptednote')
                    if issue_note:
                        _add_issue_note_from_dispo('Security', issue_id, user.id, dispo_option, issue_note)

                if dispo_option:
                    db.session.query(Vulnerabilities).filter(text(f"Vulnerabilities.VulnerabilityID={issue_id}")).update(
                        {Vulnerabilities.LastModifiedDate: now,
                         Vulnerabilities.Status: f"{dispo}-{dispo_option}"},
                        synchronize_session=False)
                    db_connection_handler(db)
                if dispo_option == 'Closed-Manual':
                    db.session.query(Vulnerabilities).filter(
                        text(f"Vulnerabilities.VulnerabilityID={issue_id}")).update(
                        {Vulnerabilities.MitigationDate: now},
                        synchronize_session=False)
                    db_connection_handler(db)

            return str(200)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)


def _add_issue_note_from_dispo(role, issue_id, user_id, dispo_option, issue_note):
    new_app = IssueNotes(
        VulnerabilityID=issue_id,
        UserID=user_id,
        Private='0',
        Note=f"New {role} Disposition: {dispo_option}\n NOTES: " + issue_note
    )
    db.session.add(new_app)
    db_connection_handler(db)


def _assign_msg_receiver(msg_id, receiver_user_id):
    db.session.query(Messages).filter(text(f"Messages.ID={msg_id}"))\
        .update({Messages.ReceiverUserId: receiver_user_id}, synchronize_session=False)
    db_connection_handler(db)


def _add_new_system_msg_status(msg_id, status, user_id):
    new_msg = MessagesStatus(
        MessageId=msg_id,
        Status=status,
        UserId=user_id
    )
    db.session.add(new_msg)
    db_connection_handler(db)


def _add_new_system_msg(user, issue_id, msg_type, msg, receiver_id=None):
    new_msg = Messages(
        SenderUserId=user.id,
        MessageType=msg_type,
        EntityType='Vulnerability',
        EntityID=issue_id,
        Message=msg
    )
    if receiver_id:
        new_msg.ReceiverUserId = receiver_id
    db.session.add(new_msg)
    db_connection_handler(db)
    return new_msg.ID


@vulns.route("/add_issue_note", methods=['POST'])
@login_required
def add_issue_note():
    try:
        NAV['curpage'] = {"name": "Add Issue Note"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        if request.method == 'POST':
            note_val = request.form.get('note_val')
            issue_id = request.form.get('issue_id')
            sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='ApplicationId')
            vuln = Vulnerabilities.query.filter(text(sql_filter)).first()
            if vuln:
                new_app = IssueNotes(
                    VulnerabilityID=issue_id,
                    UserID=user.id,
                    Private='0',
                    Note=note_val
                )
                db.session.add(new_app)
                db_connection_handler(db)
                return {
                           "ID": new_app.ID,
                           "AddDate": new_app.AddDate,
                           "Note": new_app.Note
                       }, 200
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)


@vulns.route("/delete_issue_note", methods=['POST'])
@login_required
def delete_issue_note():
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
        if request.method == 'POST':
            issue_id = request.form.get('issue_id')
            sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='ApplicationId')
            vuln = Vulnerabilities.query.filter(text(sql_filter)).first()
            if vuln:
                del_note = IssueNotes.query.filter(text(f"ID={issue_id}")).first()
                db.session.delete(del_note)
                db_connection_handler(db)
                return str(200)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)
