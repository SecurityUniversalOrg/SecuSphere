from vr.vulns import vulns
import datetime
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import render_template, session, redirect, url_for, request, send_file
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications
from vr.orchestration.model.dockerimages import DockerImages
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema
from sqlalchemy import text
from vr.functions.table_functions import load_table, update_table
from math import ceil
from io import BytesIO
from xhtml2pdf import pisa
import csv
import base64
from io import StringIO
from flask import Response


NAV = {
    'CAT': { "name": "Vulnerabilities", "url": "sourcecode.dashboard"}
}
VULN_STATUS_IS_NOT_CLOSED = "Vulnerabilities.Status!='Closed'"
ISO_FORMAT = '%Y-%m-%dT%H:%M:%S'


@vulns.route("/all_vulnerabilities", methods=['GET', 'POST'])
@login_required
def all_vulnerabilities():
    try:
        NAV['curpage'] = {"name": "All Vulnerabilities"}
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

        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        vuln_all = Vulnerabilities.query.with_entities(
            Vulnerabilities.VulnerabilityID, Vulnerabilities.VulnerabilityName, Vulnerabilities.CVEID, Vulnerabilities.CWEID,
            Vulnerabilities.Description, Vulnerabilities.ReleaseDate, Vulnerabilities.Severity, Vulnerabilities.Classification,
            Vulnerabilities.Source, Vulnerabilities.LastModifiedDate, Vulnerabilities.ReferenceName, Vulnerabilities.ReferenceUrl,
            Vulnerabilities.ReferenceTags, Vulnerabilities.AddDate, Vulnerabilities.SourceCodeFileId, Vulnerabilities.SourceCodeFileStartLine,
            Vulnerabilities.SourceCodeFileStartCol, Vulnerabilities.SourceCodeFileEndLine, Vulnerabilities.SourceCodeFileEndCol,
            Vulnerabilities.DockerImageId, Vulnerabilities.ApplicationId, Vulnerabilities.HostId, Vulnerabilities.Uri,
            Vulnerabilities.HtmlMethod, Vulnerabilities.Param, Vulnerabilities.Attack, Vulnerabilities.Evidence,
            Vulnerabilities.Solution, Vulnerabilities.VulnerablePackage, Vulnerabilities.VulnerableFileName, Vulnerabilities.VulnerableFilePath,
            Vulnerabilities.Status, Vulnerabilities.MitigationDate, BusinessApplications.ApplicationName
        ).join(BusinessApplications, BusinessApplications.ID==Vulnerabilities.ApplicationId) \
            .filter(text(sql_filter)) \
            .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((vuln_all.total / per_page))
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all.items)

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": vuln_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < vuln_all.total else vuln_all.total
        }

        return render_template('all_vulnerabilities.html', entities=assets, user=user, NAV=NAV, table_details= table_details)
    except RuntimeError:
        return render_template('500.html'), 500


@vulns.route("/all_vulnerabilities/export", methods=['GET', 'POST'])
@login_required
def all_vulnerabilities_export():
    try:
        NAV['curpage'] = {"name": "All Vulnerabilities"}
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

        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        vuln_all = Vulnerabilities.query.with_entities(
            Vulnerabilities.VulnerabilityID, Vulnerabilities.VulnerabilityName, Vulnerabilities.CVEID, Vulnerabilities.CWEID,
            Vulnerabilities.Description, Vulnerabilities.ReleaseDate, Vulnerabilities.Severity, Vulnerabilities.Classification,
            Vulnerabilities.Source, Vulnerabilities.LastModifiedDate, Vulnerabilities.ReferenceName, Vulnerabilities.ReferenceUrl,
            Vulnerabilities.ReferenceTags, Vulnerabilities.AddDate, Vulnerabilities.SourceCodeFileId, Vulnerabilities.SourceCodeFileStartLine,
            Vulnerabilities.SourceCodeFileStartCol, Vulnerabilities.SourceCodeFileEndLine, Vulnerabilities.SourceCodeFileEndCol,
            Vulnerabilities.DockerImageId, Vulnerabilities.ApplicationId, Vulnerabilities.HostId, Vulnerabilities.Uri,
            Vulnerabilities.HtmlMethod, Vulnerabilities.Param, Vulnerabilities.Attack, Vulnerabilities.Evidence,
            Vulnerabilities.Solution, Vulnerabilities.VulnerablePackage, Vulnerabilities.VulnerableFileName, Vulnerabilities.VulnerableFilePath,
            Vulnerabilities.Status, Vulnerabilities.MitigationDate, BusinessApplications.ApplicationName
        ).join(BusinessApplications, BusinessApplications.ID==Vulnerabilities.ApplicationId) \
            .filter(text(sql_filter)) \
            .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((vuln_all.total / per_page))
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all.items)

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": vuln_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < vuln_all.total else vuln_all.total
        }

        now = datetime.datetime.utcnow()
        html = render_template('all_vulnerabilities_pdf.html', now=now, entities=assets, user=user,
                               NAV=NAV, table_details=table_details)
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
        return render_template('500.html'), 500


@vulns.route("/all_vulnerabilities/csv", methods=['GET', 'POST'])
@login_required
def all_vulnerabilities_csv():
    try:
        NAV['curpage'] = {"name": "All Vulnerabilities"}
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

        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        vuln_all = Vulnerabilities.query.with_entities(
            Vulnerabilities.VulnerabilityID, Vulnerabilities.VulnerabilityName, Vulnerabilities.CVEID, Vulnerabilities.CWEID,
            Vulnerabilities.Description, Vulnerabilities.ReleaseDate, Vulnerabilities.Severity, Vulnerabilities.Classification,
            Vulnerabilities.Source, Vulnerabilities.LastModifiedDate, Vulnerabilities.ReferenceName, Vulnerabilities.ReferenceUrl,
            Vulnerabilities.ReferenceTags, Vulnerabilities.AddDate, Vulnerabilities.SourceCodeFileId, Vulnerabilities.SourceCodeFileStartLine,
            Vulnerabilities.SourceCodeFileStartCol, Vulnerabilities.SourceCodeFileEndLine, Vulnerabilities.SourceCodeFileEndCol,
            Vulnerabilities.DockerImageId, Vulnerabilities.ApplicationId, Vulnerabilities.HostId, Vulnerabilities.Uri,
            Vulnerabilities.HtmlMethod, Vulnerabilities.Param, Vulnerabilities.Attack, Vulnerabilities.Evidence,
            Vulnerabilities.Solution, Vulnerabilities.VulnerablePackage, Vulnerabilities.VulnerableFileName, Vulnerabilities.VulnerableFilePath,
            Vulnerabilities.Status, Vulnerabilities.MitigationDate, BusinessApplications.ApplicationName
        ).join(BusinessApplications, BusinessApplications.ID==Vulnerabilities.ApplicationId) \
            .filter(text(sql_filter)) \
            .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((vuln_all.total / per_page))
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all.items)

        # Process the data and create the CSV
        csv_buffer = StringIO()
        csv_writer = csv.writer(csv_buffer)

        headers = ["Severity", "Name", "CWE", "CVE", "AddDate", "FoundBy", "Status", "Resource Type", "Resource", "App"]
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
                   resource_type, resource, vuln['ApplicationName']]
            csv_writer.writerow(row)

        # Reset the buffer's file pointer to the beginning
        csv_buffer.seek(0)

        # Send the CSV as a file response
        response = Response(csv_buffer.getvalue(),
                            mimetype="text/csv",
                            headers={"Content-Disposition": "attachment;filename=report.csv"})
        return response
    except RuntimeError:
        return render_template('500.html'), 500


@vulns.route("/all_vulnerabilities_filtered/<type>/<val>", methods=['GET', 'POST'])
@login_required
def all_vulnerabilities_filtered(type, val):
    try:
        NAV['curpage'] = {"name": "All Vulnerabilities"}
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

        assets, pg_cnt, vuln_all = _get_assets(orderby, per_page, page, filter_list, sql_filter)

        table_details = _set_table_details(pg_cnt, page, vuln_all, per_page, orderby)

        return render_template('all_vulnerabilities_filtered.html', entities=assets, user=user, NAV=NAV, table_details= table_details,
                               filter_type=type, filter_value=val)
    except RuntimeError:
        return render_template('500.html'), 500


def _get_assets(orderby, per_page, page, filter_list, sql_filter):
    vuln_all = Vulnerabilities. \
            query.with_entities(
                Vulnerabilities.VulnerabilityID, Vulnerabilities.VulnerabilityName, Vulnerabilities.CVEID,
                Vulnerabilities.CWEID,
                Vulnerabilities.Description, Vulnerabilities.ReleaseDate, Vulnerabilities.Severity,
                Vulnerabilities.Classification,
                Vulnerabilities.Source, Vulnerabilities.LastModifiedDate, Vulnerabilities.ReferenceName,
                Vulnerabilities.ReferenceUrl,
                Vulnerabilities.ReferenceTags, Vulnerabilities.AddDate, Vulnerabilities.SourceCodeFileId,
                Vulnerabilities.SourceCodeFileStartLine,
                Vulnerabilities.SourceCodeFileStartCol, Vulnerabilities.SourceCodeFileEndLine,
                Vulnerabilities.SourceCodeFileEndCol,
                Vulnerabilities.DockerImageId, Vulnerabilities.ApplicationId, Vulnerabilities.HostId,
                Vulnerabilities.Uri,
                Vulnerabilities.HtmlMethod, Vulnerabilities.Param, Vulnerabilities.Attack, Vulnerabilities.Evidence,
                Vulnerabilities.Solution, Vulnerabilities.VulnerablePackage, Vulnerabilities.VulnerableFileName,
                Vulnerabilities.VulnerableFilePath,
                Vulnerabilities.Status, Vulnerabilities.MitigationDate, BusinessApplications.ApplicationName
            ).join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
                .filter(text(VULN_STATUS_IS_NOT_CLOSED)) \
        .filter(text("".join(filter_list))) \
        .filter(text(sql_filter)) \
        .order_by(text(orderby)) \
        .yield_per(per_page) \
        .paginate(page=page, per_page=per_page, error_out=False)
    pg_cnt = ceil((vuln_all.total / per_page))
    schema = VulnerabilitiesSchema(many=True)
    assets = schema.dump(vuln_all.items)
    return assets, pg_cnt, vuln_all


def _set_table_details(pg_cnt, page, vuln_all, per_page, orderby):
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


@vulns.route("/all_vulnerabilities_filtered/<type>/<val>/export", methods=['GET', 'POST'])
@login_required
def all_vulnerabilities_filtered_export(type, val):
    try:
        NAV['curpage'] = {"name": "All Vulnerabilities"}
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

        assets, pg_cnt, vuln_all = _get_assets(orderby, per_page, page, filter_list, sql_filter)

        table_details = _set_table_details(pg_cnt, page, vuln_all, per_page, orderby)

        now = datetime.datetime.utcnow()
        html = render_template('all_vulnerabilities_pdf.html', now=now, entities=assets, user=user,
                               NAV=NAV, table_details=table_details)
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
        return render_template('500.html'), 500


@vulns.route("/all_vulnerabilities_filtered/<type>/<val>/csv", methods=['GET', 'POST'])
@login_required
def all_vulnerabilities_filtered_csv(type, val):
    try:
        NAV['curpage'] = {"name": "All Vulnerabilities"}
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

        assets, pg_cnt, vuln_all = _get_assets(orderby, per_page, page, filter_list, sql_filter)

        # Process the data and create the CSV
        csv_buffer = StringIO()
        csv_writer = csv.writer(csv_buffer)

        headers = ["Severity", "Name", "CWE", "CVE", "AddDate", "FoundBy", "Status", "Resource Type", "Resource", "App"]
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
                   resource_type, resource, vuln['ApplicationName']]
            csv_writer.writerow(row)

        # Reset the buffer's file pointer to the beginning
        csv_buffer.seek(0)

        # Send the CSV as a file response
        response = Response(csv_buffer.getvalue(),
                            mimetype="text/csv",
                            headers={"Content-Disposition": "attachment;filename=report.csv"})
        return response
    except RuntimeError:
        return render_template('500.html'), 500
