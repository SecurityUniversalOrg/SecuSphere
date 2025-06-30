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
VULN_STATUS_IS_NOT_CLOSED = "Vulnerabilities.Status NOT LIKE '%Closed%'"
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
            allowed_columns = [
                "VulnerabilityID", "VulnerabilityName", "CVEID", "CWEID", "Description", "ReleaseDate", "Severity",
                "Classification", "Source", "LastModifiedDate", "ReferenceName", "ReferenceUrl", "ReferenceTags",
                "AddDate", "SourceCodeFileId", "SourceCodeFileStartLine", "SourceCodeFileStartCol",
                "SourceCodeFileEndLine", "SourceCodeFileEndCol", "DockerImageId", "ApplicationId", "HostId", "Uri",
                "HtmlMethod", "Param", "Attack", "Evidence", "Solution", "VulnerablePackage", "VulnerableFileName",
                "VulnerableFilePath", "Status", "MitigationDate", "ApplicationName"
            ]
            allowed_directions = ["ASC", "DESC"]
            if not any(orderby.startswith(col) and orderby.endswith(dir) for col in allowed_columns for dir in allowed_directions):
                orderby = "VulnerabilityID ASC"  # Default to a safe value
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
            .order_by(orderby) \
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

        return render_template('vulns/all_vulnerabilities.html', entities=assets, user=user, NAV=NAV, table_details= table_details)
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
            # Validate orderby against a whitelist of allowed columns
            allowed_columns = [
                "VulnerabilityID", "VulnerabilityName", "CVEID", "CWEID", "Description", "ReleaseDate",
                "Severity", "Classification", "Source", "LastModifiedDate", "ReferenceName", "ReferenceUrl",
                "ReferenceTags", "AddDate", "SourceCodeFileId", "SourceCodeFileStartLine", "SourceCodeFileStartCol",
                "SourceCodeFileEndLine", "SourceCodeFileEndCol", "DockerImageId", "ApplicationId", "HostId",
                "Uri", "HtmlMethod", "Param", "Attack", "Evidence", "Solution", "VulnerablePackage",
                "VulnerableFileName", "VulnerableFilePath", "Status", "MitigationDate", "ApplicationName"
            ]
            if orderby not in allowed_columns:
                orderby = "VulnerabilityID"  # Default to a safe column
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
            .order_by(orderby) \
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
        html = render_template('vulns/all_vulnerabilities_pdf.html', now=now, entities=assets, user=user,
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
            # Validate orderby against a whitelist
            allowed_columns = ["VulnerabilityID", "VulnerabilityName", "Severity", "Classification", "ReleaseDate"]
            allowed_directions = ["ASC", "DESC"]
            orderby_parts = orderby.split()
            if len(orderby_parts) == 2 and orderby_parts[0] in allowed_columns and orderby_parts[1] in allowed_directions:
                validated_orderby = f"{orderby_parts[0]} {orderby_parts[1]}"
            else:
                validated_orderby = "VulnerabilityID ASC"  # Default fallback
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
            .order_by(
                getattr(Vulnerabilities, orderby_parts[0]).asc() if orderby_parts[1] == "ASC" else getattr(Vulnerabilities, orderby_parts[0]).desc()
            ) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

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
            image = DockerImages.query.filter(DockerImages.ImageName == val).first()
            val = image.ID if image else None
        elif type == 'Application Name':
            key = 'ApplicationId'
            app = BusinessApplications.query.filter(BusinessApplications.ApplicationName == val).first()
            val = app.ID if app else None
        else:
            key = type.capitalize()
            allowed_keys = [
                "DockerImageId", "ApplicationId", "VulnerabilityID", "VulnerabilityName", "CVEID", "CWEID",
                "Severity", "Classification", "Source", "Status", "MitigationDate", "ApplicationName"
            ]
            if key not in allowed_keys:
                raise ValueError(f"Invalid filter key: {key}")
        if val.endswith("-"):
            filter_list = [Vulnerabilities.__table__.c[key].like(f"{val}%")]
        elif val == 'ALL':
            filter_list = [Vulnerabilities.__table__.c[key].like("%-%")]
        else:
            filter_list = [Vulnerabilities.__table__.c[key] == val]

        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
            allowed_columns = [
                "VulnerabilityID", "VulnerabilityName", "CVEID", "CWEID", "Description", "ReleaseDate",
                "Severity", "Classification", "Source", "LastModifiedDate", "ReferenceName", "ReferenceUrl",
                "ReferenceTags", "AddDate", "SourceCodeFileId", "SourceCodeFileStartLine",
                "SourceCodeFileStartCol", "SourceCodeFileEndLine", "SourceCodeFileEndCol", "DockerImageId",
                "ApplicationId", "HostId", "Uri", "HtmlMethod", "Param", "Attack", "Evidence", "Solution",
                "VulnerablePackage", "VulnerableFileName", "VulnerableFilePath", "Status", "MitigationDate",
                "ApplicationName"
            ]
            if orderby not in allowed_columns:
                orderby = "VulnerabilityID"  # Default safe column
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        assets, pg_cnt, vuln_all = _get_assets(orderby, per_page, page, filter_list, sql_filter)

        table_details = _set_table_details(pg_cnt, page, vuln_all, per_page, orderby)

        return render_template('vulns/all_vulnerabilities_filtered.html', entities=assets, user=user, NAV=NAV, table_details= table_details,
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
        .filter(*filter_list) \
        .filter(text(sql_filter)) \
        .order_by(getattr(Vulnerabilities, orderby)) \
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
            image = DockerImages.query.filter(text("DockerImages.ImageName = :image_name").params(image_name=val)).first()
            val = image.ID
        elif type == 'Application Name':
            key = 'ApplicationId'
            app = BusinessApplications.query.filter(text("BusinessApplications.ApplicationName = :app_name").params(app_name=val)).first()
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
        html = render_template('vulns/all_vulnerabilities_pdf.html', now=now, entities=assets, user=user,
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
            image = DockerImages.query.filter(text("DockerImages.ImageName = :image_name").params(image_name=val)).first()
            val = image.ID
        elif type == 'Application Name':
            key = 'ApplicationId'
            app = BusinessApplications.query.filter(text("BusinessApplications.ApplicationName = :app_name").params(app_name=val)).first()
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


@vulns.route("/all_app_vulns_filtered/<app_name>/<type>/<val>", methods=['GET', 'POST'])
@login_required
def all_app_vulns_filtered(app_name, type, val):
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
        allowed_types = {
            'Docker Image Name': 'DockerImageId',
            'Application Name': 'ApplicationId'
        }
        allowed_columns = {
            'Docker Image Name': 'DockerImageId',
            'Application Name': 'ApplicationId',
            # Add other allowed mappings here
        }
        if type in allowed_columns:
            key = allowed_columns[type]
            if type == 'Docker Image Name':
                image = DockerImages.query.filter(DockerImages.ImageName == val).first()
                val = image.ID
            elif type == 'Application Name':
                app = BusinessApplications.query.filter(BusinessApplications.ApplicationName == val).first()
                val = app.ID
        else:
            raise ValueError(f"Invalid filter type: {type}")
        if val.endswith("-"):
            filter_list = [f"{key} LIKE :val"]
            val = f"{val}%"
        elif val == 'ALL':
            filter_list = [f"{key} LIKE :val"]
            val = "%-%"
        else:
            filter_list = [f"{key} = :val"]

        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        assets, pg_cnt, vuln_all = _get_appname_assets(app_name, orderby, per_page, page, filter_list, sql_filter)

        table_details = _set_table_details(pg_cnt, page, vuln_all, per_page, orderby)

        NAV['appbar'] = 'findings'
        app = BusinessApplications.query.filter(BusinessApplications.ApplicationName == app_name).first()
        app_data = {'ID': app.ID, 'ApplicationName': app.ApplicationName}

        return render_template('vulns/all_app_vulns_filtered.html', entities=assets, user=user, NAV=NAV, table_details= table_details,
                               filter_type=type, filter_value=val, app_data=app_data)
    except RuntimeError:
        return render_template('500.html'), 500


@vulns.route("/all_app_vulns_filtered/<app_name>/<type>/<val>/export", methods=['GET', 'POST'])
@login_required
def all_app_vulns_filtered_export(app_name, type, val):
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
            image = DockerImages.query.filter(DockerImages.ImageName == val).first()
            val = image.ID
        elif type == 'Application Name':
            key = 'ApplicationId'
            app = BusinessApplications.query.filter(BusinessApplications.ApplicationName == val).first()
            val = app.ID
        else:
            key = type.capitalize()
        # Whitelist of allowed column names
        allowed_columns = {
            'Severity': Vulnerabilities.Severity,
            'Status': Vulnerabilities.Status,
            'VulnerablePackage': Vulnerabilities.VulnerablePackage,
            'Uri': Vulnerabilities.Uri,
            'VulnerableFileName': Vulnerabilities.VulnerableFileName,
            'DockerImageId': Vulnerabilities.DockerImageId,
            'ApplicationId': Vulnerabilities.ApplicationId
        }
        if key not in allowed_columns:
            return render_template('400.html', message="Invalid filter type"), 400
        column = allowed_columns[key]
        if val.endswith("-"):
            filter_list = [column.like(f"{val}%")]
        elif val == 'ALL':
            filter_list = [column.like("%-%%")]
        else:
            filter_list = [column == val]

        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        assets, pg_cnt, vuln_all = _get_appname_assets(app_name, orderby, per_page, page, filter_list, sql_filter)

        table_details = _set_table_details(pg_cnt, page, vuln_all, per_page, orderby)

        now = datetime.datetime.utcnow()
        html = render_template('vulns/all_app_vulns_filtered_pdf.html', now=now, entities=assets, user=user,
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


@vulns.route("/all_app_vulns_filtered/<app_name>/<type>/<val>/csv", methods=['GET', 'POST'])
@login_required
def all_app_vulns_filtered_csv(app_name, type, val):
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
        # Define a mapping of valid types to safe column names
        type_to_column = {
            'severity': 'Severity',
            'status': 'Status',
            'import': 'VulnerablePackage',
            'endpoint': 'Uri',
            'file': 'VulnerableFileName',
            'docker': 'DockerImageId',
            'Docker Image Name': 'DockerImageId',
            'Application Name': 'ApplicationId',
        }

        # Validate and map the type to a column name
        if type in type_to_column:
            key = type_to_column[type]
        else:
            raise ValueError(f"Invalid type: {type}")

        # Decode `val` for specific types
        if type in ['endpoint', 'file']:
            val = base64.b64decode(val.encode()).decode()
        elif type == 'Docker Image Name':
            image = DockerImages.query.filter(text("DockerImages.ImageName=:val").params(val=val)).first()
            val = image.ID
        elif type == 'Application Name':
            app = BusinessApplications.query.filter(text("BusinessApplications.ApplicationName=:val").params(val=val)).first()
            val = app.ID
        if val.endswith("-"):
            filter_list = [text(f"{key} LIKE :val").params(val=f"{val}%")]
        elif val == 'ALL':
            filter_list = [text(f"{key} LIKE :val").params(val="%-%")]
        else:
            filter_list = [text(f"{key} = :val").params(val=val)]

        new_dict = {
            'db_name': 'Vulnerabilities',
            "sort_field": "VulnerabilityID"
        }
        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        assets, pg_cnt, vuln_all = _get_appname_assets(app_name, orderby, per_page, page, filter_list, sql_filter)

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


def _get_appname_assets(app_name, orderby, per_page, page, filter_list, sql_filter):
    # Define a whitelist of allowed columns for ordering
    allowed_orderby_columns = [
        "VulnerabilityID", "VulnerabilityName", "CVEID", "CWEID", "Description", "ReleaseDate", "Severity",
        "Classification", "Source", "LastModifiedDate", "ReferenceName", "ReferenceUrl", "ReferenceTags",
        "AddDate", "SourceCodeFileId", "SourceCodeFileStartLine", "SourceCodeFileStartCol", "SourceCodeFileEndLine",
        "SourceCodeFileEndCol", "DockerImageId", "ApplicationId", "HostId", "Uri", "HtmlMethod", "Param",
        "Attack", "Evidence", "Solution", "VulnerablePackage", "VulnerableFileName", "VulnerableFilePath",
        "Status", "MitigationDate", "ApplicationName", "ApplicationAcronym"
    ]
    # Validate orderby against the whitelist
    if orderby not in allowed_orderby_columns:
        raise ValueError(f"Invalid orderby column: {orderby}")

    full_filter = text(f' AND ({sql_filter}) AND (BusinessApplications.ApplicationName = :app_name) AND ({VULN_STATUS_IS_NOT_CLOSED})')
    full_filter = text(" AND ").join(filter_list)
    full_filter = text(f"{full_filter} AND (BusinessApplications.ApplicationName = :app_name) AND ({VULN_STATUS_IS_NOT_CLOSED})").params(app_name=app_name)
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
                Vulnerabilities.Status, Vulnerabilities.MitigationDate, BusinessApplications.ApplicationName,
                BusinessApplications.ApplicationAcronym
            ).join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
        .filter(text(full_filter).params(app_name=app_name, val=val)) \
        .order_by(getattr(Vulnerabilities, orderby)) \
        .yield_per(per_page) \
        .paginate(page=page, per_page=per_page, error_out=False)
    pg_cnt = ceil((vuln_all.total / per_page))
    schema = VulnerabilitiesSchema(many=True)
    assets = schema.dump(vuln_all.items)
    return assets, pg_cnt, vuln_all
