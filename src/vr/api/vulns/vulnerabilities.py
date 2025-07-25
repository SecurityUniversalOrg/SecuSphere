import datetime
from vr import db, app
from flask import jsonify, request
from sqlalchemy import text, bindparam, update
from sqlalchemy.orm import Session
from vr.api import api
from vr.admin.auth_functions import verify_api_key, get_token_auth_header
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema
from vr.assets.model.businessapplications import BusinessApplications
from vr.vulns.model.vulnerabilityscans import MakeVulnerabilityScansSchema, VulnerabilityScans
from vr.vulns.model.vulnerabilityslas import VulnerabilitySLAs
from vr.vulns.model.vulnerabilityslaapppair import VulnerabilitySLAAppPair
from vr.orchestration.model.dockerimages import DockerImages
from vr.orchestration.model.dockerimageapppair import DockerImageAppPair
from vr.functions.routing_functions import check_entity_permissions
from vr.admin.oauth2 import require_oauth
from vr.admin.functions import db_connection_handler
from authlib.integrations.flask_oauth2 import current_token
import re


ERROR_RESP = "Error: Invalid API Request"


@api.route("/api/vulnerabilities")
@require_oauth('read:vulnerabilities')
def get_vulnerabilities():
    token = current_token
    auth, user_id, is_admin = verify_api_key(token)
    response = jsonify({'response': ERROR_RESP}), 403
    if auth == 'valid':
        permitted = check_entity_permissions(is_admin)
        if permitted:
            vulns_all = Vulnerabilities.query.all()
            schema = VulnerabilitiesSchema(many=True)
            vulns = schema.dump(
                filter(lambda t: t.AddDate != '', vulns_all)
            )
            response = jsonify(vulns), 200
    return response


@api.route('/api/search_vulnerabilities', methods=['POST'])
@require_oauth('read:vulnerabilities')
def search_vulnerabilities():
    token = current_token
    auth, user_id, is_admin = verify_api_key(token)
    response = jsonify({'response': ERROR_RESP}), 403
    if auth == 'valid':
        permitted = check_entity_permissions(is_admin)
        if permitted:
            src_filter = request.get_json()
            filter_list = []
            valid_columns = {column.name for column in Vulnerabilities.__table__.columns}
            filters = {}
            for key, val in src_filter.items():
                if key in valid_columns:
                    filters[key] = val
            vulns_all = Vulnerabilities.query.filter_by(**filters).all()
            schema = VulnerabilitiesSchema(many=True)
            vulns = schema.dump(vulns_all)
            response = jsonify(vulns), 200
    return response


@api.route("/api/add_vulnerabilities", methods=["POST"])
@require_oauth('write:vulnerabilities')
def add_vulnerabilities():
    token = current_token
    auth, user_id, is_admin = verify_api_key(token)
    response = jsonify({'response': ERROR_RESP}), 403
    if auth == "valid":
        permitted = check_entity_permissions(is_admin)
        if permitted:
            req_raw = request.get_json()
            app_cmdb_id, scan_id = add_vulns_background_process(req_raw)
            update_vulnerabilities_status(app_cmdb_id, scan_id, req_raw)
            response = jsonify({"Status": "success"}), 200
    return response


def update_vulnerabilities_status(app_cmdb_id, scan_id, req_raw):
    scan_type = f"CI/CD-{req_raw['scanType']}"
    if req_raw['findings']:
        scans = VulnerabilityScans\
            .query\
            .filter(text("VulnerabilityScans.ApplicationId=:app_cmdb_id AND VulnerabilityScans.ScanType=:scan_type")\
            .params(app_cmdb_id=app_cmdb_id, scan_type=scan_type))\
            .order_by(VulnerabilityScans.ID.desc())\
            .limit(2)\
            .all()
    else:
        scans = []
    scans_to_check = []
    for i in scans:
        if i.ID not in scans_to_check:
            scans_to_check.append(i.ID)
        scans_to_check = sorted(scans_to_check, reverse=True)
    if req_raw['scanType'] == 'Container':
        if 'dockerImg' in req_raw:
            previous_vulns = Vulnerabilities \
                .query \
                .join(VulnerabilityScans, VulnerabilityScans.ID == Vulnerabilities.ScanId) \
                .join(DockerImages, DockerImages.ID == Vulnerabilities.DockerImageId) \
                .filter(text(
                "(Vulnerabilities.Status NOT LIKE 'Closed-%' OR Vulnerabilities.Status='Closed-Mitigated') AND (Vulnerabilities.ApplicationId=:app_cmdb_id) AND (Vulnerabilities.SourceType=:source_type) AND (Vulnerabilities.InitialScanId!=:scan_id) AND (DockerImages.ImageName=:docker_img)")
                ).params(app_cmdb_id=app_cmdb_id, source_type=scan_type.split('CI/CD-')[1], scan_id=scan_id, docker_img=req_raw['dockerImg']) \
                .all()
    else:
        previous_vulns = Vulnerabilities\
            .query\
            .join(VulnerabilityScans, VulnerabilityScans.ID==Vulnerabilities.ScanId)\
            .filter(text(f"(Vulnerabilities.Status NOT LIKE 'Closed-%' OR Vulnerabilities.Status='Closed-Mitigated') AND (Vulnerabilities.ApplicationId='{app_cmdb_id}') AND (Vulnerabilities.SourceType='{scan_type.split('CI/CD-')[1]}') AND (Vulnerabilities.InitialScanId!='{scan_id}')"))\
            .all()
    closed_cnt = 0
    new_vulns = req_raw['findings']

    for i in previous_vulns:
        found = False
        prev_id_check = i.VulnerabilityID
        for j in new_vulns:
            new_id_check = j['b_VulnerabilityID'] if 'b_VulnerabilityID' in j else None
            if (prev_id_check == new_id_check) and (i.SourceType == j['SourceType']):
                found = True
                break
        if not found and i.Status != "Closed-Mitigated":
            now = datetime.datetime.utcnow()
            db.session.query(Vulnerabilities).filter(Vulnerabilities.VulnerabilityID == int(i.VulnerabilityID)).update(
                {Vulnerabilities.Status: 'Closed-Mitigated', Vulnerabilities.LastModifiedDate: now, Vulnerabilities.MitigationDate: now},
                synchronize_session=False)
            db_connection_handler(db)
            closed_cnt += 1


def add_vulns_background_process(req_raw):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    app_name = req_raw['appName']
    git_url = req_raw['gitUrl']
    git_branch = req_raw['branch']
    findings = req_raw['findings']
    scan_type = req_raw['scanType']

    app_cmdb_id = get_app_id(app_name, git_url)

    docker_img_id = None
    if 'dockerImg' in req_raw:
        docker_img_id = get_docker_img_id(req_raw['dockerImg'], app_cmdb_id)

    if findings:
        source = findings[0]['Source']
        scan_dict = {
            "ScanName": f"{source}",
            "ScanType": f"CI/CD-{scan_type}",
            "ScanTargets": str(app_cmdb_id),
            "ScanStartDate": now,
            "ApplicationId": app_cmdb_id,
            "Branch": git_branch
        }
        scan_id = _add_vulnerabilityscan(scan_dict)
    else:
        scan_id = None

    full_findings = []
    for i in findings:
        i['ScanId'] = scan_id
        i['ApplicationId'] = app_cmdb_id
        if docker_img_id:
            i['DockerImageId'] = docker_img_id
        if i['VulnerablePackage']:
            pattern = r'(?:pkg:[\w\-]+/)?([^@:/-]+)(?:[@:\-]([\d\w\.-]+))?'
            match = re.match(pattern, i['VulnerablePackage'])
            if match:
                i['VulnerablePackage'] = match.group(1)
                i['VulnerablePackageVersion'] = match.group(2) if match.group(2) else 'No version'

        full_findings.append(i)

    if full_findings:
        source_type = scan_type
        new_vulns, dup_vulns, reopened_vulns = _get_vulns_for_src_and_app(source_type, app_cmdb_id, source, full_findings, scan_id)

        _set_new_and_dup_vulns(new_vulns, dup_vulns, source_type, source, app_cmdb_id)
        _update_reopened_vulns(reopened_vulns)
    return app_cmdb_id, scan_id


def _update_reopened_vulns(reopened_vulns):
    for i in reopened_vulns:
        db.session.query(Vulnerabilities).filter(text("Vulnerabilities.VulnerabilityID = :vuln_id").bindparams(vuln_id=i['VulnerabilityID'])).update(
            values={"Status": "Open-Rediscovered"},
            synchronize_session=False)
        db_connection_handler(db)


def get_docker_img_id(docker_img_and_tag, app_cmdb_id):
    img_name = docker_img_and_tag.split(':')[0]
    img_tag = docker_img_and_tag.split(':')[1]
    img = DockerImages.query.filter(
        text("DockerImages.ImageName = :img_name AND DockerImages.ImageTag = :img_tag")
        .bindparams(img_name=img_name, img_tag=img_tag)
    ).first()
    if img:
        docker_img_id = img.ID
        img_obj = img
    else:
        now = datetime.datetime.utcnow()
        new_img = DockerImages(
            AddDate=now,
            ImageName=img_name,
            ImageTag=img_tag
        )
        db.session.add(new_img)
        db_connection_handler(db)
        docker_img_id = new_img.ID
        img_obj = new_img
    app_id_list = img_obj.AppIdList.split(',') if img_obj.AppIdList else []
    if str(app_cmdb_id) not in app_id_list:
        add_app_id_to_docker_img(docker_img_id, str(app_cmdb_id), app_id_list)
    return docker_img_id


def add_app_id_to_docker_img(docker_img_id, app_cmdb_id, app_id_list):
    app_id_list.append(app_cmdb_id)
    app_id_list_str = ','.join(app_id_list)
    if not app_id_list_str.endswith(','):
        app_id_list_str += ","
    db.session.query(DockerImages).filter(text(f"DockerImages.ID={docker_img_id}")).update(values={"AppIdList": app_id_list_str},
                                                                     synchronize_session=False)
    db_connection_handler(db)
    new_pair = DockerImageAppPair(
        DockerImageID=docker_img_id,
        AppID=app_cmdb_id
    )
    db.session.add(new_pair)
    db_connection_handler(db)


def get_app_id(app_name, git_url):
    if '--' in app_name:
        a_name = app_name.split('--')[0]
        app_component = app_name.split('--')[1]
    else:
        a_name = app_name
        app_component = app_name.lower()
    app = BusinessApplications.query.filter(
        BusinessApplications.ApplicationName == a_name,
        BusinessApplications.ApplicationAcronym == app_component.lower()
    ).first()
    if app:
        app_id = app.ID
        if git_url and not app.RepoURL:
            app.RepoURL = git_url
            db.session.add(app)
            db_connection_handler(db)
    else:
        now = datetime.datetime.utcnow()
        new_app = BusinessApplications(
            ApplicationName=a_name,
            AssignmentChangedDate=now,
            MalListingAddDate=now,
            ApplicationAcronym=app_component.lower(),
            RepoURL=git_url
        )
        db.session.add(new_app)
        db_connection_handler(db)
        app_id = new_app.ID
        add_application_sla_policy(app_id)
    return app_id


def add_application_sla_policy(app_id):
    default_sla = VulnerabilitySLAs.query.filter(text("Name='Default'")).first()
    new_sla_pairing = VulnerabilitySLAAppPair(ApplicationID=app_id, SlaID=default_sla.ID)
    db.session.add(new_sla_pairing)
    db_connection_handler(db)


def _add_vulnerabilityscan(scan_dict):
    scan = MakeVulnerabilityScansSchema().load(scan_dict)
    db.session.add(scan)
    db_connection_handler(db)
    return scan.ID


def _set_new_and_dup_vulns(new_vulns, dup_vulns, source_type, source, app_id):
    if new_vulns or dup_vulns:
        engine = db.engine
    if new_vulns:
        _add_new_vulns(new_vulns, engine)
    if dup_vulns:
        sourced_dup_vulns = _setup_duplicate_vulns(source_type, dup_vulns)
        stmt = _set_dup_vuln_sql_stmts(source_type, source, app_id)
        if stmt is not None:
            with engine.begin() as conn:
                conn.execute(stmt, sourced_dup_vulns)


def _add_new_vulns(new_vulns, engine):
    with Session(engine) as s:
        s.bulk_save_objects(new_vulns)
        s.commit()


def _setup_duplicate_vulns(source_type, dup_vulns):
    sourced_dup_vulns = []
    for vuln in dup_vulns:
        if app.config['ENV'] == 'test':
            vuln['LastModifiedDate'] = datetime.datetime.utcnow().replace(microsecond=0)
            if vuln['ReleaseDate']:
                vuln['ReleaseDate'] = datetime.datetime.strptime(vuln['ReleaseDate'], '%Y-%m-%d %H:%M:%S')
            if vuln['AddDate']:
                vuln['AddDate'] = datetime.datetime.strptime(vuln['AddDate'], '%Y-%m-%d %H:%M:%S')
        else:
            vuln['LastModifiedDate'] = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        vuln['b_VulnerabilityID'] = vuln['VulnerabilityID']
        vuln['b_Status'] = vuln['Status']
        del vuln["VulnerabilityID"]
        del vuln["Status"]
        if source_type == 'FileName':
            vuln['b_VulnerabilityName'] = vuln['VulnerabilityName']
            vuln['b_VulnerableFilePath'] = vuln['VulnerableFilePath']
        elif source_type == 'DockerImage' or source_type == 'Container':
            vuln['b_VulnerabilityName'] = vuln['VulnerabilityName']
            vuln['b_CVEID'] = vuln['CVEID']
            vuln['b_DockerImageId'] = vuln['DockerImageId']
        elif source_type == 'WebApp' or source_type == 'DAST' or source_type == 'DASTAPI':
            vuln['b_VulnerabilityName'] = vuln['VulnerabilityName']
            vuln['b_Uri'] = vuln['Uri']
            vuln['b_HtmlMethod'] = vuln['HtmlMethod']
            vuln['b_Param'] = vuln['Param']
        elif source_type == 'SCA':
            vuln['b_CVEID'] = vuln['CVEID']
            vuln['b_VulnerablePackage'] = vuln['VulnerablePackage']
            vuln['b_VulnerableFilePath'] = vuln['VulnerableFilePath']
        elif source_type == 'IaC' or source_type == 'Secret':
            vuln['b_Description'] = vuln['Description']
            vuln['b_VulnerableFileName'] = vuln['VulnerableFileName']
        if vuln['LastModifiedDate']:
            sourced_dup_vulns.append(vuln)

    return sourced_dup_vulns


def _set_dup_vuln_sql_stmts(source_type, source, app_id):
    values_dict = {
        'LastModifiedDate': bindparam('LastModifiedDate'),
        'ScanId': bindparam('ScanId'),
    }
    if source_type == 'FileName':
        stmt = update(Vulnerabilities). \
            where(Vulnerabilities.ApplicationId == app_id, Vulnerabilities.Source == source,
                  Vulnerabilities.VulnerabilityName == bindparam('b_VulnerabilityName'),
                  Vulnerabilities.VulnerableFilePath == bindparam('b_VulnerableFilePath')). \
            values(values_dict)

    elif source_type == 'DockerImage' or source_type == 'Container':
        stmt = update(Vulnerabilities). \
            where(Vulnerabilities.ApplicationId == app_id, Vulnerabilities.Source == source,
                  Vulnerabilities.VulnerabilityName == bindparam('b_VulnerabilityName'),
                  Vulnerabilities.CVEID == bindparam('b_CVEID'),
                  Vulnerabilities.DockerImageId == bindparam('b_DockerImageId')). \
            values(values_dict)

    elif source_type == 'WebApp' or source_type == 'DAST' or source_type == 'DASTAPI':
        stmt = update(Vulnerabilities). \
            where(Vulnerabilities.ApplicationId == app_id, Vulnerabilities.Source == source,
                  Vulnerabilities.VulnerabilityName == bindparam('b_VulnerabilityName'),
                  Vulnerabilities.Uri == bindparam('b_Uri'),
                  Vulnerabilities.HtmlMethod == bindparam('b_HtmlMethod'),
                  Vulnerabilities.Param == bindparam('b_Param')). \
            values(values_dict)

    elif source_type == 'SCA':
        stmt = update(Vulnerabilities). \
            where(Vulnerabilities.ApplicationId == app_id, Vulnerabilities.Source == source,
                  Vulnerabilities.CVEID == bindparam('b_CVEID'),
                  Vulnerabilities.VulnerablePackage == bindparam('b_VulnerablePackage'),
                  Vulnerabilities.VulnerableFilePath == bindparam('b_VulnerableFilePath')). \
            values(values_dict)

    elif source_type == 'IaC' or source_type == 'Secret':
        stmt = update(Vulnerabilities). \
            where(Vulnerabilities.ApplicationId == app_id, Vulnerabilities.Source == source,
                  Vulnerabilities.Description == bindparam('b_Description'),
                  Vulnerabilities.VulnerableFileName == bindparam('b_VulnerableFileName')). \
            values(values_dict)
    else:
        stmt = None
    return stmt


def _get_vulns_for_src_and_app(source_type, app_id, source, req_raw, scan_id):
    new_vulns = []
    dup_vulns = []
    reopened_vuln = []
    vulns_all = Vulnerabilities.query \
        .filter(text("ApplicationId = :app_id AND Source = :source").params(app_id=app_id, source=source)) \
        .all()

    # Determine unique
    for r in req_raw:
        new = True
        new_vuln_name = r['VulnerabilityName']
        status = None
        if source_type == 'FileName':
            new, vuln_id, status = _unique_check_filename(new, r, vulns_all, new_vuln_name)
        elif source_type == 'DockerImage' or source_type == 'Container':
            new, vuln_id, status = _unique_check_docker_image(new, r, vulns_all, new_vuln_name)
        elif source_type == 'WebApp' or source_type == 'DAST' or source_type == 'DASTAPI':
            new, vuln_id, status = _unique_check_webapp(new, r, vulns_all, new_vuln_name)
        elif source_type == 'SCA':
            new, vuln_id, status = _unique_check_sca(new, r, vulns_all, new_vuln_name)
        elif source_type == 'IaC' or source_type == 'Secret':
            new, vuln_id, status = _unique_check_iac_or_secret(new, r, vulns_all, new_vuln_name)
        if new:
            r['InitialScanId'] = scan_id
            new_vuln = MakeVulnerabilitiesSchema().load(r)
            new_vulns.append(new_vuln)
        elif status == 'Closed-Mitigated':
            r['Status'] = status
            r['VulnerabilityID'] = vuln_id
            reopened_vuln.append(r)
        else:
            r['Status'] = status
            r['VulnerabilityID'] = vuln_id
            dup_vulns.append(r)
    return new_vulns, dup_vulns, reopened_vuln


def _unique_check_filename(new, r, vulns_all, new_vuln_name):
    new_vuln_file = r['VulnerableFilePath']
    vuln_id = None
    status = None
    for v in vulns_all:
        vuln_name = v.VulnerabilityName
        vuln_file = v.VulnerableFilePath
        if new_vuln_name == vuln_name and new_vuln_file == vuln_file:
            new = False
            vuln_id = v.VulnerabilityID
            status = v.Status
    return new, vuln_id, status


def _unique_check_docker_image(new, r, vulns_all, new_vuln_name):
    cve_id = r['CVEID']
    new_docker_img = r['DockerImageId']
    vuln_id = None
    status = None
    for v in vulns_all:
        vuln_name = v.VulnerabilityName
        docker_img = v.DockerImageId
        new_cve_id = v.CVEID
        if new_vuln_name == vuln_name and new_docker_img == docker_img and new_cve_id == cve_id:
            new = False
            vuln_id = v.VulnerabilityID
            status = v.Status
    return new, vuln_id, status


def _unique_check_webapp(new, r, vulns_all, new_vuln_name):
    new_uri = r['Uri']
    new_method = r['HtmlMethod']
    new_param = r['Param']
    vuln_id = None
    status = None
    for v in vulns_all:
        vuln_name = v.VulnerabilityName
        uri = v.Uri
        method = v.HtmlMethod
        param = v.Param
        if new_vuln_name == vuln_name and new_uri == uri and new_method == method and new_param == param:
            new = False
            vuln_id = v.VulnerabilityID
            status = v.Status
    return new, vuln_id, status


def _unique_check_sca(new, r, vulns_all, new_vuln_name):
    new_cve = r['CVEID']
    new_pkg = r['VulnerablePackage']
    new_fp = r['VulnerableFilePath']
    new_desc = r['Description']
    vuln_id = None
    status = None
    for v in vulns_all:
        vuln_name = v.VulnerabilityName
        cve = v.CVEID
        pkg = v.VulnerablePackage
        fp = v.VulnerableFilePath
        desc = v.Description
        if new_vuln_name == vuln_name and new_cve == cve and new_pkg == pkg and new_fp == fp and new_desc == desc:
            new = False
            vuln_id = v.VulnerabilityID
            status = v.Status
    return new, vuln_id, status


def _unique_check_iac_or_secret(new, r, vulns_all, new_vuln_name):
    new_desc = r['Description']
    new_fn = r['VulnerableFileName']
    vuln_id = None
    status = None
    for v in vulns_all:
        vuln_name = v.VulnerabilityName
        desc = v.Description
        fn = v.VulnerableFileName
        if new_vuln_name == vuln_name and new_desc == desc and new_fn == fn:
            new = False
            vuln_id = v.VulnerabilityID
            status = v.Status
    return new, vuln_id, status


@api.route('/api/edit_vulnerabilities', methods=['POST'])
@require_oauth('write:vulnerabilities')
def edit_vulnerabilities():
    token = current_token
    auth, user_id, is_admin = verify_api_key(token)
    response = jsonify({'response': ERROR_RESP}), 403
    if auth == 'valid':
        req_raw = request.get_json()
        src_filter = req_raw['filter']
        req_dict = req_raw['values']
        req = {**src_filter, **req_dict}
        entity_id = req[list(req.keys())[0]]
        permitted = check_entity_permissions(is_admin)
        if permitted:
            query = db.session.query(Vulnerabilities)
            for key, val in src_filter.items():
                query = query.filter(getattr(Vulnerabilities, key) == val)
            query.update(values=req_dict, synchronize_session=False)
            db_connection_handler(db)
            response = jsonify({"Status": "Success"}), 200
    return response


@api.route('/api/delete_vulnerabilities', methods=['POST'])
@require_oauth('write:vulnerabilities')
def delete_vulnerabilities():
    token = current_token
    auth, user_id, is_admin = verify_api_key(token)
    response = jsonify({'response': ERROR_RESP}), 403
    if auth == 'valid':
        permitted = check_entity_permissions(is_admin)
        if permitted:
            req_raw = request.get_json()
            for key, val in req_raw.items():
                vulns = Vulnerabilities.query.filter(getattr(Vulnerabilities, key) == val).all()
                for vuln in vulns:
                    db.session.delete(vuln)
                db_connection_handler(db)
            response = jsonify({"Status": "Deleted"}), 200
    return response


