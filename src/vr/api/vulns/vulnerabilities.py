import datetime
from vr import db, app
from flask import jsonify, request, json
from sqlalchemy import text, bindparam, create_engine, update
from sqlalchemy.orm import Session
from vr.api import api
from vr.admin.auth_functions import verify_api_key, get_token_auth_header
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema
from vr.assets.model.businessapplications import BusinessApplications
from vr.vulns.model.vulnerabilityscans import MakeVulnerabilityScansSchema, VulnerabilityScans
from vr.vulns.model.vulnerabilityslas import VulnerabilitySLAs
from vr.vulns.model.vulnerabilityslaapppair import VulnerabilitySLAAppPair
from vr.sourcecode.model.appcodecomposition import AppCodeComposition
from vr.orchestration.model.dockerimages import DockerImages
from vr.orchestration.model.dockerimageapppair import DockerImageAppPair
from vr.vulns.model.pipelinejobs import PipelineJobs
from vr.vulns.model.sgconfigsettingsperjob import SgConfigSettingsPerJob
from vr.vulns.model.sgresultsperjob import SgResultsPerJob
from vr.functions.routing_functions import check_entity_permissions
from vr.admin.oauth2 import require_oauth
from authlib.integrations.flask_oauth2 import current_token
from requests.auth import HTTPBasicAuth
import requests
from config_engine import JENKINS_USER, JENKINS_PW, JENKINS_KEY


ERROR_RESP = "Error: Invalid API Request"

@api.route("/vulnerabilities")
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


@api.route('/search_vulnerabilities', methods=['POST'])
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
            for key in src_filter:
                val = src_filter[key].replace("'", "")
                filter_list.append(f"{key} = '{val}'")
            vulns_all = Vulnerabilities.query.filter(text(" AND ".join(filter_list))).all()
            schema = VulnerabilitiesSchema(many=True)
            vulns = schema.dump(vulns_all)
            response = jsonify(vulns), 200
    return response


@api.route("/add_vulnerabilities", methods=["POST"])
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
            .filter(text(f"VulnerabilityScans.ApplicationId={app_cmdb_id} AND VulnerabilityScans.ScanType='{scan_type}'"))\
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

    previous_vulns = Vulnerabilities\
        .query\
        .join(VulnerabilityScans, VulnerabilityScans.ID==Vulnerabilities.ScanId)\
        .filter(text(f"(Vulnerabilities.Status NOT LIKE 'Closed-%' OR Vulnerabilities.Status='Closed-Mitigated') AND (Vulnerabilities.ApplicationId='{app_cmdb_id}') AND (Vulnerabilities.SourceType='{scan_type.split('CI/CD-')[1]}')"))\
        .all()
    closed_cnt = 0
    new_vulns = req_raw['findings']

    for i in previous_vulns:
        found = False
        prev_id_check = i.VulnerabilityID
        for j in new_vulns:
            new_id_check = j['b_VulnerabilityID'] if 'b_VulnerabilityID' in j else None
            if prev_id_check == new_id_check:
                found = True
                break
        if not found and i.Status != "Closed-Mitigated":
            db.session.query(Vulnerabilities).filter(Vulnerabilities.VulnerabilityID == int(i.VulnerabilityID)).update(
                {Vulnerabilities.Status: 'Closed-Mitigated', Vulnerabilities.LastModifiedDate: datetime.datetime.utcnow()},
                synchronize_session=False)
            db.session.commit()
            closed_cnt += 1


def add_vulns_background_process(req_raw):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    app_name = req_raw['appName']
    git_url = req_raw['giturl']
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
        full_findings.append(i)

    if full_findings:
        source_type = scan_type
        new_vulns, dup_vulns, reopened_vulns = _get_vulns_for_src_and_app(source_type, app_cmdb_id, source, full_findings, scan_id)

        _set_new_and_dup_vulns(new_vulns, dup_vulns, source_type, source, app_cmdb_id)
        _update_reopened_vulns(reopened_vulns)
    return app_cmdb_id, scan_id


def _update_reopened_vulns(reopened_vulns):
    for i in reopened_vulns:
        db.session.query(Vulnerabilities).filter(text(f"Vulnerabilities.VulnerabilityID={i['VulnerabilityID']}")).update(
            values={"Status": "Open-New"},
            synchronize_session=False)
        db.session.commit()


def get_docker_img_id(docker_img_and_tag, app_cmdb_id):
    img_name = docker_img_and_tag.split(':')[0]
    img_tag = docker_img_and_tag.split(':')[1]
    img = DockerImages.query.filter(text(f"DockerImages.ImageName='{img_name}' AND DockerImages.ImageTag='{img_tag}'")).first()
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
        db.session.commit()
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
    db.session.commit()
    new_pair = DockerImageAppPair(
        DockerImageID=docker_img_id,
        AppID=app_cmdb_id
    )
    db.session.add(new_pair)
    db.session.commit()


def get_app_id(app_name, git_url):
    app = BusinessApplications.query.filter(text(f"BusinessApplications.RepoURL='{git_url}' AND BusinessApplications.ApplicationName='{app_name}'")).first()
    if app:
        app_id = app.ID
    else:
        now = datetime.datetime.utcnow()
        new_app = BusinessApplications(
            ApplicationName=app_name,
            RepoURL=git_url,
            AssignmentChangedDate=now,
            MalListingAddDate=now
        )
        db.session.add(new_app)
        db.session.commit()
        app_id = new_app.ID
        add_application_sla_policy(app_id)
    return app_id


def add_application_sla_policy(app_id):
    default_sla = VulnerabilitySLAs.query.filter(text("Name='Default'")).first()
    new_sla_pairing = VulnerabilitySLAAppPair(ApplicationID=app_id, SlaID=default_sla.ID)
    db.session.add(new_sla_pairing)
    db.session.commit()


def _add_vulnerabilityscan(scan_dict):
    scan = MakeVulnerabilityScansSchema().load(scan_dict)
    db.session.add(scan)
    db.session.commit()
    return scan.ID


def _set_new_and_dup_vulns(new_vulns, dup_vulns, source_type, source, app_id):
    if new_vulns or dup_vulns:
        engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
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
        .filter(text(f"ApplicationId='{app_id}' AND Source='{source}'")) \
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


@api.route('/edit_vulnerabilities', methods=['POST'])
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
            filter_db_keys = []
            for key in src_filter:
                val = src_filter[key].replace("'", "")
                filter_db_keys.append(f"{key}='{val}'")
            filter_db = " AND ".join(filter_db_keys)
            db.session.query(Vulnerabilities).filter(text(filter_db)).update(values=req_dict,
                                                                             synchronize_session=False)
            db.session.commit()
            response = jsonify({"Status": "Success"}), 200
    return response


@api.route('/delete_vulnerabilities', methods=['POST'])
@require_oauth('write:vulnerabilities')
def delete_vulnerabilities():
    token = current_token
    auth, user_id, is_admin = verify_api_key(token)
    response = jsonify({'response': ERROR_RESP}), 403
    if auth == 'valid':
        permitted = check_entity_permissions(is_admin)
        if permitted:
            req_raw = request.get_json()
            for key in req_raw:
                val = req_raw[key].replace("'", "")
                vulns = Vulnerabilities.query.filter(text(f"{key}='{val}'")).all()
                for vuln in vulns:
                    db.session.delete(vuln)
                db.session.commit()
            response = jsonify({"Status": "Deleted"}), 200
    return response


