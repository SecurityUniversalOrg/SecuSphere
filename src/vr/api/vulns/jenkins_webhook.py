import requests
import datetime
from threading import Thread
from flask import jsonify, request, json
from vr import db, app
from vr.api import api
from requests.auth import HTTPBasicAuth
# from config_engine import JENKINS_USER, JENKINS_KEY, JENKINS_PROJECT, JENKINS_HOST, JENKINS_TOKEN
from config_engine import getConfigs
from vr.admin.oauth2 import require_oauth
from sqlalchemy import text
from vr.assets.model.cicdpipelinebuilds import CICDPipelineBuilds
from vr.assets.model.cicdpipelinestagedata import CICDPipelineStageData
from vr.assets.model.integrations import Integrations
from vr.assets.model.appintegrations import AppIntegrations
from vr.orchestration.model.cicdpipelines import CICDPipelines
from vr.assets.model.businessapplications import BusinessApplications
from vr.vulns.model.vulnerabilityslas import VulnerabilitySLAs
from vr.vulns.model.vulnerabilityslaapppair import VulnerabilitySLAAppPair
from vr.orchestration.model.parallelsecuritypipelineruns import ParallelSecurityPipelineRuns
from vr.vulns.model.sgglobalthresholds import SgGlobalThresholds
from vr.admin.functions import db_connection_handler
import traceback


@api.route('/api/jenkins_webhook', methods=['POST'])
@require_oauth('write:vulnerabilities')
def jenkins_webhook():
    getConfigs(app.config)
    all = request.form
    payload_dict = json.loads(all['payload'])
    ref = payload_dict['ref']
    created_status = payload_dict['created']
    if ref.startswith('refs/heads/security/') and created_status:
        if '--' in ref:
            tests_to_run = ref.split('--')[1]
        elif 'all' in ref.lower():
            tests_to_run = 'ALL'
        else:
            response = jsonify({"Status": "Not Applicable"}), 200
            return response
        git_url = f"{payload_dict['repository']['html_url']}.git"
        git_branch = payload_dict['base_ref'].split('refs/heads/')[1]
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            'token': JENKINS_TOKEN,
            'GIT_URL': git_url,
            'TESTS': tests_to_run.upper(),
            'GIT_BRANCH': git_branch
        }
        url = f'{JENKINS_HOST}/job/{JENKINS_PROJECT}/buildWithParameters'
        resp = requests.post(url, headers=headers, data=data, auth=HTTPBasicAuth(JENKINS_USER, JENKINS_KEY))
        response = jsonify({"Status": resp.status_code}), 200
    else:
        response = jsonify({"Status": "Not Applicable"}), 200
    return response


@api.route('/api/jenkins_pipeline_reporter', methods=['POST'])
@require_oauth('write:vulnerabilities')
def jenkins_pipeline_reporter():
    try:
        # Decode bytes object to string
        report_data_str = request.data.decode('utf-8')

        # Convert string to JSON (Python dictionary)
        report_data_json = json.loads(report_data_str)

        # Now report_data_json is a standard Python dictionary
        _process_pipeline_report(report_data_json)

        response = jsonify({"Status": 200}), 200
        return response


    except Exception as e:
        print(f"ERROR: Exception during request processing: {e}")
        traceback.print_exc()
        return jsonify(error=str(e)), 500

def _process_pipeline_report(report_data_json):
    app_id = ""
    app_name = ""
    build_id = ""
    branch_name = ""
    for entry in report_data_json:
        if 'applicationName' in entry:
            app_name = entry['applicationName']
            git_url = entry['gitUrl']
            app_id = get_app_id(app_name, git_url)
            build_id = entry['buildId']
            branch_name = entry['branchName']

    # Remove the report metadata before processing
    report_data_json = [entry for entry in report_data_json if 'applicationName' not in entry]

    integration = Integrations.query.filter(Integrations.Name=="Jenkins Pipeline Reporter").first()
    if not integration:
        integration = Integrations(
            Name="Jenkins Pipeline Reporter",
            Description="This is an auto-generated integration for CI/CD Pipeline reports sent from Jenkins jobs.",
            ToolType="Jenkins"
        )
        db.session.add(integration)
        db.session.commit()
        app_integration = AppIntegrations(
            AppID=app_id,
            IntegrationID=integration.ID,
            Type="Jenkins"
        )
        db.session.add(app_integration)
        db.session.commit()
    else:
        app_integration = AppIntegrations.query.filter(text(f"AppID={app_id} AND IntegrationID={integration.ID} AND Type='Jenkins'")).first()
        if not app_integration:
            app_integration = AppIntegrations(
                AppID=app_id,
                IntegrationID=integration.ID,
                Type="Jenkins"
            )
            db.session.add(app_integration)
            db.session.commit()
    cicd_pipeline = CICDPipelines.query.filter(text(f"ApplicationID={app_id} AND IntegrationID={app_integration.ID} AND Source='Jenkins Pipeline Reporter'")).first()
    if not cicd_pipeline:
        cicd_pipeline = CICDPipelines(
            ApplicationID=app_id,
            IntegrationID=app_integration.ID,
            Name=app_name,
            Source="Jenkins Pipeline Reporter"
        )
        db.session.add(cicd_pipeline)
        db.session.commit()


    report_summary = report_data_json[len(report_data_json)-1]
    overall_status = report_summary['status']
    start_time = datetime.datetime.strptime(report_summary['start'], '%m/%d/%y %I:%M:%S %p')
    hours, minutes, seconds = [float(part) for part in report_summary['duration'].split(':')]
    milliseconds = int((hours * 3600 + minutes * 60 + seconds) * 1000)

    new_build = CICDPipelineBuilds(
        PipelineID=cicd_pipeline.ID,
        BuildName=build_id,
        BranchName=branch_name,
        Status=overall_status,
        StartTime=start_time,
        DurationMillis=milliseconds
    )
    db.session.add(new_build)
    db.session.commit()
    now = datetime.datetime.utcnow()
    for stage in report_data_json:
        if stage['stage'] != "Total Values":
            status = stage['status']
            start_time = datetime.datetime.strptime(stage['start'], '%m/%d/%y %I:%M:%S %p')
            hours, minutes, seconds = [float(part) for part in stage['duration'].split(':')]
            milliseconds = int((hours * 3600 + minutes * 60 + seconds) * 1000)

            new_build_stage = CICDPipelineStageData(
                BuildID=new_build.ID,
                StageName=stage['stage'],
                Status=status,
                StartTime=start_time,
                DurationMillis=milliseconds,
                AddDate=now
            )
            db.session.add(new_build_stage)
            db.session.commit()


def get_app_id(app_name, git_url):
    if '--' in app_name:
        a_name = app_name.split('--')[0]
        app_component = app_name.split('--')[1]
    else:
        a_name = app_name
        app_component = app_name.lower()
    app = BusinessApplications.query.filter(text(f"BusinessApplications.ApplicationName='{a_name}' AND BusinessApplications.ApplicationAcronym='{app_component.lower()}'")).first()
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


# Global dictionary to keep track of report statuses
report_statuses = {}

def add_new_scan(git_url, branch_name, report_id):
    try:
        stage_str = _determine_stages_for_app(git_url, branch_name)
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            'token': JENKINS_TOKEN,
            'GIT_URL': git_url,
            'TESTS': stage_str,
            'GIT_BRANCH': branch_name,
            'REPORT_ID': report_id
        }
        url = f'{JENKINS_HOST}/job/{JENKINS_PROJECT}/buildWithParameters'
        resp = requests.post(url, headers=headers, data=data, auth=HTTPBasicAuth(JENKINS_USER, JENKINS_KEY))
        response = jsonify({"Status": resp.status_code}), 200
    except requests.exceptions.Timeout:
        print('Processing Error')


def _determine_stages_for_app(git_url, branch_name):
    stage_str = ""

    #temp
    stage_str = "SECRET"
    return stage_str

@api.route('/api/parallel_security_scan', methods=['POST'])
@require_oauth('write:vulnerabilities')
def parallel_security_scan():
    try:
        report_data_str = request.data.decode('utf-8')
        report_data_json = json.loads(report_data_str)

        app_name = report_data_json['applicationName']
        git_url = report_data_json['gitUrl']
        branch_name = report_data_json['branchName']
        app_id = get_app_id(app_name, git_url)

        report_id = _add_vulnerability_scan(app_id, branch_name)

        # Start processing in a new thread
        processing_thread = Thread(target=add_new_scan, args=(git_url, branch_name, report_id))
        processing_thread.start()

        return jsonify({"report_id": report_id, "status": "processing started"}), 200

    except json.JSONDecodeError as json_err:
        return jsonify(error=str(json_err)), 400
    except Exception as e:
        return jsonify(error=str(e)), 500


def _add_vulnerability_scan(app_id, branch_name):
    new_scan = ParallelSecurityPipelineRuns(
        AddDate=datetime.datetime.utcnow(),
        ApplicationID=app_id,
        Branch=branch_name
    )
    db.session.add(new_scan)
    db.session.commit()
    return new_scan.ID


@api.route('/api/check_security_scan_status/<report_id>', methods=['GET'])
def check_security_scan_status(report_id):
    try:
        scan = ParallelSecurityPipelineRuns.query.filter(text(f"ID={report_id}")).first()
        if scan.ScanEndDate:
            secret = scan.SecretFindings.split(':')
            sca = scan.ScaFindings.split(':')
            sast = scan.SastFindings.split(':')
            iac = scan.IacFindings.split(':')
            container = scan.ContainerFindings.split(':')
            dast = scan.DastFindings.split(':')
            dastapi = scan.DastApiFindings.split(':')
            report = {
                'secret': {'low': int(secret[0]), 'medium': int(secret[1]), 'high': int(secret[2]), 'critical': int(secret[3])},
                'sca': {'low': int(sca[0]), 'medium': int(sca[1]), 'high': int(sca[2]), 'critical': int(sca[3])},
                'sast': {'low': int(sast[0]), 'medium': int(sast[1]), 'high': int(sast[2]), 'critical': int(sast[3])},
                'iac': {'low': int(iac[0]), 'medium': int(iac[1]), 'high': int(iac[2]), 'critical': int(iac[3])},
                'container': {'low': int(container[0]), 'medium': int(container[1]), 'high': int(container[2]), 'critical': int(container[3])},
                'dast': {'low': int(dast[0]), 'medium': int(dast[1]), 'high': int(dast[2]), 'critical': int(dast[3])},
                'dastapi': {'low': int(dastapi[0]), 'medium': int(dastapi[1]), 'high': int(dastapi[2]), 'critical': int(dastapi[3])},
            }
            t = SgGlobalThresholds.query.filter(text("Name='General'")).first()
            ato, reason = _get_sg_thresholds_status(report, t)
            response = {
                'status': 'processing_complete',
                'report': report,
                'ato': ato,
                'reason': reason
            }
            return jsonify(response), 200
        else:
            return jsonify({'status': 'processing_started'}), 200
    except Exception as e:
        return jsonify({"error": f"{e}"}), 200


def _get_sg_thresholds_status(report, t):
    overall_score = 'PASS'
    justification = []

    for category, values in report.items():
        for severity, count in values.items():
            # Construct the threshold attribute name
            threshold_attr = f'Thresh{category.capitalize()}{severity.capitalize()}'
            # Get the corresponding threshold value; if None, skip evaluation
            threshold_value = getattr(t, threshold_attr, None)
            if threshold_value is not None and count > threshold_value:
                overall_score = 'FAIL'
                justification.append(f'{category} {severity} count {count} exceeds threshold of {threshold_value}')

    return overall_score, justification



@api.route('/api/closeout_security_scan/<report_id>', methods=['POST'])
def closeout_security_scan(report_id):
    scan = ParallelSecurityPipelineRuns.query.filter(text(f"ID={report_id}")).first()
    scan.ScanEndDate = datetime.datetime.utcnow()

    report_data_str = request.data.decode('utf-8').replace('\\n', '')
    rp = json.loads(report_data_str)

    scan.Status = 'Completed'
    secret = rp['report']['secret']
    scan.SecretFindings = f"{secret['low']}:{secret['medium']}:{secret['high']}:{secret['critical']}"
    sca = rp['report']['sca']
    scan.ScaFindings = f"{sca['low']}:{sca['medium']}:{sca['high']}:{sca['critical']}"
    sast = rp['report']['sast']
    scan.SastFindings = f"{sast['low']}:{sast['medium']}:{sast['high']}:{sast['critical']}"
    iac = rp['report']['iac']
    scan.IacFindings = f"{iac['low']}:{iac['medium']}:{iac['high']}:{iac['critical']}"
    container = rp['report']['container']
    scan.ContainerFindings = f"{container['low']}:{container['medium']}:{container['high']}:{container['critical']}"
    dast = rp['report']['dast']
    scan.DastFindings = f"{dast['low']}:{dast['medium']}:{dast['high']}:{dast['critical']}"
    dastapi = rp['report']['dastapi']
    scan.DastApiFindings = f"{dastapi['low']}:{dastapi['medium']}:{dastapi['high']}:{dastapi['critical']}"

    db.session.add(scan)
    db.session.commit()

    return jsonify({}), 200

