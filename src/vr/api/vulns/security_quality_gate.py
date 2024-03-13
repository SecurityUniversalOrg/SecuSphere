import datetime
from vr import db, app
from flask import jsonify, request
from vr.api import api
from vr.orchestration.model.pipelinejobs import PipelineJobs
from vr.vulns.model.sgconfigsettingsperjob import SgConfigSettingsPerJob
from vr.vulns.model.sgresultsperjob import SgResultsPerJob
from vr.api.vulns.vulnerabilities import get_app_id
from vr.admin.functions import db_connection_handler
from vr.admin.oauth2 import require_oauth


@api.route('/api/add_sg_results', methods=['POST'])
@require_oauth('write:vulnerabilities')
def add_sg_results():
    form = request.get_json()
    job_data = form['jobData']
    job_id, app_id = _add_pipeline_job_data(job_data)
    config = form['config']
    _add_sg_config_settings(config, job_id, app_id)
    results = form['results']
    _add_sg_results(results, job_id, app_id)
    return jsonify({"result": "Report Delivered"}), 200


def _add_pipeline_job_data(job_data):
    timestamp = job_data['buildStartTime']
    timestamp_seconds = timestamp / 1000
    start_dt_object = datetime.datetime.fromtimestamp(timestamp_seconds)
    app_id = get_app_id(job_data['appName'], job_data['gitUrl'])
    job = PipelineJobs(
        StartDate=start_dt_object,
        Status = "In Progress",
        Source = "Jenkins",
        SourceJobId = job_data['buildNumber'],
        ApplicationId = app_id,
        BranchName = job_data['gitBranch'],
        BuildNum = job_data['buildNumber'],
        JobName = job_data['jobName'],
        Project = job_data['jobName'].split('/')[0],
        GitCommit = job_data['gitCommit'],
        GitBranch = job_data['gitBranch'],
        GitUrl = job_data['gitUrl']
    )
    db.session.add(job)
    db_connection_handler(db)
    return job.ID, app_id


def _add_sg_config_settings(config, job_id, app_id):
    job = SgConfigSettingsPerJob(
        AppID=app_id,
        PipelineJobID = job_id,
        ThreshScaLow = config['sca']['low'],
        ThreshScaMedium = config['sca']['medium'],
        ThreshScaHigh = config['sca']['high'],
        ThreshScaCritical = config['sca']['critical'],
        ThreshContainerLow = config['container']['low'],
        ThreshContainerMedium = config['container']['medium'],
        ThreshContainerHigh = config['container']['high'],
        ThreshContainerCritical = config['container']['critical'],
        ThreshDastLow = config['dast']['low'],
        ThreshDastMedium = config['dast']['medium'],
        ThreshDastHigh = config['dast']['high'],
        ThreshDastCritical = config['dast']['critical'],
        ThreshDastApiLow = config['dastapi']['low'],
        ThreshDastApiMedium = config['dastapi']['medium'],
        ThreshDastApiHigh = config['dastapi']['high'],
        ThreshDastApiCritical = config['dastapi']['critical'],
        ThreshInfrastructureLow = config['infrastructure']['low'],
        ThreshInfrastructureMedium = config['infrastructure']['medium'],
        ThreshInfrastructureHigh = config['infrastructure']['high'],
        ThreshInfrastructureCritical = config['infrastructure']['critical'],
        ThreshSastLow = config['sast']['low'],
        ThreshSastMedium = config['sast']['medium'],
        ThreshSastHigh = config['sast']['high'],
        ThreshSastCritical = config['sast']['critical'],
        ThreshIacLow = config['iac']['low'],
        ThreshIacMedium = config['iac']['medium'],
        ThreshIacHigh = config['iac']['high'],
        ThreshIacCritical = config['iac']['critical'],
        ThreshSecretsLow = config['secret']['low'],
        ThreshSecretsMedium = config['secret']['medium'],
        ThreshSecretsHigh = config['secret']['high'],
        ThreshSecretsCritical = config['secret']['critical'],
    )
    db.session.add(job)
    db_connection_handler(db)


def _add_sg_results(results, job_id, app_id):
    job = SgResultsPerJob(
        AppID=app_id,
        PipelineJobID=job_id,
        ResultScaLow=results['sca']['low'],
        ResultScaMedium=results['sca']['medium'],
        ResultScaHigh=results['sca']['high'],
        ResultScaCritical=results['sca']['critical'],
        ResultContainerLow=results['container']['low'],
        ResultContainerMedium=results['container']['medium'],
        ResultContainerHigh=results['container']['high'],
        ResultContainerCritical=results['container']['critical'],
        ResultDastLow=results['dast']['low'],
        ResultDastMedium=results['dast']['medium'],
        ResultDastHigh=results['dast']['high'],
        ResultDastCritical=results['dast']['critical'],
        ResultDastApiLow=results['dastapi']['low'],
        ResultDastApiMedium=results['dastapi']['medium'],
        ResultDastApiHigh=results['dastapi']['high'],
        ResultDastApiCritical=results['dastapi']['critical'],
        ResultInfrastructureLow=results['infrastructure']['low'],
        ResultInfrastructureMedium=results['infrastructure']['medium'],
        ResultInfrastructureHigh=results['infrastructure']['high'],
        ResultInfrastructureCritical=results['infrastructure']['critical'],
        ResultSastLow=results['sast']['low'],
        ResultSastMedium=results['sast']['medium'],
        ResultSastHigh=results['sast']['high'],
        ResultSastCritical=results['sast']['critical'],
        ResultIacLow=results['iac']['low'],
        ResultIacMedium=results['iac']['medium'],
        ResultIacHigh=results['iac']['high'],
        ResultIacCritical=results['iac']['critical'],
        ResultSecretsLow=results['secret']['low'],
        ResultSecretsMedium=results['secret']['medium'],
        ResultSecretsHigh=results['secret']['high'],
        ResultSecretsCritical=results['secret']['critical'],
    )
    db.session.add(job)
    db_connection_handler(db)
