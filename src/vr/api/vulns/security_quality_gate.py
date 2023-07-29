import datetime
from vr import db, app
from flask import jsonify, request
from vr.api import api
from vr.vulns.model.pipelinejobs import PipelineJobs
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
        ThreshScaLow = config['thresholds']['sca']['low'],
        ThreshScaMedium = config['thresholds']['sca']['medium'],
        ThreshScaHigh = config['thresholds']['sca']['high'],
        ThreshScaCritical = config['thresholds']['sca']['critical'],
        ThreshContainerLow = config['thresholds']['container']['low'],
        ThreshContainerMedium = config['thresholds']['container']['medium'],
        ThreshContainerHigh = config['thresholds']['container']['high'],
        ThreshContainerCritical = config['thresholds']['container']['critical'],
        ThreshDastLow = config['thresholds']['dast']['low'],
        ThreshDastMedium = config['thresholds']['dast']['medium'],
        ThreshDastHigh = config['thresholds']['dast']['high'],
        ThreshDastCritical = config['thresholds']['dast']['critical'],
        ThreshDastApiLow = config['thresholds']['dastapi']['low'],
        ThreshDastApiMedium = config['thresholds']['dastapi']['medium'],
        ThreshDastApiHigh = config['thresholds']['dastapi']['high'],
        ThreshDastApiCritical = config['thresholds']['dastapi']['critical'],
        ThreshInfrastructureLow = config['thresholds']['infrastructure']['low'],
        ThreshInfrastructureMedium = config['thresholds']['infrastructure']['medium'],
        ThreshInfrastructureHigh = config['thresholds']['infrastructure']['high'],
        ThreshInfrastructureCritical = config['thresholds']['infrastructure']['critical'],
        ThreshSastLow = config['thresholds']['sast']['low'],
        ThreshSastMedium = config['thresholds']['sast']['medium'],
        ThreshSastHigh = config['thresholds']['sast']['high'],
        ThreshSastCritical = config['thresholds']['sast']['critical'],
        ThreshIacLow = config['thresholds']['iac']['low'],
        ThreshIacMedium = config['thresholds']['iac']['medium'],
        ThreshIacHigh = config['thresholds']['iac']['high'],
        ThreshIacCritical = config['thresholds']['iac']['critical'],
        ThreshSecretsLow = config['thresholds']['secret']['low'],
        ThreshSecretsMedium = config['thresholds']['secret']['medium'],
        ThreshSecretsHigh = config['thresholds']['secret']['high'],
        ThreshSecretsCritical = config['thresholds']['secret']['critical'],
    )
    db.session.add(job)
    db_connection_handler(db)


def _add_sg_results(results, job_id, app_id):
    job = SgResultsPerJob(
        AppID=app_id,
        PipelineJobID=job_id,
        ResultScaLow=results['report']['sca']['low'],
        ResultScaMedium=results['report']['sca']['medium'],
        ResultScaHigh=results['report']['sca']['high'],
        ResultScaCritical=results['report']['sca']['critical'],
        ResultContainerLow=results['report']['container']['low'],
        ResultContainerMedium=results['report']['container']['medium'],
        ResultContainerHigh=results['report']['container']['high'],
        ResultContainerCritical=results['report']['container']['critical'],
        ResultDastLow=results['report']['dast']['low'],
        ResultDastMedium=results['report']['dast']['medium'],
        ResultDastHigh=results['report']['dast']['high'],
        ResultDastCritical=results['report']['dast']['critical'],
        ResultDastApiLow=results['report']['dastapi']['low'],
        ResultDastApiMedium=results['report']['dastapi']['medium'],
        ResultDastApiHigh=results['report']['dastapi']['high'],
        ResultDastApiCritical=results['report']['dastapi']['critical'],
        ResultInfrastructureLow=results['report']['infrastructure']['low'],
        ResultInfrastructureMedium=results['report']['infrastructure']['medium'],
        ResultInfrastructureHigh=results['report']['infrastructure']['high'],
        ResultInfrastructureCritical=results['report']['infrastructure']['critical'],
        ResultSastLow=results['report']['sast']['low'],
        ResultSastMedium=results['report']['sast']['medium'],
        ResultSastHigh=results['report']['sast']['high'],
        ResultSastCritical=results['report']['sast']['critical'],
        ResultIacLow=results['report']['iac']['low'],
        ResultIacMedium=results['report']['iac']['medium'],
        ResultIacHigh=results['report']['iac']['high'],
        ResultIacCritical=results['report']['iac']['critical'],
        ResultSecretsLow=results['report']['secret']['low'],
        ResultSecretsMedium=results['report']['secret']['medium'],
        ResultSecretsHigh=results['report']['secret']['high'],
        ResultSecretsCritical=results['report']['secret']['critical'],
    )
    db.session.add(job)
    db_connection_handler(db)
