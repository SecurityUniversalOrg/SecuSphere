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
        ThreshScaLow = config['sca']['low'] if 'low' in 'sca' else '',
        ThreshScaMedium = config['sca']['medium'] if 'medium' in 'sca' else '',
        ThreshScaHigh = config['sca']['high'] if 'high' in 'sca' else '',
        ThreshScaCritical = config['sca']['critical'] if 'critical' in 'sca' else '',
        ThreshContainerLow = config['container']['low'] if 'low' in 'container' else '',
        ThreshContainerMedium = config['container']['medium'] if 'medium' in 'container' else '',
        ThreshContainerHigh = config['container']['high'] if 'high' in 'container' else '',
        ThreshContainerCritical = config['container']['critical'] if 'critical' in 'container' else '',
        ThreshDastLow = config['dast']['low'] if 'low' in 'dast' else '',
        ThreshDastMedium = config['dast']['medium'] if 'medium' in 'dast' else '',
        ThreshDastHigh = config['dast']['high'] if 'high' in 'dast' else '',
        ThreshDastCritical = config['dast']['critical'] if 'critical' in 'dast' else '',
        ThreshDastApiLow = config['dastapi']['low'] if 'low' in 'dastapi' else '',
        ThreshDastApiMedium = config['dastapi']['medium'] if 'medium' in 'dastapi' else '',
        ThreshDastApiHigh = config['dastapi']['high'] if 'high' in 'dastapi' else '',
        ThreshDastApiCritical = config['dastapi']['critical'] if 'critical' in 'dastapi' else '',
        ThreshInfrastructureLow = config['infrastructure']['low'] if 'low' in 'infrastructure' else '',
        ThreshInfrastructureMedium = config['infrastructure']['medium'] if 'medium' in 'infrastructure' else '',
        ThreshInfrastructureHigh = config['infrastructure']['high'] if 'high' in 'infrastructure' else '',
        ThreshInfrastructureCritical = config['infrastructure']['critical'] if 'critical' in 'infrastructure' else '',
        ThreshSastLow = config['sast']['low'] if 'low' in 'sast' else '',
        ThreshSastMedium = config['sast']['medium'] if 'medium' in 'sast' else '',
        ThreshSastHigh = config['sast']['high'] if 'high' in 'sast' else '',
        ThreshSastCritical = config['sast']['critical'] if 'critical' in 'sast' else '',
        ThreshIacLow = config['iac']['low'] if 'low' in 'iac' else '',
        ThreshIacMedium = config['iac']['medium'] if 'medium' in 'iac' else '',
        ThreshIacHigh = config['iac']['high'] if 'high' in 'iac' else '',
        ThreshIacCritical = config['iac']['critical'] if 'critical' in 'iac' else '',
        ThreshSecretsLow = config['secret']['low'] if 'low' in 'secret' else '',
        ThreshSecretsMedium = config['secret']['medium'] if 'medium' in 'secret' else '',
        ThreshSecretsHigh = config['secret']['high'] if 'high' in 'secret' else '',
        ThreshSecretsCritical = config['secret']['critical'] if 'critical' in 'secret' else '',
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
