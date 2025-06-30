from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, _add_page_permissions_filter
from sqlalchemy import text
from flask import render_template, session, redirect, url_for
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.orchestration.model.pipelinejobs import PipelineJobs
from vr.vulns.model.sgconfigsettingsperjob import SgConfigSettingsPerJob
from vr.vulns.model.sgresultsperjob import SgResultsPerJob


NAV = {
    'CAT': { "name": "Applications", "url": "sourcecode.dashboard"}
}

@vulns.route("/securitygatescorecard/<id>", methods=['GET'])
@login_required
def securitygatescorecard(id):
    try:
        NAV['curpage'] = {"name": "Security Gate Scorecard"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Security Gate Scorecard']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        try:
            id = int(id)  # Ensure `id` is a valid integer
        except ValueError:
            return render_template('400.html'), 400  # Return a 400 Bad Request if `id` is invalid
        assets_all = PipelineJobs.query \
            .with_entities(PipelineJobs.ID, PipelineJobs.StartDate,
                           PipelineJobs.BuildNum, BusinessApplications.ApplicationName, BusinessApplications.ID,
                           PipelineJobs.BranchName, PipelineJobs.BuildNum, PipelineJobs.JobName, PipelineJobs.Project,
                           PipelineJobs.GitBranch,
                           SgResultsPerJob.ResultScaLow,SgResultsPerJob.ResultScaMedium,SgResultsPerJob.ResultScaHigh,
                           SgResultsPerJob.ResultScaCritical,
                           SgResultsPerJob.ResultContainerLow, SgResultsPerJob.ResultContainerMedium, SgResultsPerJob.ResultContainerHigh,
                           SgResultsPerJob.ResultContainerCritical,
                           SgResultsPerJob.ResultDastLow, SgResultsPerJob.ResultDastMedium, SgResultsPerJob.ResultDastHigh,
                           SgResultsPerJob.ResultDastCritical,
                           SgResultsPerJob.ResultDastApiLow, SgResultsPerJob.ResultDastApiMedium, SgResultsPerJob.ResultDastApiHigh,
                           SgResultsPerJob.ResultDastApiCritical,
                           SgResultsPerJob.ResultInfrastructureLow, SgResultsPerJob.ResultInfrastructureMedium, SgResultsPerJob.ResultInfrastructureHigh,
                           SgResultsPerJob.ResultInfrastructureCritical,
                           SgResultsPerJob.ResultSastLow, SgResultsPerJob.ResultSastMedium, SgResultsPerJob.ResultSastHigh,
                           SgResultsPerJob.ResultSastCritical,
                           SgResultsPerJob.ResultIacLow, SgResultsPerJob.ResultIacMedium, SgResultsPerJob.ResultIacHigh,
                           SgResultsPerJob.ResultIacCritical,
                           SgResultsPerJob.ResultSecretsLow, SgResultsPerJob.ResultSecretsMedium, SgResultsPerJob.ResultSecretsHigh,
                           SgResultsPerJob.ResultSecretsCritical,
                           SgConfigSettingsPerJob.ThreshScaLow, SgConfigSettingsPerJob.ThreshScaMedium,
                           SgConfigSettingsPerJob.ThreshScaHigh,
                           SgConfigSettingsPerJob.ThreshScaCritical,
                           SgConfigSettingsPerJob.ThreshContainerLow, SgConfigSettingsPerJob.ThreshContainerMedium,
                           SgConfigSettingsPerJob.ThreshContainerHigh,
                           SgConfigSettingsPerJob.ThreshContainerCritical,
                           SgConfigSettingsPerJob.ThreshDastLow, SgConfigSettingsPerJob.ThreshDastMedium,
                           SgConfigSettingsPerJob.ThreshDastHigh,
                           SgConfigSettingsPerJob.ThreshDastCritical,
                           SgConfigSettingsPerJob.ThreshDastApiLow, SgConfigSettingsPerJob.ThreshDastApiMedium,
                           SgConfigSettingsPerJob.ThreshDastApiHigh,
                           SgConfigSettingsPerJob.ThreshDastApiCritical,
                           SgConfigSettingsPerJob.ThreshInfrastructureLow,
                           SgConfigSettingsPerJob.ThreshInfrastructureMedium,
                           SgConfigSettingsPerJob.ThreshInfrastructureHigh,
                           SgConfigSettingsPerJob.ThreshInfrastructureCritical,
                           SgConfigSettingsPerJob.ThreshSastLow, SgConfigSettingsPerJob.ThreshSastMedium,
                           SgConfigSettingsPerJob.ThreshSastHigh,
                           SgConfigSettingsPerJob.ThreshSastCritical,
                           SgConfigSettingsPerJob.ThreshIacLow, SgConfigSettingsPerJob.ThreshIacMedium,
                           SgConfigSettingsPerJob.ThreshIacHigh,
                           SgConfigSettingsPerJob.ThreshIacCritical,
                           SgConfigSettingsPerJob.ThreshSecretsLow, SgConfigSettingsPerJob.ThreshSecretsMedium,
                           SgConfigSettingsPerJob.ThreshSecretsHigh,
                           SgConfigSettingsPerJob.ThreshSecretsCritical
                           ) \
            .join(BusinessApplications, BusinessApplications.ID == PipelineJobs.ApplicationId, isouter=True) \
            .join(SgConfigSettingsPerJob, PipelineJobs.ID == SgConfigSettingsPerJob.PipelineJobID, isouter=True) \
            .join(SgResultsPerJob, PipelineJobs.ID == SgResultsPerJob.PipelineJobID, isouter=True) \
            .filter(PipelineJobs.ID == id).all()
        schema = BusinessApplicationsSchema(many=True)
        assets = schema.dump(assets_all)
        NAV['appbar'] = 'scorecard'
        if assets:
            app_data = {'ID': assets[0]['ID'], 'ApplicationName': assets[0]['ApplicationName']}
        else:
            app_data = {}
        if assets_all:
            scorecard_results = {
                "secrets": "Pass",
                "sca": "Pass",
                "iac": "Pass",
                "sast": "Pass",
                "container": "Pass",
                "infrastructure": "Pass",
                "dast": "Pass",
                "dastapi": "Pass",
                "OVERALL": "Pass"
            }
            entities = assets_all
            entity = entities[0]

            if entity.ThreshSecretsLow and safe_int(entity.ResultSecretsLow) > safe_int(entity.ThreshSecretsLow):
                scorecard_results['secrets'] = 'Fail'
            if entity.ThreshSecretsMedium and safe_int(entity.ResultSecretsMedium) > safe_int(entity.ThreshSecretsMedium):
                scorecard_results['secrets'] = 'Fail'
            if entity.ThreshSecretsHigh and safe_int(entity.ResultSecretsHigh) > safe_int(entity.ThreshSecretsHigh):
                scorecard_results['secrets'] = 'Fail'
            if entity.ThreshSecretsCritical and safe_int(entity.ResultSecretsCritical) > safe_int(entity.ThreshSecretsCritical):
                scorecard_results['secrets'] = 'Fail'

            if entity.ThreshScaLow and safe_int(entity.ResultScaLow) > safe_int(entity.ThreshScaLow):
                scorecard_results['sca'] = 'Fail'
            if entity.ThreshScaMedium and safe_int(entity.ResultScaMedium) > safe_int(entity.ThreshScaMedium):
                scorecard_results['sca'] = 'Fail'
            if entity.ThreshScaHigh and safe_int(entity.ResultScaHigh) > safe_int(entity.ThreshScaHigh):
                scorecard_results['sca'] = 'Fail'
            if entity.ThreshScaCritical and safe_int(entity.ResultScaCritical) > safe_int(entity.ThreshScaCritical):
                scorecard_results['sca'] = 'Fail'

            if entity.ThreshIacLow and safe_int(entity.ResultIacLow) > safe_int(entity.ThreshIacLow):
                scorecard_results['iac'] = 'Fail'
            if entity.ThreshIacMedium and safe_int(entity.ResultIacMedium) > safe_int(entity.ThreshIacMedium):
                scorecard_results['iac'] = 'Fail'
            if entity.ThreshIacHigh and safe_int(entity.ResultIacHigh) > safe_int(entity.ThreshIacHigh):
                scorecard_results['iac'] = 'Fail'
            if entity.ThreshIacCritical and safe_int(entity.ResultIacCritical) > safe_int(entity.ThreshIacCritical):
                scorecard_results['iac'] = 'Fail'

            if entity.ThreshSastLow and safe_int(entity.ResultSastLow) > safe_int(entity.ThreshSastLow):
                scorecard_results['sast'] = 'Fail'
            if entity.ThreshSastMedium and safe_int(entity.ResultSastMedium) > safe_int(entity.ThreshSastMedium):
                scorecard_results['sast'] = 'Fail'
            if entity.ThreshSastHigh and safe_int(entity.ResultSastHigh) > safe_int(entity.ThreshSastHigh):
                scorecard_results['sast'] = 'Fail'
            if entity.ThreshSastCritical and safe_int(entity.ResultSastCritical) > safe_int(entity.ThreshSastCritical):
                scorecard_results['sast'] = 'Fail'

            if entity.ThreshContainerLow and safe_int(entity.ResultContainerLow) > safe_int(entity.ThreshContainerLow):
                scorecard_results['container'] = 'Fail'
            if entity.ThreshContainerMedium and safe_int(entity.ResultContainerMedium) > safe_int(entity.ThreshContainerMedium):
                scorecard_results['container'] = 'Fail'
            if entity.ThreshContainerHigh and safe_int(entity.ResultContainerHigh) > safe_int(entity.ThreshContainerHigh):
                scorecard_results['container'] = 'Fail'
            if entity.ThreshContainerCritical and safe_int(entity.ResultContainerCritical) > safe_int(entity.ThreshContainerCritical):
                scorecard_results['container'] = 'Fail'

            if entity.ThreshInfrastructureLow and safe_int(entity.ResultInfrastructureLow) > safe_int(entity.ThreshInfrastructureLow):
                scorecard_results['infrastructure'] = 'Fail'
            if entity.ThreshInfrastructureMedium and safe_int(entity.ResultInfrastructureMedium) > safe_int(entity.ThreshInfrastructureMedium):
                scorecard_results['infrastructure'] = 'Fail'
            if entity.ThreshInfrastructureHigh and safe_int(entity.ResultInfrastructureHigh) > safe_int(entity.ThreshInfrastructureHigh):
                scorecard_results['infrastructure'] = 'Fail'
            if entity.ThreshInfrastructureCritical and safe_int(entity.ResultInfrastructureCritical) > safe_int(entity.ThreshInfrastructureCritical):
                scorecard_results['infrastructure'] = 'Fail'

            if entity.ThreshDastLow and safe_int(entity.ResultDastLow) > safe_int(entity.ThreshDastLow):
                scorecard_results['dast'] = 'Fail'
            if entity.ThreshDastMedium and safe_int(entity.ResultDastMedium) > safe_int(entity.ThreshDastMedium):
                scorecard_results['dast'] = 'Fail'
            if entity.ThreshDastHigh and safe_int(entity.ResultDastHigh) > safe_int(entity.ThreshDastHigh):
                scorecard_results['dast'] = 'Fail'
            if entity.ThreshDastCritical and safe_int(entity.ResultDastCritical) > safe_int(entity.ThreshDastCritical):
                scorecard_results['dast'] = 'Fail'

            if entity.ThreshDastApiLow and safe_int(entity.ResultDastApiLow) > safe_int(entity.ThreshDastApiLow):
                scorecard_results['dastapi'] = 'Fail'
            if entity.ThreshDastApiMedium and safe_int(entity.ResultDastApiMedium) > safe_int(entity.ThreshDastApiMedium):
                scorecard_results['dastapi'] = 'Fail'
            if entity.ThreshDastApiHigh and safe_int(entity.ResultDastApiHigh) > safe_int(entity.ThreshDastApiHigh):
                scorecard_results['dastapi'] = 'Fail'
            if entity.ThreshDastApiCritical and safe_int(entity.ResultDastApiCritical) > safe_int(entity.ThreshDastApiCritical):
                scorecard_results['dastapi'] = 'Fail'

            contains_fail = False
            for value in scorecard_results.values():
                if value == 'Fail':
                    contains_fail = True
                    break  # Exit the loop once a 'Fail' value is found
            if contains_fail:
                scorecard_results['OVERALL'] = 'Fail'
        else:
            entity = []
            scorecard_results = {}
            scorecard_results['OVERALL'] = 'No Tests'
        NAV['appbar'] = 'ci_cd'
        return render_template('vulns/securitygatescorecard.html', app_data=app_data, entities=entity, user=user, NAV=NAV,
                               scorecard_results=scorecard_results)
    except RuntimeError:
        return render_template('500.html'), 500


def safe_int(value, default=0):
    if value is None:
        return default
    if value[0].isdigit():
        return int(value)
    else:
        return value
