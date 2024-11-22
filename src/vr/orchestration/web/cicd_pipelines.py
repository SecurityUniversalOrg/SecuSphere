import io
import yaml
import zipfile
from vr.orchestration import orchestration
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import render_template, session, redirect, url_for, request, send_file, jsonify, Response
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications
from vr.orchestration.model.cicdpipelines import CICDPipelines, CICDPipelinesSchema
from vr.assets.model.integrations import Integrations, IntegrationsSchema
from vr.sourcecode.model.appcodecomposition import AppCodeComposition
from sqlalchemy import text, desc


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}

@orchestration.route("/all_pipelines")
@login_required
def all_pipelines():
    try:
        NAV['curpage'] = {"name": "All CI/CD Pipelines"}
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

        assets_all = CICDPipelines.query\
            .with_entities(CICDPipelines.ID, CICDPipelines.Name, CICDPipelines.Description, CICDPipelines.Url,
                           BusinessApplications.ApplicationName, Integrations.Name.label('IntegrationName'))\
            .join(BusinessApplications, BusinessApplications.ID == CICDPipelines.ApplicationID, isouter=True) \
            .join(Integrations, Integrations.ID == CICDPipelines.IntegrationID, isouter=True) \
            .filter(text(sql_filter)) \
            .all()
        return render_template('orchestration/all_pipelines.html', entities=assets_all, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500


@orchestration.route("/pipeline_generator/<appid>")
@login_required
def pipeline_generator(appid):
    try:
        NAV['curpage'] = {"name": "Pipeline Generator"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        NAV['appbar'] = 'ci_cd'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
        return render_template('orchestration/pipeline_generator.html', user=user, NAV=NAV, app_data=app_data)
    except RuntimeError:
        return render_template('500.html'), 500

def _parse_languages(ld, tot_files, active_languages, tot_loc):
    if ld.CFiles:
        tot_files += ld.CFiles
    if ld.GoFiles:
        tot_files += ld.GoFiles
    if ld.JavaFiles:
        tot_files += ld.JavaFiles
    if ld.JavascriptFiles:
        tot_files += ld.JavascriptFiles
    if ld.PerlFiles:
        tot_files += ld.PerlFiles
    if ld.PythonFiles:
        tot_files += ld.PythonFiles
    if ld.CLoc:
        tot_loc += ld.CLoc
        active_languages.append({"C": ld.CLoc})
    if ld.GoLoc:
        tot_loc += ld.GoLoc
        active_languages.append({"Go": ld.GoLoc})
    if ld.JavaLoc:
        tot_loc += ld.JavaLoc
        active_languages.append({"Java": ld.JavaLoc})
    if ld.JavascriptLoc:
        tot_loc += ld.JavascriptLoc
        active_languages.append({"Javascript": ld.JavascriptLoc})
    if ld.PerlLoc:
        tot_loc += ld.PerlLoc
        active_languages.append({"Perl": ld.PerlLoc})
    if ld.PythonLoc:
        tot_loc += ld.PythonLoc
        active_languages.append({"Python": ld.PythonLoc})
    return tot_loc, active_languages, tot_files

def calculate_loc_stats(ld):
    tot_files = 0
    tot_loc = 0
    active_languages = []
    if ld:
        tot_loc, active_languages, tot_files = _parse_languages(ld, tot_files, active_languages, tot_loc)
    sorted_active_languages = sorted(active_languages, key=lambda d: d[list(d.keys())[0]], reverse=True)
    all_languages = [list(i.keys())[0] for i in sorted_active_languages]
    return {"total_files": tot_files, "total_loc": tot_loc, "active_languages": sorted_active_languages, "all_languages": all_languages}


@orchestration.route('/analyze', methods=['POST'])
def analyze_stages():
    try:
        NAV['curpage'] = {"name": "Pipeline Generator"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        app_id = request.json['appId']
        app = BusinessApplications.query.filter(text(f'ID={app_id}')).first()
        loc_data = AppCodeComposition.query \
            .filter(text(f"AppCodeComposition.ApplicationID={app_id}")) \
            .order_by(desc(AppCodeComposition.AddDate)).first()
        ld = calculate_loc_stats(loc_data)
        stages = request.json['stages']
        fields = determine_fields(stages, ld['all_languages'], app.ApplicationName, app.ApplicationAcronym)
        return jsonify({'fields': fields})
    except RuntimeError:
        return render_template('500.html'), 500


def determine_fields(stages, prog_languages, app_name, component_name):
    fields = [
        {
            'name': 'details_DefaultBranches',
            'label': 'Default Branches',
            'placeholder': 'Enter your Default Branches',
            'type': 'multi-text',  # New type indicating multiple text inputs
            'defaults': ['release', 'security']
        }
    ]
    if 'Software Composition Analysis' in stages or 'Static Application Security Testing' in stages:
        fields.append(
            {
                'name': 'details_LanguagesList',
                'label': 'Programming Languages',
                'type': 'checkbox-group',  # Change to checkbox-group for multi-select
                'options': ['JavaScript', 'Python', 'Java', 'TypeScript', 'C#', 'PHP', 'C++', 'C', 'Shell', 'Ruby', 'Go', 'Swift', 'Kotlin', 'Rust', 'Objective-C', 'Dart', 'Scala', 'Perl', 'Haskell', 'Lua', 'Other'],  # Options for checkboxes
                'default': prog_languages  # Adding default value for checkboxes
            }
        )
        fields.append(
            {
                'name': 'details_SBOM',
                'label': 'Produce SBOM?',
                'type': 'select',  # Simple select input
                'options': ['Yes', 'No']  # Options for the select
            }
        )
    if 'Build Docker Service' in stages:
        fields.append(
            {
                'name': 'details_DockerServiceName',
                'label': 'Docker Service Name',
                'placeholder': 'Enter your Docker Service Name',
                'type': 'text',  # Text input
                'default': component_name
            }
        )
    if 'Test Release - Web' in stages:
        fields.append(
            {
                'name': 'details_WebUrl',
                'label': 'Web URL',
                'placeholder': 'Enter your Web URL',
                'type': 'text'  # Text input
            }
        )
    if 'Test Release - API' in stages:
        fields.append(
            {
                'name': 'details_ApiUrl',
                'label': 'API URL',
                'placeholder': 'Enter your API URL',
                'type': 'text'  # Text input
            }
        )
    if 'Test Release' in stages:
        fields.append(
            {
                'name': 'details_WebUrl',
                'label': 'Web URL',
                'placeholder': 'Enter your Web URL',
                'type': 'text'  # Text input
            }
        )
        fields.append(
            {
                'name': 'details_ApiUrl',
                'label': 'API URL',
                'placeholder': 'Enter your API URL',
                'type': 'text'  # Text input
            }
        )
    if 'Deploy' in stages:
        fields.append(
            {
                'name': 'details_SecretsCreds',
                'label': 'Helm Secrets Deployment Credentials (Optional)',
                'type': 'key-value',
                'placeholder': {'key': 'Helm Variable', 'value': 'Jenkins Credential ID'}
            }
        )
        fields.append(
            {
                'name': 'details_SecretsStrings',
                'label': 'Helm Secrets Deployment Strings (Optional)',
                'placeholder': {'key': 'Helm Variable', 'value': 'String Value'},
                'type': 'key-value'
            }
        )
        fields.append(
            {
                'name': 'details_ServiceCreds',
                'label': 'Helm Service Deployment Credentials (Optional)',
                'placeholder': {'key': 'Helm Variable', 'value': 'Jenkins Credential ID'},
                'type': 'key-value'
            }
        )
        fields.append(
            {
                'name': 'details_ServiceStrings',
                'label': 'Helm Service Deployment Strings (Optional)',
                'placeholder': {'key': 'Helm Variable', 'value': 'String Value'},
                'type': 'key-value'
            }
        )
    if 'Post' in stages:
        fields.append(
            {
                'name': 'details_PostEmails',
                'label': 'Report Email Distribution List',
                'placeholder': 'Enter your Recipient Email List',
                'type': 'multi-text',  # New type indicating multiple text inputs
            }
        )
        fields.append(
            {
                'name': 'details_PostTeamsChannels',
                'label': 'Report Teams Channels List',
                'placeholder': 'Enter your Recipient Teams Channels List',
                'type': 'multi-text',  # New type indicating multiple text inputs
            }
        )
    return fields



@orchestration.route('/submit', methods=['POST'])
def submit_pipeline():
    try:
        NAV['curpage'] = {"name": "Pipeline Generator"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        data = request.json
        app_id = data['appId']
        app = BusinessApplications.query.filter(text(f'ID={app_id}')).first()
        yaml_content = generate_yaml(data, app)
        jenkins_content = generate_jenkinsfile(data, app)

        # Creating a zip file in memory
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('pipeline.yaml', yaml_content)
            zf.writestr('Jenkinsfile', jenkins_content)

        memory_file.seek(0)

        response = Response(memory_file.getvalue(), mimetype='application/zip')
        response.headers['Content-Disposition'] = 'attachment; filename=pipeline_package.zip'
        return response

    except Exception as e:
        print(e)
        return render_template('500.html'), 500


def generate_jenkinsfile(data, app):
    # Placeholder function to generate Jenkinsfile content
    library_str = generate_library_str()
    agent_str = generate_agent_str()
    environment_str = generate_env_str(data['stages'])
    stages_str = generate_stages_str(data['stages'])
    post_str = "post {\n        always {\n            node('jenkins-pipeline-agent') {\n                script {\n                    jslPipelineReporter()\n                }\n            }\n        }\n    }"
    jenkins_file_str = f"{library_str}\n\n\npipeline {{\n    {agent_str}\n    {environment_str}\n    {stages_str}\n    {post_str}\n}}"
    return jenkins_file_str



def generate_stages_str(stages):
    sp_four = "    "
    sp_eight = "        "
    sp_twelve = "            "
    sp_sixteen = "                "
    sp_twenty = "                    "

    stages_dict = {
        'Initialize Config': f"{sp_eight}stage('Initialize Config') {{\n{sp_twelve}agent {{\n{sp_sixteen}kubernetes {{\n{sp_twenty}cloud 'kubernetes-cloud'\n{sp_twenty}label 'jenkins-pipeline-agent'\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_twelve}steps {{\n{sp_sixteen}script {{\n{sp_twenty}def config = jslReadYamlConfig()\n{sp_twenty}env.appName = config.global.appName\n{sp_twenty}env.GLOBAL_BRANCH_LIST = config.global.defaultBranches.join(',')\n{sp_twenty}env.CURRENT_STAGE_BRANCH_LIST = \"\"\n{sp_twenty}jslStageWrapper.initReport(config)\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Prep Job': f"{sp_eight}stage('Prep Job') {{            agent {{                kubernetes {{                    cloud 'kubernetes-cloud'                    label 'jenkins-pipeline-agent'                }}            }}            when {{                expression {{                    def config = jslReadYamlConfig('prepJob')                    env.CURRENT_STAGE_BRANCH_LIST = env.GLOBAL_BRANCH_LIST                    if (config.branches) {{                        env.CURRENT_STAGE_BRANCH_LIST = config.branches.join(',')                    }}                    def branchType = env.BRANCH_NAME.tokenize('/')[0]                    env.CURRENT_STAGE_BRANCH_LIST.tokenize(',').contains(branchType) && config.enabled                }}            }}            steps {{                jslStageWrapper('Prep Job') {{                    script {{                        jslCountLinesOfCode()                    }}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Unit Testing': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Secret Scanning': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Software Composition Analysis': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Static Application Security Testing': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Infrastructure-as-Code Security Testing': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Build Docker Service': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Docker Container Scanning': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Release to Test': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Test Release': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Quality Gate - Security': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Deploy': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
        'Post': f"{sp_eight}\n{sp_sixteen}}}\n{sp_twelve}}}\n{sp_eight}}}\n",
    }
    stages_str = "stages {\n"
    for stage in stages:
        stages_str += stages_dict[stage]
    stages_str += "    }"
    return stages_str

def generate_agent_str():
    agent_str = "agent none"

    return agent_str
def generate_library_str():
    library_str = "@Library('security-pipeline-library')_"

    return library_str

def generate_env_str(stages):
    # env_str = "environment {\n        SNYK_API_KEY = credentials('snyk-api-key')\n    }"
    env_str = "environment {\n"
    init = False
    for i in stages:
        if i == 'Software Composition Analysis':
            if not init:
                init = True
            env_str += f"        SNYK_API_KEY = credentials('snyk-api-key')\n"
    if init:
        env_str += "    }"
    else:
        env_str = ""
    return env_str


def generate_yaml(data, app_obj):
    """
    Generate YAML content from the provided data.

    :param data: A dictionary containing the pipeline stages and additional inputs.
    :return: A string representation of the YAML content.
    """
    # Example of converting the data to a YAML format
    # You can customize the structure as needed for your application
    yaml_dict = {
        'pipeline': {
            'stages': data['stages'],
            'inputs': {input_item['name']: input_item['value'] for input_item in data['inputs']}
        }
    }
    stage_map = {
        'Prep Job': 'prepJob',
        'Unit Testing': 'unitTesting',
        'Secret Scanning': 'secretScanning',
        'Software Composition Analysis': 'sca',
        'Static Application Security Testing': 'sast',
        'Infrastructure-as-Code Security Testing': 'iac',
        'Build Docker Service': 'buildDocker',
        'Docker Container Scanning': 'containerScan',
        'Release to Test': 'releaseToTest',
        'Test Release': 'testRelease',
        'Quality Gate - Security': 'securityQualityGate',
        'Deploy': 'deploy',
        'Post': 'post'
    }
    stages = {}
    inputs = {}
    for i in data['inputs']:
        inputs[i['name'].split('details_')[1]] = i['value']
    for i in data['stages']:
        if i in stage_map:
            stages[stage_map[i]] = {'enabled': 'true', 'branches': []}
            if i == 'Software Composition Analysis' or i == 'Static Application Security Testing':
                stages[stage_map[i]]['codeLanguages'] = inputs['LanguagesList'].replace(' ', '').split(',')
            if i == 'Docker Container Scanning':
                stages[stage_map[i]]['containerName'] = inputs['DockerServiceName']
                stages[stage_map[i]]['containerTag'] = 'latest'
            if i == 'Release to Test':
                stages[stage_map[i]]['serviceName'] = inputs['DockerServiceName']
                stages[stage_map[i]]['containerTag'] = 'latest'
            if i == 'Test Release':
                stages[stage_map[i]]['targetUrl'] = inputs['WebUrl']
                stages[stage_map[i]]['dastTestType'] = 'full'
                stages[stage_map[i]]['apiTargetUrl'] = inputs['ApiUrl']
            if i == 'Deploy':
                secrets_creds_list = inputs['SecretsCreds'].replace(' ', '').split(',') if inputs['SecretsCreds'] else []
                secrets_creds = {}
                secrets_str = {}
                for j in secrets_creds_list:
                    if j and j != '::':
                        new_key = j.split('::')[0]
                        new_val = j.split('::')[1]
                        secrets_creds[new_key.replace('.', '_')] = new_val
                        secrets_str[new_key] = new_key.replace('.', '_')

                secrets_str_list = inputs['SecretsStrings'].replace(' ', '').split(',') if inputs['SecretsStrings'] else []
                for j in secrets_str_list:
                    if j and j != '::':
                        new_key = j.split('::')[0]
                        new_val = j.split('::')[1]
                        secrets_str[new_key] = new_val

                service_creds_list = inputs['ServiceCreds'].replace(' ', '').split(',') if inputs['ServiceCreds'] else []
                service_creds = {}
                service_str = {}
                for j in service_creds_list:
                    if j and j != '::':
                        new_key = j.split('::')[0]
                        new_val = j.split('::')[1]
                        service_creds[new_key.replace('.', '_')] = new_val
                        service_str[new_key] = new_key.replace('.', '_')

                service_str_list = inputs['ServiceStrings'].replace(' ', '').split(',') if inputs['ServiceStrings'] else []
                for j in service_str_list:
                    if j and j != '::':
                        new_key = j.split('::')[0]
                        new_val = j.split('::')[1]
                        service_str[new_key] = new_val

                stages[stage_map[i]]['tlsCredId'] = 'su-tls-wildcard'
                stages[stage_map[i]]['secretsCredentials'] = secrets_creds
                stages[stage_map[i]]['secretsSetStrings'] = secrets_str
                stages[stage_map[i]]['serviceCredentials'] = service_creds
                stages[stage_map[i]]['serviceSetStrings'] = service_str
            if i == 'Post':
                stages[stage_map[i]]['recipientEmails'] = inputs['PostEmails']
                stages[stage_map[i]]['recipientTeamsChannels'] = inputs['PostTeamsChannels']
    default_branches = []
    for i in data['inputs']:
        if i['name'] == 'details_DefaultBranches':
            default_branches = i['value'].replace(' ', '').split(',')
    yaml_dict = {
        'global': {
            'appName': f"{app_obj.ApplicationName}--{app_obj.ApplicationAcronym}",
            'defaultBranches': default_branches
        },
        'stages': stages
    }

    # Convert the dictionary to a YAML string
    yaml_content = yaml.dump(yaml_dict, default_flow_style=False, indent=2, allow_unicode=True, sort_keys=False)

    return yaml_content
