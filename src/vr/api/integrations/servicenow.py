from flask import jsonify, request
import requests
import json
from vr.api import api
from vr.admin.oauth2 import require_oauth
from authlib.integrations.flask_oauth2 import current_token
from vr.admin.auth_functions import verify_api_key, get_token_auth_header
from vr.functions.routing_functions import check_entity_permissions
from vr.assets.model.applicationprofiles import ApplicationProfiles, ApplicationProfilesSchema
from config_engine import SNOW_PASSWORD, SNOW_CLIENT_SECRET, SNOW_INSTANCE_NAME, SNOW_CLIENT_ID, SNOW_USERNAME


ERROR_RESP = "Error: Invalid API Request"

@api.route("/api/onboard_new_application", methods=['POST'])
@require_oauth('read:vulnerabilities')
def onboard_new_application():
    token = current_token
    auth, user_id, is_admin = verify_api_key(token)
    response = jsonify({'response': ERROR_RESP}), 403
    if auth == 'valid':
        permitted = check_entity_permissions(is_admin)
        if permitted:
            # Step 1: Decode the bytes to string
            data_str = request.data.decode('utf-8')

            # Step 2: Convert the string to a Python dictionary
            data_dict = json.loads(data_str)

            app_name = data_dict['app_name']

            # Step 3: Create a new ci for Business Application if not exists
            sm = SnowManager()
            bus_app_sys_id = create_new_bus_app(sm, app_name, data_dict['app_description'])

            app_service_sys_id = create_new_app_service_for_web(sm, app_name, data_dict['app_description'])

            # Create Artifact Repositories
            docker_repo_sys_id = create_new_artifact_repos(sm, app_name, data_dict['app_description'])

            # Create CI/CD Pipeline
            cicd_pipeline_sys_id = create_new_cicd_pipeline(sm, app_name, data_dict['app_description'])

            # Create Development Environments
            dev_env_sys_id = create_new_development_environments(sm, app_name, data_dict['app_description'])

            # Create Issue & Project Tracking
            jira_sys_id = create_new_issue_project_tracking(sm, app_name, data_dict['app_description'])

            # Create Source Code Repository
            git_repo_sys_id = create_new_source_code_repo(sm, app_name, data_dict['app_description'])

            # Create Collaboration Tools
            collab_sys_id_map = create_new_collaboration_tools(sm, app_name, data_dict['app_description'])
            teams_sys_id = collab_sys_id_map['chat']
            confluence_sys_id = collab_sys_id_map['project_collaboration']


            response = {}, 200
    return response


def create_new_bus_app(snow_obj, app_name, app_desc):
    table_data = snow_obj.get_ci_table_data('cmdb_ci_business_app', filter_str=f'name={app_name}')
    if not table_data['result']:
        data = {
            "name": app_name,
            "short_description": app_desc,
            "active": True
        }
        return snow_obj.create_ci('cmdb_ci_business_app', data)
    else:
        return table_data['result'][0]['sys_id']

def create_new_app_service_for_web(snow_obj, app_name, app_desc):
    table_data = snow_obj.get_ci_table_data('cmdb_ci_service_auto', filter_str=f'name={app_name} Web Service')
    if not table_data['result']:
        data = {
            "name": f'{app_name} Web Service',
            "short_description": app_desc
        }
        return snow_obj.create_ci('cmdb_ci_service_auto', data)
    else:
        return table_data['result'][0]['sys_id']

def create_new_artifact_repos(snow_obj, app_name, app_desc):
    table_data = snow_obj.get_ci_table_data('u_cmdb_ci_sdlc_artifact_repository', filter_str=f'name={app_name} Docker Images')
    if not table_data['result']:
        data = {
            "name": f'{app_name} Docker Images',
            "short_description": app_desc,
            "u_artifact_type": 'Docker Images'
        }
        return snow_obj.create_ci('u_cmdb_ci_sdlc_artifact_repository', data)
    else:
        return table_data['result'][0]['sys_id']

def create_new_cicd_pipeline(snow_obj, app_name, app_desc):
    table_data = snow_obj.get_ci_table_data('u_cmdb_ci_cicd_pipeline', filter_str=f'name={app_name} CI/CD Pipeline')
    if not table_data['result']:
        data = {
            "name": f'{app_name} CI/CD Pipeline',
            "short_description": app_desc,
            "u_deployment_frequency": "Monthly",
            "u_pipeline_type": "Jenkins"
        }
        return snow_obj.create_ci('u_cmdb_ci_cicd_pipeline', data)
    else:
        return table_data['result'][0]['sys_id']

def create_new_development_environments(snow_obj, app_name, app_desc):
    table_data = snow_obj.get_ci_table_data('u_cmdb_ci_development_environment', filter_str=f'name={app_name} Development Environment')
    if not table_data['result']:
        data = {
            "name": f'{app_name} Development Environment',
            "short_description": app_desc,
            "u_access_level": "developers",
            "u_environment_type": "Development",
            "u_hosted_platform": "on-prem"
        }
        return snow_obj.create_ci('u_cmdb_ci_development_environment', data)
    else:
        return table_data['result'][0]['sys_id']

def create_new_issue_project_tracking(snow_obj, app_name, app_desc):
    table_data = snow_obj.get_ci_table_data('u_cmdb_ci_sdlc_issue_and_project_tracking', filter_str=f'name={app_name} Jira Project')
    if not table_data['result']:
        data = {
            "name": f'{app_name} Jira Project',
            "short_description": app_desc,
            "tool_type": "Jira"
        }
        return snow_obj.create_ci('u_cmdb_ci_sdlc_issue_and_project_tracking', data)
    else:
        return table_data['result'][0]['sys_id']

def create_new_source_code_repo(snow_obj, app_name, app_desc):
    table_data = snow_obj.get_ci_table_data('u_cmdb_ci_source_code_repository', filter_str=f'name={app_name} Code Repo')
    if not table_data['result']:
        data = {
            "name": f'{app_name} Code Repo',
            "short_description": app_desc,
            "u_default_branch": "main",
            "u_repository_type": "git",
            "u_repository_vendor": "GitHub",
            "u_visibility": "Private",
            "u_component_type": "Web",
        }
        return snow_obj.create_ci('u_cmdb_ci_source_code_repository', data)
    else:
        return table_data['result'][0]['sys_id']

def create_new_collaboration_tools(snow_obj, app_name, app_desc):
    sys_id_map = {
        "chat": None,
        "project_collaboration": None
    }
    table_data = snow_obj.get_ci_table_data('u_cmdb_ci_sdlc_collaboration_tools', filter_str=f'name={app_name} Teams Channel')
    if not table_data['result']:
        data = {
            "name": f'{app_name} Teams Channel',
            "short_description": app_desc,
            "u_tool_name": "Microsoft Teams",
            "u_platform": "Chat",
            "u_status": "Active"
        }
        sys_id_map["chat"] = snow_obj.create_ci('u_cmdb_ci_sdlc_collaboration_tools', data)
    else:
        sys_id_map["chat"] = table_data['result'][0]['sys_id']

    table_data = snow_obj.get_ci_table_data('u_cmdb_ci_sdlc_collaboration_tools', filter_str=f'name={app_name} Confluence Space')
    if not table_data['result']:
        data = {
            "name": f'{app_name} Confluence Space',
            "short_description": app_desc,
            "u_tool_name": "Confluence",
            "u_platform": "Project Collaboration",
            "u_status": "Active"
        }
        sys_id_map["project_collaboration"] = snow_obj.create_ci('u_cmdb_ci_sdlc_collaboration_tools', data)
    else:
        sys_id_map["project_collaboration"] = table_data['result'][0]['sys_id']

    return sys_id_map

# ServiceNow instance details
INSTANCE_NAME = SNOW_INSTANCE_NAME
CLIENT_ID  = SNOW_CLIENT_ID
CLIENT_SECRET  = SNOW_CLIENT_SECRET
USERNAME = SNOW_USERNAME
PASSWORD = SNOW_PASSWORD

TOKEN_URL = f'https://{INSTANCE_NAME}.service-now.com/oauth_token.do'
TOKEN_DATA = {
    'grant_type': 'password',
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'username': USERNAME,
    'password': PASSWORD
}


class SnowManager(object):
    def __init__(self):
        self.access_token = self.get_token()
        self.headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        self.url_base = f'https://{INSTANCE_NAME}.service-now.com/api/now'

    def get_token(self):
        response = requests.post(TOKEN_URL, data=TOKEN_DATA)
        token_info = response.json()

        if 'access_token' in token_info:
            return token_info['access_token']
        else:
            print("Failed to get access token:", response.text)
            exit()

    def get_ci_table_data(self, table, filter_str=None):
        if filter_str:
            url = f'{self.url_base}/table/{table}?{filter_str}'
        else:
            url = f'{self.url_base}/table/{table}'

        # Make the GET request
        response = requests.get(
            url,
            headers=self.headers
        )

        # Check if the request was successful
        if response.status_code == 200:
            return response.json()
        else:
            response.raise_for_status()

    def create_ci(self, table, data):
        BASE_URL = f"{self.url_base}/table"
        response = requests.post(f"{BASE_URL}/{table}", headers=self.headers, data=json.dumps(data))
        return response.json().get("result", {}).get("sys_id")

