import requests
from flask import jsonify, request, json
from vr.api import api
from requests.auth import HTTPBasicAuth
from config_engine import JENKINS_USER, JENKINS_KEY, JENKINS_PROJECT, JENKINS_HOST, JENKINS_TOKEN


@api.route('/jenkins_webhook', methods=['POST'])
def jenkins_webhook():
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

