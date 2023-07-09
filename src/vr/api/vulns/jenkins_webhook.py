import requests
from flask import jsonify, request, json
from vr.api import api
from requests.auth import HTTPBasicAuth
from config_engine import JENKINS_USER, JENKINS_KEY, JENKINS_PROJECT, JENKINS_HOST


@api.route('/jenkins_webhook', methods=['POST'])
def jenkins_webhook():
    all = request.form
    payload_dict = json.loads(all['payload'])
    ref = payload_dict['ref']
    if ref.startswith('refs/heads/security/'):
        tests_to_run = ref.split('--')[1]
        git_url = f"{payload_dict['repository']['html_url']}.git"
        git_branch = ref.split('refs/heads/')[1]
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        url = f'{JENKINS_HOST}/job/{JENKINS_PROJECT}/buildWithParameters?token={JENKINS_KEY}&GITHUB_URL={git_url}&TESTS={tests_to_run}&GIT_BRANCH={git_branch}'
        resp = requests.get(url, headers, auth=HTTPBasicAuth(JENKINS_USER, JENKINS_KEY))
        response = jsonify({"Status": resp.status_code}), 200
    else:
        response = jsonify({"Status": "Not Applicable"}), 200
    return response
