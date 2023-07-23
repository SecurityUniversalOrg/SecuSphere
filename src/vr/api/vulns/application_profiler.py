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
from authlib.integrations.flask_oauth2 import current_token
from vr.admin.auth_functions import verify_api_key, get_token_auth_header
from vr.functions.routing_functions import check_entity_permissions
from vr.assets.model.applicationprofiles import ApplicationProfiles, ApplicationProfilesSchema


ERROR_RESP = "Error: Invalid API Request"

@api.route("/get_application_profile/<app_id>")
@require_oauth('read:vulnerabilities')
def get_application_profile(app_id):
    token = current_token
    auth, user_id, is_admin = verify_api_key(token)
    response = jsonify({'response': ERROR_RESP}), 403
    if auth == 'valid':
        permitted = check_entity_permissions(is_admin)
        if permitted:
            vulns_all = ApplicationProfiles.query.all()
            schema = ApplicationProfilesSchema(many=True)
            vulns = schema.dump(
                filter(lambda t: t.AppID == app_id, vulns_all)
            )
            response = jsonify(vulns), 200
    return response

@api.route('/add_application_profile/<app_id>', methods=['POST'])
@require_oauth('write:vulnerabilities')
def add_application_profile(app_id):
    form = request.get_json()
    _add_application_profile(app_id, form)
    return jsonify({"result": "Report Delivered"}), 200


def _add_application_profile(app_id, form):
    profile = ApplicationProfiles(
        AppID=app_id,
        SecretScanReq=form['SecretScanReq'],
        SecretScanData=form['SecretScanData'],
        SCAReq=form['SCAReq'],
        SCAData=form['SCAData'],
        SASTReq=form['SASTReq'],
        SASTData=form['SASTData'],
        IACReq=form['IACReq'],
        IACData=form['IACData'],
        ContainerReq=form['ContainerReq'],
        ContainerData=form['ContainerData'],
        InfrastructureScanReq=form['InfrastructureScanReq'],
        InfrastructureScanData=form['InfrastructureScanData'],
        DASTReq=form['DASTReq'],
        DASTData=form['DASTData'],
        DASTApiReq=form['DASTApiReq'],
        DASTApiData=form['DASTApiData'],
        CICDConfigLocations=form['CICDConfigLocations'],
        CICDConfigData=form['CICDConfigData']
    )
    db.session.add(profile)
    db_connection_handler(db)


