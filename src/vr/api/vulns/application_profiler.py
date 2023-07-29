import datetime
from vr import db, app
from flask import jsonify, request
from vr.api import api
from vr.admin.functions import db_connection_handler
from vr.admin.oauth2 import require_oauth
from authlib.integrations.flask_oauth2 import current_token
from vr.admin.auth_functions import verify_api_key, get_token_auth_header
from vr.functions.routing_functions import check_entity_permissions
from vr.assets.model.applicationprofiles import ApplicationProfiles, ApplicationProfilesSchema
from vr.assets.model.businessapplications import BusinessApplications


ERROR_RESP = "Error: Invalid API Request"

@api.route("/api/get_application_profile/<app_id>")
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

@api.route('/api/add_application_profile/<repo_name>', methods=['POST'])
@require_oauth('write:vulnerabilities')
def add_application_profile(repo_name):
    form = request.get_json()
    _add_application_profile(repo_name, form)
    return jsonify({"result": "Report Delivered"}), 200


def _add_application_profile(repo_name, form):
    app_obj = BusinessApplications.query.filter(BusinessApplications.ApplicationAcronym.ilike(repo_name)).first()
    if app_obj:
        # Try to get the existing profile
        profile = ApplicationProfiles.query.filter_by(AppID=app_obj.ID).first()

        # If the profile exists, update its properties
        if profile:
            profile.AddDate = datetime.datetime.utcnow()
            profile.SecretScanReq = form['SecretScanReq']
            profile.SecretScanData = form['SecretScanData']
            profile.SCAReq = form['SCAReq']
            profile.SCAData = form['SCAData']
            profile.SASTReq = form['SASTReq']
            profile.SASTData = form['SASTData']
            profile.IACReq = form['IACReq']
            profile.IACData = form['IACData']
            profile.ContainerReq = form['ContainerReq']
            profile.ContainerData = form['ContainerData']
            profile.InfrastructureScanReq = form['InfrastructureScanReq']
            profile.InfrastructureScanData = form['InfrastructureScanData']
            profile.DASTReq = form['DASTReq']
            profile.DASTData = form['DASTData']
            profile.DASTApiReq = form['DASTApiReq']
            profile.DASTApiData = form['DASTApiData']
            profile.CICDConfigLocations = form['CICDConfigLocations']
            profile.CICDConfigData = form['CICDConfigData']

        # If the profile does not exist, create a new one
        else:
            profile = ApplicationProfiles(
                AppID=app_obj.ID,
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

        # Commit the changes to the database
        db_connection_handler(db)



