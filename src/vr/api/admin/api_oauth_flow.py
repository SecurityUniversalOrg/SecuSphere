from flask import request, session, url_for, jsonify
from flask import render_template, redirect, Response
from authlib.oauth2 import OAuth2Error
from time import sleep
from vr.api import api
from vr.admin.models import User, OAuth2Client
from vr.admin.oauth2 import authorization, require_oauth


NAV = {
    'CAT': { "name": "Admin", "url": "admin.dashboard"}
}


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@api.route('/api/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user()
    # if user log status is not true (Auth server), then to log it in
    if not user:
        return redirect(url_for('home.home', next=request.url))
    if request.method == 'GET':
        try:
            grant = authorization.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=user, grant=grant)
    if not user and 'username' in request.form:
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
    if request.form['confirm']:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)


@api.route('/api/oauth/token', methods=['POST'])
def issue_token():
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            return authorization.create_token_response()
        except Exception as e:
            if attempt < max_attempts - 1:  # i.e. if it's not the final attempt
                sleep(1)
                continue  # go to the next iteration of the loop
            else:  # if it's the final attempt
                return jsonify(error=str(e)), 500


@api.route('/api/oauth/revoke', methods=['POST'])
def revoke_token():
    return authorization.create_endpoint_response('revocation')


@api.route('/api/openapi.yaml')
def api_me():
    yaml_content = render_template('openapi_spec.yaml')
    response = Response(yaml_content, content_type="application/x-yaml")
    return response, 200

