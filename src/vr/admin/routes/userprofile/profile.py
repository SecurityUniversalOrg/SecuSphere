import datetime
import base64
import os
from io import BytesIO
import pyqrcode

from flask import session, redirect, url_for, render_template, request, json
from flask_login import login_required
# Start of Entity-specific Imports
from vr import db, app
from vr.admin import admin
from vr.admin.models import User, Messages, MessagesStatus
from vr.vulns.model.vulnerabilities import Vulnerabilities
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from sqlalchemy import text
from vr.assets.model.businessapplications import BusinessApplications


NAV = {
    'CAT': { "name": "Profile", "url": "admin.profile"}
}
VULN_STATUS_IS_NOT_CLOSED = "Vulnerabilities.Status NOT LIKE 'Closed%'"


@admin.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user, status, user_roles = _auth_user(session, 'No Role')
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, NAV=NAV)
    ua = request.headers.get('User-Agent')
    now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    # Messages
    key = 'Messages.ReceiverUserId'
    val = user.id
    filter_list = f"{key} = {val}"
    base_filter = " AND (MessagesStatus.Status <> 'Closed' OR MessagesStatus.Status IS NULL)"

    if user.is_admin or user.is_security:
        msg_filter = "(" + filter_list + " OR Messages.ReceiverUserId IS NULL)" + base_filter
    else:
        msg_filter = filter_list + base_filter
    messages_all = Messages.query.with_entities(
        Messages.ID, Messages.SenderUserId, Messages.ReceiverUserId, Messages.AddDate, Messages.MessageType,
        Messages.Message, User.username, Messages.EntityType, Messages.EntityID, Vulnerabilities.ApplicationId
    ) \
        .join(MessagesStatus, MessagesStatus.MessageId == Messages.ID, isouter=True) \
        .join(Vulnerabilities, Vulnerabilities.VulnerabilityID == Messages.EntityID, isouter=True) \
        .join(User, User.id == Messages.SenderUserId) \
        .filter(text(msg_filter)).all()
    msg_cnt = len(messages_all)

    # Vulnerabilities
    admin_role = 'Application Admin'
    sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='BusinessApplications.ID')
    vuln_status = "Vulnerabilities.Status LIKE 'Open-New%'"
    sql_filter_mix = vuln_status + " AND (" + sql_filter + ")"

    vuln_all = Vulnerabilities.query.with_entities(
        Vulnerabilities.VulnerabilityID, Vulnerabilities.VulnerabilityName, Vulnerabilities.CVEID,
        Vulnerabilities.CWEID,
        Vulnerabilities.Description, Vulnerabilities.ReleaseDate, Vulnerabilities.Severity,
        Vulnerabilities.Classification,
        Vulnerabilities.Source, Vulnerabilities.LastModifiedDate, Vulnerabilities.ReferenceName,
        Vulnerabilities.ReferenceUrl,
        Vulnerabilities.ReferenceTags, Vulnerabilities.AddDate, Vulnerabilities.SourceCodeFileId,
        Vulnerabilities.SourceCodeFileStartLine,
        Vulnerabilities.SourceCodeFileStartCol, Vulnerabilities.SourceCodeFileEndLine,
        Vulnerabilities.SourceCodeFileEndCol,
        Vulnerabilities.DockerImageId, Vulnerabilities.ApplicationId, Vulnerabilities.HostId, Vulnerabilities.Uri,
        Vulnerabilities.HtmlMethod, Vulnerabilities.Param, Vulnerabilities.Attack, Vulnerabilities.Evidence,
        Vulnerabilities.Solution, Vulnerabilities.VulnerablePackage, Vulnerabilities.VulnerableFileName,
        Vulnerabilities.VulnerableFilePath,
        Vulnerabilities.Status, Vulnerabilities.MitigationDate, BusinessApplications.ApplicationName
    ).join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
        .filter(text(sql_filter_mix)) \
        .all()

    new_vuln_cnt = len(vuln_all)

    if user.is_admin or user.is_security:
        vuln_status = "Vulnerabilities.Status LIKE 'Open-SecReview%'"
    else:
        vuln_status = "Vulnerabilities.Status LIKE 'Open-New%'"
    sql_filter_mix = vuln_status + " AND (" + sql_filter + ")"

    vuln_all = Vulnerabilities.query.with_entities(
        Vulnerabilities.VulnerabilityID, Vulnerabilities.VulnerabilityName, Vulnerabilities.CVEID,
        Vulnerabilities.CWEID,
        Vulnerabilities.Description, Vulnerabilities.ReleaseDate, Vulnerabilities.Severity,
        Vulnerabilities.Classification,
        Vulnerabilities.Source, Vulnerabilities.LastModifiedDate, Vulnerabilities.ReferenceName,
        Vulnerabilities.ReferenceUrl,
        Vulnerabilities.ReferenceTags, Vulnerabilities.AddDate, Vulnerabilities.SourceCodeFileId,
        Vulnerabilities.SourceCodeFileStartLine,
        Vulnerabilities.SourceCodeFileStartCol, Vulnerabilities.SourceCodeFileEndLine,
        Vulnerabilities.SourceCodeFileEndCol,
        Vulnerabilities.DockerImageId, Vulnerabilities.ApplicationId, Vulnerabilities.HostId, Vulnerabilities.Uri,
        Vulnerabilities.HtmlMethod, Vulnerabilities.Param, Vulnerabilities.Attack, Vulnerabilities.Evidence,
        Vulnerabilities.Solution, Vulnerabilities.VulnerablePackage, Vulnerabilities.VulnerableFileName,
        Vulnerabilities.VulnerableFilePath,
        Vulnerabilities.Status, Vulnerabilities.MitigationDate, BusinessApplications.ApplicationName
    ).join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
        .filter(text(sql_filter_mix)) \
        .all()
    findings_needing_action_cnt = len(vuln_all)


    ################
    NAV['curpage'] = {"name": "Profile"}
    return render_template('admin/profile.html', user_roles=user_roles, NAV=NAV, user=user, msg_cnt=msg_cnt,
                           new_vuln_cnt=new_vuln_cnt, findings_needing_action_cnt=findings_needing_action_cnt)


@admin.route('/mobile_qrcode')
@login_required
def mobile_qrcode():
    user, status, user_roles = _auth_user(session, 'No Role')
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, NAV=NAV)

    # render qrcode for FreeTOTP
    otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    totp_uri = f'sumobilesync:///Security-Universal///{otp_secret}///{app.config["APP_EXT_URL"]}///{user.username}'
    url = pyqrcode.create(totp_uri)
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@admin.route('/mfa_qrcode')
@login_required
def mfa_qrcode():
    user, status, user_roles = _auth_user(session, 'No Role')
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, NAV=NAV)

    # render qrcode for FreeTOTP
    totp_uri = f'otpauth://totp/Security-Universal:{user.username}?secret={user.otp_secret}&issuer=Security-Universal'
    url = pyqrcode.create(totp_uri)
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

