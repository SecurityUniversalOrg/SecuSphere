from flask import session, redirect, url_for, render_template
from flask_login import login_required
# Start of Entity-specific Imports
from vr.admin import admin
from vr.admin.functions import _auth_user, check_menu_tour_init
from config_engine import ENV, PROD_DB_URI, AUTH_TYPE, APP_EXT_URL, LDAP_HOST, LDAP_PORT, LDAP_BASE_DN, \
    LDAP_USER_DN, LDAP_GROUP_DN, LDAP_USER_RDN_ATTR, LDAP_USER_LOGIN_ATTR, LDAP_BIND_USER_DN, LDAP_BIND_USER_PASSWORD, \
    AZAD_CLIENT_ID, AZAD_CLIENT_SECRET, AZAD_AUTHORITY, JENKINS_USER, AZURE_KEYVAULT_NAME, INSECURE_OAUTH, \
    JENKINS_HOST, JENKINS_KEY, JENKINS_PROJECT, JENKINS_STAGING_PROJECT, JENKINS_TOKEN, SMTP_ADMIN_EMAIL, \
    SMTP_HOST, SMTP_PASSWORD, SMTP_USER, SNOW_CLIENT_ID, SNOW_CLIENT_SECRET, SNOW_INSTANCE_NAME, SNOW_PASSWORD, \
    SNOW_USERNAME, VERSION


NAV = {
    'CAT': { "name": "Settings", "url": "admin.admin_dashboard"}
}

@admin.route('/settings', methods=['GET'])
@login_required
def settings():
    NAV['curpage'] = {"name": "Settings"}
    user, status, user_roles = _auth_user(session, 'No Role')
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, nav_cat={}, nav_subcat='', \
                               nav_subsubcat='', nav_curpage={"name": "Unauthorized"})
    current_settings = {
        "APP_EXT_URL": APP_EXT_URL,
        "AUTH_TYPE": AUTH_TYPE,
        "AZAD_AUTHORITY":AZAD_AUTHORITY,
        "AZAD_CLIENT_ID": AZAD_CLIENT_ID,
        "AZAD_CLIENT_SECRET": AZAD_CLIENT_SECRET,
        "AZURE_KEYVAULT_NAME": AZURE_KEYVAULT_NAME,
        "ENV": ENV,
        "INSECURE_OAUTH": INSECURE_OAUTH,
        "JENKINS_HOST": JENKINS_HOST,
        "JENKINS_KEY": JENKINS_KEY,
        "JENKINS_PROJECT": JENKINS_PROJECT,
        "JENKINS_STAGING_PROJECT": JENKINS_STAGING_PROJECT,
        "JENKINS_TOKEN": JENKINS_TOKEN,
        "JENKINS_USER": JENKINS_USER,
        "LDAP_BASE_DN": LDAP_BASE_DN,
        "LDAP_BIND_USER_DN": LDAP_BIND_USER_DN,
        "LDAP_BIND_USER_PASSWORD": LDAP_BIND_USER_PASSWORD,
        "LDAP_GROUP_DN": LDAP_GROUP_DN,
        "LDAP_HOST": LDAP_HOST,
        "LDAP_PORT": LDAP_PORT,
        "LDAP_USER_DN": LDAP_USER_DN,
        "LDAP_USER_LOGIN_ATTR": LDAP_USER_LOGIN_ATTR,
        "LDAP_USER_RDN_ATTR": LDAP_USER_RDN_ATTR,
        "PROD_DB_URI": PROD_DB_URI,
        "SMTP_ADMIN_EMAIL": SMTP_ADMIN_EMAIL,
        "SMTP_HOST": SMTP_HOST,
        "SMTP_PASSWORD": SMTP_PASSWORD,
        "SMTP_USER": SMTP_USER,
        "SNOW_CLIENT_ID": SNOW_CLIENT_ID,
        "SNOW_CLIENT_SECRET": SNOW_CLIENT_SECRET,
        "SNOW_INSTANCE_NAME": SNOW_INSTANCE_NAME,
        "SNOW_PASSWORD": SNOW_PASSWORD,
        "SNOW_USERNAME": SNOW_USERNAME,
        "VERSION": VERSION,
    }
    return render_template('admin/settings.html', user_roles=user_roles, NAV=NAV,
                           user=user, settings=current_settings)
