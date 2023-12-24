from vr import db
from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, _add_page_permissions_filter
from sqlalchemy import text
from flask import render_template, session, redirect, url_for, request
from flask_login import login_required
from vr.vulns.model.sgglobalthresholds import SgGlobalThresholds


NAV = {
    'CAT': { "name": "Settings", "url": "sourcecode.dashboard"}
}

@vulns.route("/securitygatesettings", methods=['GET'])
@login_required
def securitygatesettings():
    try:
        NAV['curpage'] = {"name": "Security Gate Settings"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        settings = SgGlobalThresholds.query.filter(text("Name='General'")).first()
        if settings is None:
            return render_template('500.html'), 500
        NAV['appbar'] = 'ci_cd'
        return render_template('vulns/settings.html', user=user, NAV=NAV,
                               settings=settings)
    except RuntimeError:
        return render_template('500.html'), 500



@vulns.route("/update_securitygatesettings", methods=['POST'])
@login_required
def update_securitygatesettings():
    try:
        NAV['curpage'] = {"name": "Security Gate Settings"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        settings = SgGlobalThresholds.query.filter(text("Name='General'")).first()
        if settings:
            all = request.form
            # Update each setting from the form
            settings.ThreshScaLow = request.form.get('ThreshScaLow', type=int)
            settings.ThreshScaMedium = request.form.get('ThreshScaMedium', type=int)
            settings.ThreshScaHigh = request.form.get('ThreshScaHigh', type=int)
            settings.ThreshScaCritical = request.form.get('ThreshScaCritical', type=int)
            settings.ThreshContainerLow = request.form.get('ThreshContainerLow', type=int)
            settings.ThreshContainerMedium = request.form.get('ThreshContainerMedium', type=int)
            settings.ThreshContainerHigh = request.form.get('ThreshContainerHigh', type=int)
            settings.ThreshContainerCritical = request.form.get('ThreshContainerCritical', type=int)
            settings.ThreshDastLow = request.form.get('ThreshDastLow', type=int)
            settings.ThreshDastMedium = request.form.get('ThreshDastMedium', type=int)
            settings.ThreshDastHigh = request.form.get('ThreshDastHigh', type=int)
            settings.ThreshDastCritical = request.form.get('ThreshDastCritical', type=int)
            settings.ThreshDastApiLow = request.form.get('ThreshDastApiLow', type=int)
            settings.ThreshDastApiMedium = request.form.get('ThreshDastApiMedium', type=int)
            settings.ThreshDastApiHigh = request.form.get('ThreshDastApiHigh', type=int)
            settings.ThreshDastApiCritical = request.form.get('ThreshDastApiCritical', type=int)
            settings.ThreshInfrastructureLow = request.form.get('ThreshInfrastructureLow', type=int)
            settings.ThreshInfrastructureMedium = request.form.get('ThreshInfrastructureMedium', type=int)
            settings.ThreshInfrastructureHigh = request.form.get('ThreshInfrastructureHigh', type=int)
            settings.ThreshInfrastructureCritical = request.form.get('ThreshInfrastructureCritical', type=int)
            settings.ThreshSastLow = request.form.get('ThreshSastLow', type=int)
            settings.ThreshSastMedium = request.form.get('ThreshSastMedium', type=int)
            settings.ThreshSastHigh = request.form.get('ThreshSastHigh', type=int)
            settings.ThreshSastCritical = request.form.get('ThreshSastCritical', type=int)
            settings.ThreshIacLow = request.form.get('ThreshIacLow', type=int)
            settings.ThreshIacMedium = request.form.get('ThreshIacMedium', type=int)
            settings.ThreshIacHigh = request.form.get('ThreshIacHigh', type=int)
            settings.ThreshIacCritical = request.form.get('ThreshIacCritical', type=int)
            settings.ThreshSecretsLow = request.form.get('ThreshSecretsLow', type=int)
            settings.ThreshSecretsMedium = request.form.get('ThreshSecretsMedium', type=int)
            settings.ThreshSecretsHigh = request.form.get('ThreshSecretsHigh', type=int)
            settings.ThreshSecretsCritical = request.form.get('ThreshSecretsCritical', type=int)

            db.session.commit()

        return redirect(url_for('vulns.securitygatesettings'))
    except RuntimeError:
        return render_template('500.html'), 500
