from vr.sourcecode import sourcecode
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import request, render_template, session, redirect, url_for, jsonify
from flask_login import login_required
from vr.sourcecode.model.gitrepo import GitRepo
from vr.assets.model.businessapplications import BusinessApplications
from sqlalchemy import text


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}

@sourcecode.route("/all_git_repos")
@login_required
def all_git_repos():
    try:
        NAV['curpage'] = {"name": "Git Repositories"}
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
        assets_all = GitRepo.query\
            .with_entities(GitRepo.ID, GitRepo.RepoName, GitRepo.AddDate,
                           GitRepo.Source, BusinessApplications.ApplicationName) \
            .join(BusinessApplications, BusinessApplications.ID == GitRepo.ApplicationID, isouter=True) \
            .filter(text(sql_filter)) \
            .all()
        return render_template('all_git_repos.html', entities=assets_all, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500




