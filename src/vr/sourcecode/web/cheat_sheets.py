from vr.sourcecode import sourcecode
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import render_template, session, redirect, url_for
from flask_login import login_required
import os


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"


@sourcecode.route("/all_cheatsheets", methods=['GET'])
@login_required
def all_cheatsheets():
    try:
        NAV['curpage'] = {"name": "Cheat Sheets"}
        admin_role = APP_ADMIN
        role_req = [admin_role, 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        cwd = os.getcwd()
        if 'var' in cwd and 'www' in cwd and 'html' in cwd:
            filepath = f'/var/www/html/src/vr/sourcecode/cheat_sheets/Index.md'
        else:
            filepath = f'vr/sourcecode/cheat_sheets/Index.md'
        with open(filepath, 'r', encoding="utf8") as infile:
            mkd_text = infile.read()
        return render_template('sourcecode/cheat_sheet.html', mkd_text=mkd_text, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500


@sourcecode.route("/cheatsheets/<sheet_name>", methods=['GET'])
@login_required
def cheatsheets(sheet_name):
    try:
        NAV['curpage'] = {"name": "Cheat Sheets"}
        admin_role = APP_ADMIN
        role_req = [admin_role, 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        cwd = os.getcwd()
        if 'var' in cwd and 'www' in cwd and 'html' in cwd:
            filepath = f'/var/www/html/src/vr/sourcecode/cheat_sheets/{sheet_name}.md'
        else:
            filepath = f'vr/sourcecode/cheat_sheets/{sheet_name}.md'
        with open(filepath, 'r', encoding="utf8") as infile:
            mkd_text = infile.read()
        return render_template('sourcecode/cheat_sheet.html', mkd_text=mkd_text, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500


