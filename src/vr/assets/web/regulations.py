from vr.assets import assets
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import render_template, session, redirect, url_for
from flask_login import login_required
from vr.assets.model.regulations import Regulations, MakeRegulationsSchema, RegulationsSchema



NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}


@assets.route("/all_regulations")
@login_required
def all_regulations():
    try:
        NAV['curpage'] = {"name": "Regulations"}
        user, status, user_roles = _auth_user(session, 'No Role')
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        assets_all = Regulations.query.all()
        schema = RegulationsSchema(many=True)
        assets = schema.dump(
            filter(lambda t: t.ID != '', assets_all)
        )
        return render_template('assets/all_regulations.html', entities=assets, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500




