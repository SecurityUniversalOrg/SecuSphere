from vr.orchestration import orchestration
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import request, render_template, session, redirect, url_for, jsonify
from flask_login import login_required
from sqlalchemy import text, func
from vr.assets.model.businessapplications import BusinessApplications
from vr.orchestration.model.dockerimages import DockerImages, DockerImagesSchema
from vr.orchestration.model.dockerimageapppair import DockerImageAppPair
from vr.vulns.model.integrations import Integrations, IntegrationsSchema
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema
from math import ceil
from vr.functions.table_functions import load_table, update_table


NAV = {
    'CAT': { "name": "Orchestration", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"
APP_VIEWER = "Application Viewer"
LOGIN_URL = "admin.login"
UNAUTH_URL = "403.html"
SERVER_ERR_URL = "500.html"


@orchestration.route("/all_dockerimages", methods=['GET', 'POST'])
@login_required
def all_dockerimages():
    try:
        NAV['curpage'] = {"name": "All Docker Images"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for(LOGIN_URL))
        elif status == 403:
            return render_template(UNAUTH_URL, user=user, NAV=NAV)

        sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='DockerImageAppPair.AppID')

        new_dict = {
            'db_name': '',
            "sort_field": "total_vulnerabilities"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict, aggregate_field=True, direction="desc")
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict, aggregate_field=True, direction="desc")

        assets_all = DockerImages.query.with_entities(
            DockerImages.ID, DockerImages.AddDate, DockerImages.ImageName, DockerImages.ImageTag, DockerImages.ImageId,
            DockerImages.AppIdList, func.count(Vulnerabilities.VulnerabilityID).label('total_vulnerabilities')
        ).join(Vulnerabilities, Vulnerabilities.DockerImageId == DockerImages.ID) \
            .filter(text(sql_filter)) \
            .group_by(DockerImages.ID) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((assets_all.total / per_page))
        schema = DockerImagesSchema(many=True)
        assets = schema.dump(assets_all.items)


        entities = []
        for i in assets:
            new_dict = {
                "ID": i['ID'],
                "app_names": [],
                "AddDate": i['AddDate'],
                "ImageName": i['ImageName'],
                "ImageTag": i['ImageTag'],
                "ImageId": i['ImageId'],
                "total_vulnerabilities": i['total_vulnerabilities']
            }
            apps = i['AppIdList'].split(',') if i['AppIdList'] else []
            for a in apps:
                if a:
                    app_data = BusinessApplications.query.filter(text(f"ID = {a}")).first()
                    app_name = app_data.ApplicationName
                    new_dict['app_names'].append({'ID': a, 'AppName': app_name})
            entities.append(new_dict)

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": assets_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < assets_all.total else assets_all.total
        }
        return render_template('all_dockerimages.html', entities=entities, user=user, NAV=NAV, table_details=table_details)
    except RuntimeError:
        return render_template(SERVER_ERR_URL), 500


@orchestration.route("/dockerimages/<appid>", methods=['GET', 'POST'])
@login_required
def dockerimages(appid):
    try:
        NAV['curpage'] = {"name": "Docker Images"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for(LOGIN_URL))
        elif status == 403:
            return render_template(UNAUTH_URL, user=user, NAV=NAV)

        new_dict = {
            'db_name': 'PipelineJobs',
            "sort_field": "total_vulnerabilities"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict, aggregate_field=True, direction="desc")
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict, aggregate_field=True, direction="desc")

        assets_all = DockerImages.query.with_entities(
            DockerImages.ID, DockerImages.AddDate, DockerImages.ImageName, DockerImages.ImageTag, DockerImages.ImageId,
            DockerImages.AppIdList, func.count(Vulnerabilities.VulnerabilityID).label('total_vulnerabilities')
        ).join(Vulnerabilities, Vulnerabilities.DockerImageId == DockerImages.ID) \
            .filter(text(f"DockerImages.AppIdList LIKE '%{appid},%'")) \
            .group_by(DockerImages.ID) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((assets_all.total / per_page))
        schema = DockerImagesSchema(many=True)
        assets = schema.dump(assets_all.items)



        entities = []
        for i in assets:
            new_dict = {
                "ID": i['ID'],
                "app_names": [],
                "AddDate": i['AddDate'],
                "ImageName": i['ImageName'],
                "ImageTag": i['ImageTag'],
                "ImageId": i['ImageId'],
                "total_vulnerabilities": i['total_vulnerabilities']
            }
            apps = i['AppIdList'].split(',')
            for a in apps:
                if a:
                    app_data = BusinessApplications.query.filter(text(f"ID = {a}")).first()
                    app_name = app_data.ApplicationName
                    new_dict['app_names'].append({'ID': a, 'AppName': app_name})
            entities.append(new_dict)
        NAV['appbar'] = 'endpoints'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName}

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": assets_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < assets_all.total else assets_all.total
        }
        return render_template('dockerimages.html', app_data=app_data, entities=entities, user=user, NAV=NAV,
                               table_details=table_details)
    except RuntimeError:
        return render_template(SERVER_ERR_URL), 500
