from vr.vulns import vulns
from math import ceil
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import request, render_template, session, redirect, url_for
from flask_login import login_required
from sqlalchemy import text
from vr.functions.table_functions import load_table, update_table
from vr.assets.model.businessapplications import BusinessApplications
from vr.vulns.model.cicdpipelines import CICDPipelines, CICDPipelinesSchema
from vr.vulns.model.pipelinejobs import PipelineJobs, PipelineJobsSchema
from vr.vulns.web.pipeline_stage_data import OPTS


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"


@vulns.route("/all_pipeline_jobs", methods=['GET', 'POST'])
@login_required
def all_pipeline_jobs():
    try:
        NAV['curpage'] = {"name": "All Pipeline Jobs"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        sql_filter = _entity_permissions_filter(user_roles, session, admin_role, filter_key='BusinessApplications.ID')

        new_dict = {
            'db_name': 'PipelineJobs',
            "sort_field": "ID"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict, direction="desc")
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict, direction="desc")

        assets_all = PipelineJobs.query\
            .with_entities(PipelineJobs.ID, CICDPipelines.Name.label('PipelineName'), PipelineJobs.StartDate,
                           PipelineJobs.BuildNum, BusinessApplications.ApplicationName, CICDPipelines.Source.label('PipelineSource'),
                           PipelineJobs.BranchName, PipelineJobs.BuildNum, PipelineJobs.JobName, PipelineJobs.Project,
                           PipelineJobs.GitBranch)\
            .join(BusinessApplications, BusinessApplications.ID == PipelineJobs.ApplicationId, isouter=True) \
            .join(CICDPipelines, PipelineJobs.Source == CICDPipelines.ID, isouter=True) \
            .filter(text(sql_filter)) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((assets_all.total / per_page))
        schema = PipelineJobsSchema(many=True)
        assets = schema.dump(assets_all.items)
        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": assets_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < assets_all.total else assets_all.total
        }
        return render_template('vulns/all_pipeline_jobs.html', entities=assets, user=user, NAV=NAV,
                               table_details=table_details)
    except RuntimeError:
        return render_template('500.html'), 500

@vulns.route("/pipeline_jobs/<id>", methods=['GET', 'POST'])
@login_required
def pipeline_jobs(id):
    try:
        NAV['curpage'] = {"name": "Pipeline Jobs"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        key = 'PipelineJobs.ApplicationId'
        val = id
        filter_list = [f"{key} = '{val}'"]

        new_dict = {
            'db_name': 'PipelineJobs',
            "sort_field": "ID"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict, direction="desc")
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict, direction="desc")

        assets_all = PipelineJobs.query\
            .with_entities(PipelineJobs.ID, CICDPipelines.Name.label('PipelineName'), PipelineJobs.StartDate,
                           PipelineJobs.BuildNum, BusinessApplications.ApplicationName, CICDPipelines.Source.label('PipelineSource'),
                           PipelineJobs.BranchName, PipelineJobs.BuildNum, PipelineJobs.JobName, PipelineJobs.Project,
                           PipelineJobs.GitBranch)\
            .join(BusinessApplications, BusinessApplications.ID == PipelineJobs.ApplicationId, isouter=True) \
            .join(CICDPipelines, PipelineJobs.Source == CICDPipelines.ID, isouter=True) \
            .filter(text("".join(filter_list))) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((assets_all.total / per_page))
        schema = PipelineJobsSchema(many=True)
        assets = schema.dump(assets_all.items)

        NAV['appbar'] = 'ci_cd'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": assets_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < assets_all.total else assets_all.total
        }
        return render_template('vulns/pipeline_jobs.html', entities=assets, user=user, NAV=NAV, app_data=app_data,
                               table_details= table_details)
    except RuntimeError:
        return render_template('500.html'), 500


@vulns.route("/add_cicd_pipeline_stage/<appid>", methods=['GET'])
@login_required
def add_cicd_pipeline_stage(appid):
    NAV['curpage'] = {"name": "Add CI/CD Pipeline Stage"}
    admin_role = APP_ADMIN
    role_req = [APP_ADMIN, 'Application Viewer']
    perm_entity = 'Application'
    user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                          permissions_entity=perm_entity)
    status = _entity_page_permissions_filter(id, user_roles, session, admin_role)
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, NAV=NAV)

    NAV['appbar'] = 'ci_cd'
    app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
    app_data = {'ID': appid, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}

    return render_template('add_cicd_pipeline_stage.html', user=user, NAV=NAV, app_data=app_data)


@vulns.route("/get_cicd_pipeline_stage_data", methods=['POST'])
@login_required
def get_cicd_pipeline_stage_data():
    NAV['curpage'] = {"name": "Add CI/CD Pipeline Stage"}
    admin_role = APP_ADMIN
    role_req = [APP_ADMIN, 'Application Viewer']
    perm_entity = 'Application'
    user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                          permissions_entity=perm_entity)
    status = _entity_page_permissions_filter(id, user_roles, session, admin_role)
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, NAV=NAV)
    platform = request.form.get('platform')
    stage = request.form.get('stage')
    vendor = request.form.get('vendor')
    resp = {}
    if platform and stage:
        opts = OPTS
        for opt in opts:
            if platform == opt['platform'] and stage == opt['stage'] and vendor == opt['vendor']:
                resp['stage_data'] = opt['stage_data']
                resp['env_data'] = opt['env_data']
                resp['pre_reqs'] = opt['pre_reqs']
                break
        return resp, 200
    else:
        return resp, 500

