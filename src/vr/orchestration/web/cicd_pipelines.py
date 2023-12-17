import io
import yaml

from vr.orchestration import orchestration
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from flask import render_template, session, redirect, url_for, request, send_file, jsonify, Response
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications
from vr.orchestration.model.cicdpipelines import CICDPipelines, CICDPipelinesSchema
from vr.assets.model.integrations import Integrations, IntegrationsSchema
from sqlalchemy import text


NAV = {
    'CAT': { "name": "Source Code", "url": "sourcecode.dashboard"}
}

@orchestration.route("/all_pipelines")
@login_required
def all_pipelines():
    try:
        NAV['curpage'] = {"name": "All CI/CD Pipelines"}
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

        assets_all = CICDPipelines.query\
            .with_entities(CICDPipelines.ID, CICDPipelines.Name, CICDPipelines.Description, CICDPipelines.Url,
                           BusinessApplications.ApplicationName, Integrations.Name.label('IntegrationName'))\
            .join(BusinessApplications, BusinessApplications.ID == CICDPipelines.ApplicationID, isouter=True) \
            .join(Integrations, Integrations.ID == CICDPipelines.IntegrationID, isouter=True) \
            .filter(text(sql_filter)) \
            .all()
        return render_template('orchestration/all_pipelines.html', entities=assets_all, user=user, NAV=NAV)
    except RuntimeError:
        return render_template('500.html'), 500


@orchestration.route("/pipeline_generator/<appid>")
@login_required
def pipeline_generator(appid):
    try:
        NAV['curpage'] = {"name": "Pipeline Generator"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        NAV['appbar'] = 'ci_cd'
        app = BusinessApplications.query.filter(text(f'ID={appid}')).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
        return render_template('orchestration/pipeline_generator.html', user=user, NAV=NAV, app_data=app_data)
    except RuntimeError:
        return render_template('500.html'), 500


@orchestration.route('/analyze', methods=['POST'])
def analyze_stages():
    try:
        NAV['curpage'] = {"name": "Pipeline Generator"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        stages = request.json['stages']
        # Mock logic to determine additional input fields and labels
        fields = [
            {
                'name': 'details_' + stage.lower(),
                'label': f'{stage} Details',  # Label for the input field
                'placeholder': f'Enter details for {stage}'
            } for stage in stages
        ]
        return jsonify({'fields': fields})
    except RuntimeError:
        return render_template('500.html'), 500


@orchestration.route('/submit', methods=['POST'])
def submit_pipeline():
    try:
        NAV['curpage'] = {"name": "Pipeline Generator"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        data = request.json
        yaml_content = generate_yaml(data)

        yaml_file = io.StringIO(yaml_content)
        bytes_io = io.BytesIO(yaml_file.getvalue().encode())

        response = Response(bytes_io.getvalue(), mimetype='text/yaml')
        response.headers['Content-Disposition'] = 'attachment; filename=pipeline.yaml'
        return response

    except Exception as e:
        print(e)
        return render_template('500.html'), 500


def generate_yaml(data):
    """
    Generate YAML content from the provided data.

    :param data: A dictionary containing the pipeline stages and additional inputs.
    :return: A string representation of the YAML content.
    """
    # Example of converting the data to a YAML format
    # You can customize the structure as needed for your application
    yaml_dict = {
        'pipeline': {
            'stages': data['stages'],
            'inputs': {input_item['name']: input_item['value'] for input_item in data['inputs']}
        }
    }

    # Convert the dictionary to a YAML string
    yaml_content = yaml.dump(yaml_dict, default_flow_style=False)
    return yaml_content
