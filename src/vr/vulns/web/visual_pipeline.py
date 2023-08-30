import datetime
from flask import request, render_template, session, redirect, url_for
from flask_login import login_required
from sqlalchemy import text
from vr.api import api
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from vr.sourcecode.model.releaseversions import ReleaseVersions
from vr.sourcecode.model.servicetickets import ServiceTickets
from vr.vulns.model.vulnerabilities import Vulnerabilities


ERROR_RESP = "Error: Invalid API Request"
JIRA_ICON = 'https://cdn.icon-icons.com/icons2/2699/PNG/512/atlassian_jira_logo_icon_170511.png'
VULN_ICON = 'https://www.intel.com/content/dam/www/central-libraries/us/en/images/vpro-feature-icon-hardwaresec.png.rendition.intel.web.576.324.png'
JENKINS_ICON = 'https://upload.wikimedia.org/wikipedia/commons/thumb/e/e9/Jenkins_logo.svg/1200px-Jenkins_logo.svg.png'
GITHUB_ICON = 'https://cdn.b12.io/client_media/hFrglJLF/a362d6a8-f434-11eb-9a00-0242ac110003-png-thumbnail_image.png'
PR_ICON = 'https://upload.wikimedia.org/wikipedia/commons/thumb/8/87/Octicons-git-pull-request.svg/1200px-Octicons-git-pull-request.svg.png'
CODE_ICON = 'https://cdn-icons-png.flaticon.com/512/6614/6614689.png'
IMPCODE_ICON = 'https://cdn1.iconfinder.com/data/icons/minicons-4/64/method4-512.png'
INFCODE_ICON = 'https://prismic-io.s3.amazonaws.com/alpacked/bdb9b092-6b99-4b3a-a24b-8328924ab5c9_code.svg'
JAR_ICON = 'https://cdn-icons-png.flaticon.com/512/28/28857.png'
DOCKERIMG_ICON = 'https://www.docker.com/wp-content/uploads/2022/03/vertical-logo-monochromatic.png'
SNOW_ICON = 'https://upload.wikimedia.org/wikipedia/commons/thumb/5/57/ServiceNow_logo.svg/2560px-ServiceNow_logo.svg.png'
DIR_ICON = 'https://static.thenounproject.com/png/2817677-200.png'
FILE_ICON = 'https://cdn-icons-png.flaticon.com/512/6614/6614689.png'
ONE_ICON = '../static/images/icon_1.png'
TWO_ICON = '../static/images/icon_2.png'
THREE_ICON = '../static/images/icon_3.png'
FOUR_ICON = '../static/images/icon_4.png'
FIVE_ICON = '../static/images/icon_5.png'
SIX_ICON = '../static/images/icon_6.png'
SEVEN_ICON = '../static/images/icon_7.png'
EIGHT_ICON = '../static/images/icon_8.png'
NINE_ICON = '../static/images/icon_9.png'
RELEASE_MGMT = "Release Management"
ISSUE_MGMT = "Issue Management"
CICD_PIPELINE = "CI/CD Pipeline"
STATIC_CODE_ANALYSIS = "Static Code Analysis"
APPLICATION_BUILD = "Application Build"
INFRA_BUILD = "Infrastructure Build"
RELEASE_DEPLOY = "Release/Deploy"
CUSTOM_APP_CODE = "Custom App Code"
CUSTOM_INFRA_CODE = "Custom Infra Code"
IMPORTED_CODE = "Imported Code"
APP_BUILD = "App Build"
INFRA_BUILD_B = "Infra Build"
RELEASE_NOTES = "Release Notes"
CMDB_ENTRY = "CMDB Entry"

vuln_group_details = {'background-color': 'red', 'background-image': VULN_ICON, 'group': 'Vulnerability'}
default_settings = {
    'background-color': {
        'default': 'white',
        'options': ['aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige', 'bisque', 'black', 'blanchedalmond',
                    'blue', 'blueviolet', 'brown', 'burlywood', 'cadetblue', 'chartreuse', 'chocolate', 'coral',
                    'cornflowerblue', 'cornsilk', 'crimson', 'cyan', 'darkblue', 'darkcyan', 'darkgoldenrod', 'darkgrey',
                    'darkgreen', 'darkkhaki', 'darkmagenta', 'darkolivegreen', 'darkorange', 'darkorchid', 'darkred',
                    'darksalmon', 'darkseagreen', 'darkslateblue', 'darkslategrey', 'darkturquoise', 'darkviolet',
                    'deeppink', 'deepskyblue', 'dimgray', 'dodgerblue', 'firebrick', 'floralwhite', 'forestgreen',
                    'fuchsia', 'gainsboro', 'ghostwhite', 'gold', 'goldenrod', 'grey', 'green', 'greenyellow',
                    'honeydew', 'hotpink', 'indianred', 'indigo', 'ivory', 'khaki', 'lavender', 'lavenderblush',
                    'lawngreen', 'lemonchiffon', 'lightblue', 'lightcoral', 'lightcyan', 'lightgoldenrodyellow',
                    'lightgrey', 'lightgreen', 'lightpink', 'lightsalmon', 'lightseagreen', 'lightskyblue',
                    'lightslategrey', 'lightyellow', 'lime', 'limegreen', 'linen', 'magenta', 'maroon',
                    'mediumaquamarine', 'mediumblue', 'mediumorchid', 'mediumpurple', 'mediumseagreen',
                    'mediumslateblue', 'mediumspringgreen', 'mediumturquoise', 'mediumvioletred', 'midnightblue',
                    'mintcream', 'mistyrose', 'moccasin', 'navajowhite', 'navy', 'oldlace', 'olive', 'olivedrab',
                    'orange', 'orangered', 'orchid', 'palegoldenrod', 'palegreen', 'paleturquoise', 'palevioletred',
                    'papayawhip', 'peachpuff', 'peru', 'pink', 'plum', 'powderblue', 'purple', 'red', 'rosybrown',
                    'royalblue', 'saddlebrown', 'salmon', 'sandybrown', 'seagreen' ,'seashell', 'sienna', 'silver',
                    'skyblue', 'slateblue', 'slategrey', 'snow', 'springgreen', 'steelblue', 'tan', 'teal', 'thistle',
                    'tomato', 'turquoise', 'violet', 'wheat', 'white', 'whitesmoke', 'yellow', 'yellowgreen']
    },
    'layout': {
        'default': 'cose',
        'options': ['random', 'preset', 'grid', 'circle', 'concentric', 'breadthfirst', 'cose']
    }
}
APP_ID = 4
RELEASE_ID = 1
NAV = {
    'CAT': { "name": "Threat Modeler", "url": "threat_modeling.threat_modeler"}
}


@api.route("/visual_pipeline/<id>")
@login_required
def visual_pipeline(id):
    NAV['curpage'] = {"name": "Threat Modeler"}
    NAV['subcat'] = ""
    NAV['subsubcat'] = ""
    user, status, user_roles = _auth_user(session, NAV['CAT']['name'])
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, NAV=NAV)

    edge_groups = []
    entity_groups = []
    visualize_pipeline(entity_groups, edge_groups)

    # Release Management Children
    visualize_rel_management(id, entity_groups, edge_groups)

    # Issue Management Children
    visualize_issue_management(entity_groups, edge_groups)

    # SCM Children
    visualize_scm(entity_groups, edge_groups)

    # CI/CD Pipeline Children
    visualize_pipeline_children(entity_groups, edge_groups)

    # Static Code Analysis Children
    # visualize_static_code_analysis(id, entity_groups, edge_groups)

    # Application Build Children
    visualize_app_build(entity_groups, edge_groups)

    # Infrastructure Build Children
    visualize_infra_build(entity_groups, edge_groups)

    # Release/Deploy Children
    visualize_release_deploy(entity_groups, edge_groups)

    # Operate Children
    visualize_operate(entity_groups, edge_groups)

    group_names = [
        RELEASE_MGMT,
        ISSUE_MGMT,
        'SCM',
        CICD_PIPELINE,
        STATIC_CODE_ANALYSIS,
        APPLICATION_BUILD,
        INFRA_BUILD,
        RELEASE_DEPLOY,
        'Operate',
        'Release',
        'Issue',
        'SCM Org',
        'SCM Repo',
        'Pull Request',
        'Pipeline Job',
        CUSTOM_APP_CODE,
        'File',
        'Vulnerability',
        CUSTOM_INFRA_CODE,
        IMPORTED_CODE,
        APP_BUILD,
        INFRA_BUILD_B,
        RELEASE_NOTES,
        CMDB_ENTRY
    ]

    return render_template('visual_pipeline.html', user=user, NAV=NAV, entity_groups=entity_groups, \
                           edge_group=edge_groups, group_names=group_names, default_settings=default_settings)


def add_entity(entities, entity_groups, edge_groups, group_details):
    for ent in entities:
        base = {
            'data': {
                'id': ent[1],
                'name': ent[1],
                'group': group_details['group'],
                'href': '/net_disc',
            },
            'style': {
                'background-color': group_details['background-color']
            }
        }
        if 'background-image' in group_details:
            base['style']['background-image'] = group_details['background-image']
        if len(ent) == 5:
            def as_dict(self):
                return {c.name: getattr(self, c.name) for c in self.__table__.columns}
            db_data = as_dict(ent[4])
            for field in db_data:
                if isinstance(db_data[field], datetime.datetime):
                    db_data[field] = db_data[field].strftime("%Y-%m-%d %H:%M:%S")
                elif db_data[field] == None:
                    db_data[field] = ''
            base['data']['db_data'] = db_data
        entity_groups.append(base)
        edge_groups.append(
            {'id': f"{ent[3]}_to_{ent[1]}", 'source': f"{ent[3]}", 'target': f"{ent[1]}"},
        )
    return entity_groups, edge_groups


def visualize_pipeline(entity_groups, edge_groups):
    ## Core Pipeline ## - N0 MOD
    features = [
        (1, RELEASE_MGMT)
    ]
    group_details = {'background-color': '#666', 'group': 'Features', 'background-image': ONE_ICON}
    for feature in features:
        entity_groups.append(
            {
                'data': {
                    'id': feature[1],
                    'name': feature[1],
                    'group': group_details['group'],
                    'href': '/net_disc',
                },
                'style': {
                    'background-color': group_details['background-color'],
                    'background-image': group_details['background-image']
                }
            }
        )

    # Add Issue Management
    group_details = {'background-color': '#666', 'group': 'JIRA', 'background-image': TWO_ICON}
    for feature in features:
        entities = [
            (1, ISSUE_MGMT, 1, RELEASE_MGMT)  ## ent_id, ent_name, parent_id*, parent_name*
        ]
    entity_groups, edge_groups = add_entity(entities, entity_groups, edge_groups, group_details)

    # Add SCM
    group_details = {'background-color': '#666', 'group': 'SCM', 'background-image': THREE_ICON}
    entities = [
        (1, 'SCM', 1, ISSUE_MGMT)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    entity_groups, edge_groups = add_entity(entities, entity_groups, edge_groups, group_details)

    # Add CI/CD Pipeline
    group_details = {'background-color': '#666', 'group': CICD_PIPELINE, 'background-image': FOUR_ICON}
    entities = [
        (1, CICD_PIPELINE, 1, 'SCM')  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    entity_groups, edge_groups = add_entity(entities, entity_groups, edge_groups, group_details)

    # Add CI/CD Pipeline - Static Code Analysis
    group_details = {'background-color': '#666', 'group': 'CI/CD Pipeline - Static Code Analysis', 'background-image': FIVE_ICON}
    entities = [
        (1, STATIC_CODE_ANALYSIS, 1, CICD_PIPELINE)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    entity_groups, edge_groups = add_entity(entities, entity_groups, edge_groups, group_details)

    # Add CI/CD Pipeline - Application Build
    group_details = {'background-color': '#666', 'group': 'CI/CD Pipeline - Application Build', 'background-image': SIX_ICON}
    entities = [
        (1, APPLICATION_BUILD, 1, STATIC_CODE_ANALYSIS)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    entity_groups, edge_groups = add_entity(entities, entity_groups, edge_groups, group_details)

    # Add CI/CD Pipeline - Infrastructure Build
    group_details = {'background-color': '#666', 'group': 'CI/CD Pipeline - Infrastructure Build', 'background-image': SEVEN_ICON}
    entities = [
        (1, INFRA_BUILD, 1, APPLICATION_BUILD)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    entity_groups, edge_groups = add_entity(entities, entity_groups, edge_groups, group_details)

    # Add CI/CD Pipeline - Release/Deploy
    group_details = {'background-color': '#666', 'group': 'CI/CD Pipeline - Release/Deploy', 'background-image': EIGHT_ICON}
    entities = [
        (1, RELEASE_DEPLOY, 1, INFRA_BUILD)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    entity_groups, edge_groups = add_entity(entities, entity_groups, edge_groups, group_details)

    # Add CI/CD Pipeline - Operate
    group_details = {'background-color': '#666', 'group': 'CI/CD Pipeline - Operate', 'background-image': NINE_ICON}
    entities = [
        (1, 'Operate', 1, RELEASE_DEPLOY)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    entity_groups, edge_groups = add_entity(entities, entity_groups, edge_groups, group_details)

    ## End of Core Pipeline ## - N0 MOD
    return entity_groups, edge_groups


def visualize_rel_management(app_id, entity_groups, edge_groups):
    # Add Release
    group_details = {'background-color': 'green', 'background-image': JIRA_ICON, 'group': 'Release'}
    all_rel_vers = ReleaseVersions.query.filter(ReleaseVersions.ApplicationID==app_id).all()
    entities_list = []
    for i in all_rel_vers:
        entities_list.append((i.ID, i.ReleaseName, app_id, RELEASE_MGMT, i))
    add_entity(entities_list, entity_groups, edge_groups, group_details)


def visualize_issue_management(entity_groups, edge_groups):
    # Add Issue
    group_details = {'background-color': 'green', 'background-image': JIRA_ICON, 'group': 'Issue'}
    all_issue_mgmt = ServiceTickets.query.filter(ServiceTickets.ReleaseID == RELEASE_ID).all()
    entities_list = []
    for i in all_issue_mgmt:
        entities_list.append((i.ID, i.TicketName.split(' - ')[0], RELEASE_ID, ISSUE_MGMT, i))
    add_entity(entities_list, entity_groups, edge_groups, group_details)


def visualize_scm(entity_groups, edge_groups):
    # Add SCM Org
    group_details = {'background-color': 'green', 'background-image': GITHUB_ICON, 'group': 'SCM Org'}
    entities_list = [
        (1, 'SecurityUniversal (Org)', 1, 'SCM')  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    entity_groups, edge_groups = add_entity(entities_list, entity_groups, edge_groups, group_details)
    # Add SCM Repo
    group_details = {'background-color': 'green', 'background-image': GITHUB_ICON, 'group': 'SCM Repo'}
    entities_list = [
        (1, 'Security-Universal-Management (Repo)', 1, 'SecurityUniversal (Org)')
        ## ent_id, ent_name, parent_id*, parent_name*
    ]
    entity_groups, edge_groups = add_entity(entities_list, entity_groups, edge_groups, group_details)
    # SCM Repo Children
    visualize_scm_repo(entity_groups, edge_groups)


def visualize_scm_repo(entity_groups, edge_groups):
    # Add Pull Request
    group_details = {'background-color': 'green', 'background-image': PR_ICON, 'group': 'Pull Request'}
    entities_list = [
        (1, 'PR-1', 1, 'Security-Universal-Management (Repo)')  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    add_entity(entities_list, entity_groups, edge_groups, group_details)


def visualize_pipeline_children(entity_groups, edge_groups):
    # Add Pipeline Request
    group_details = {'background-color': 'green', 'background-image': JENKINS_ICON, 'group': 'Pipeline Job'}
    entities_list = [
        (1, 'Jenkins-123456', 1, CICD_PIPELINE)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    add_entity(entities_list, entity_groups, edge_groups, group_details)


def visualize_static_code_analysis(app_id, entity_groups, edge_groups):
    # Add Custom App Code
    group_details = {'background-color': 'green', 'background-image': CODE_ICON, 'group': CUSTOM_APP_CODE}
    entities_list = [
        (1, CUSTOM_APP_CODE, 1, STATIC_CODE_ANALYSIS)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    add_entity(entities_list, entity_groups, edge_groups, group_details)

    # Add Custom App Code Vulnerabilities
    all_static_code_analysis = Vulnerabilities.query.filter(Vulnerabilities.ApplicationId == app_id)\
        .filter(Vulnerabilities.Classification == 'SAST').all()
    files = []
    for i in all_static_code_analysis:
        fp = i.VulnerableFilePath
        files.append(fp)
    files_data = []
    file_index = 0
    file_group_details = {'background-color': 'green', 'background-image': FILE_ICON, 'group': 'File'}
    for file in files:
        files_data.append((file_index, file, entities_list[0][0], CUSTOM_APP_CODE))
        file_index += 1
    add_entity(files_data, entity_groups, edge_groups, file_group_details)
    vulns_data = []
    for i in all_static_code_analysis:
        vulns_data.append((i.VulnerabilityID, i.VulnerabilityName, entities_list[0][0], i.VulnerableFilePath, i))
    add_entity(vulns_data, entity_groups, edge_groups, vuln_group_details)

    # Add Custom Infra Code
    all_custom_infra_code = Vulnerabilities.query.filter(Vulnerabilities.ApplicationId == app_id) \
        .filter(text("Classification LIKE 'IaC-%'")).all()
    group_details = {'background-color': 'green', 'background-image': INFCODE_ICON, 'group': CUSTOM_INFRA_CODE}
    entities_list = [
        (1, CUSTOM_INFRA_CODE, 1, STATIC_CODE_ANALYSIS)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    add_entity(entities_list, entity_groups, edge_groups, group_details)
    files = []
    for i in all_custom_infra_code:
        fp = i.VulnerableFileName
        files.append(fp)
    files_data = []
    file_index = 0
    file_group_details = {'background-color': 'green', 'background-image': FILE_ICON, 'group': 'File'}
    for file in files:
        files_data.append((file_index, file, entities_list[0][0], CUSTOM_INFRA_CODE))
        file_index += 1
    add_entity(files_data, entity_groups, edge_groups, file_group_details)
    vulns_data = []
    for i in all_custom_infra_code:
        vulns_data.append((i.VulnerabilityID, i.VulnerabilityName, entities_list[0][0], i.VulnerableFileName, i))
    add_entity(vulns_data, entity_groups, edge_groups, vuln_group_details)

    # Add Imported Code
    all_imported_code = Vulnerabilities.query.filter(Vulnerabilities.ApplicationId == app_id) \
        .filter(Vulnerabilities.Classification == 'SCA').all()
    group_details = {'background-color': 'green', 'background-image': IMPCODE_ICON, 'group': IMPORTED_CODE}
    entities_list = [
        (1, IMPORTED_CODE, 1, STATIC_CODE_ANALYSIS)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    add_entity(entities_list, entity_groups, edge_groups, group_details)
    files = []
    for i in all_imported_code:
        fp = i.VulnerableFilePath
        if not fp:
            fp = i.VulnerablePackage
        files.append(fp)
    files_data = []
    file_index = 0
    file_group_details = {'background-color': 'green', 'background-image': FILE_ICON, 'group': 'File'}
    for file in files:
        files_data.append((file_index, file, entities_list[0][0], IMPORTED_CODE))
        file_index += 1
    add_entity(files_data, entity_groups, edge_groups, file_group_details)
    pkg_data = []
    pkg_index = 0
    for i in all_imported_code:
        pkg_data.append((pkg_index, i.VulnerablePackage, entities_list[0][0], i.VulnerableFilePath))
        pkg_index += 1
    add_entity(pkg_data, entity_groups, edge_groups, file_group_details)
    vulns_data = []
    for i in all_imported_code:
        vulns_data.append((i.VulnerabilityID, i.VulnerabilityName, entities_list[0][0], i.VulnerablePackage, i))
    add_entity(vulns_data, entity_groups, edge_groups, vuln_group_details)


def visualize_app_build(entity_groups, edge_groups):
    # Add App Build
    group_details = {'background-color': 'green', 'background-image': JAR_ICON, 'group': APP_BUILD}
    entities_list = [
        (1, APP_BUILD, 1, APPLICATION_BUILD)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    add_entity(entities_list, entity_groups, edge_groups, group_details)


def visualize_infra_build(entity_groups, edge_groups):
    # Add Infra Build
    group_details = {'background-color': 'green', 'background-image': DOCKERIMG_ICON, 'group': INFRA_BUILD_B}
    entities_list = [
        (1, INFRA_BUILD_B, 1, INFRA_BUILD)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    add_entity(entities_list, entity_groups, edge_groups, group_details)


def visualize_release_deploy(entity_groups, edge_groups):
    # Add Release Notes
    group_details = {'background-color': 'green', 'background-image': JIRA_ICON, 'group': RELEASE_NOTES}
    entities_list = [
        (1, RELEASE_NOTES, 1, RELEASE_DEPLOY)  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    add_entity(entities_list, entity_groups, edge_groups, group_details)


def visualize_operate(entity_groups, edge_groups):
    # Add CMDB Entry
    group_details = {'background-color': 'green', 'background-image': SNOW_ICON, 'group': CMDB_ENTRY}
    entities_list = [
        (1, CMDB_ENTRY, 1, 'Operate')  ## ent_id, ent_name, parent_id*, parent_name*
    ]
    add_entity(entities_list, entity_groups, edge_groups, group_details)


@api.route("/visual_vulnerabilities/<id>")
@login_required
def visual_vulnerabilities(id):
    NAV['curpage'] = {"name": "Threat Modeler"}
    NAV['subcat'] = ""
    NAV['subsubcat'] = ""
    user, status, user_roles = _auth_user(session, NAV['CAT']['name'])
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, NAV=NAV)

    edge_groups = [
        {
            "id": 'Release Management_to_Issue Management',
            "source": 'Release Management',
            "target": 'Issue Management'
        }
    ]
    entity_groups = [
        {
            "data": {
                "id": 'Release Management',
                "name": 'Release Management',
                "group": 'Features',
                "href": '/net_disc'
            },
            "style": {
                'background-color': '#666',
                'background-image': '../static/images/icon_1.png'
            }
        },
        {
            "data": {
                "id": 'Issue Management',
                "name": 'Issue Management',
                "group": 'JIRA',
                "href": '/net_disc'
            },
            "style": {
                'background-color': '#666',
                'background-image': '../static/images/icon_2.png'
            }
        }
    ]


    group_names = [
        RELEASE_MGMT,
        ISSUE_MGMT,
    ]

    return render_template('visual_pipeline.html', user=user, NAV=NAV, entity_groups=entity_groups, \
                           edge_group=edge_groups, group_names=group_names, default_settings=default_settings)
