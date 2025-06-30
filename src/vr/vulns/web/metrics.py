import datetime
from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from sqlalchemy import text
from flask import render_template, session, redirect, url_for, request
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema
from vr.assets.model.cicdpipelinebuilds import CICDPipelineBuilds
from vr.assets.model.cicdpipelinestagedata import CICDPipelineStageData
from vr.orchestration.model.cicdpipelines import CICDPipelines

NAV = {
    'CAT': { "name": "Vulnerabilities", "url": "sourcecode.dashboard"}
}

@vulns.route("/metrics/<id>")
@login_required
def component_metrics(id):
    try:
        NAV['curpage'] = {"name": "Metrics"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        key = 'ApplicationId'
        val = id
        filter_list = [f"{key} = '{val}'"]
        vuln_all = Vulnerabilities.query.filter(text("".join(filter_list))).all()
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all)
        NAV['appbar'] = 'metrics'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
        findings_map = {}
        reviewed_findings = parse_vuln_findings(vuln_all, 'reviewed')
        findings_map['reviewed_findings'] = reviewed_findings
        open_findings = parse_vuln_findings(vuln_all, 'open')
        findings_map['open_findings'] = open_findings
        risk_accepted_findings = parse_vuln_findings(vuln_all, 'risk_accepted')
        findings_map['risk_accepted_findings'] = risk_accepted_findings
        closed_findings = parse_vuln_findings(vuln_all, 'closed')
        findings_map['closed_findings'] = closed_findings
        closed_manually = parse_vuln_findings(vuln_all, 'closed_manually')
        findings_map['closed_manually'] = closed_manually
        total_findings = parse_vuln_findings(vuln_all, 'total')
        findings_map['total_findings'] = total_findings
        secreview_findings = parse_vuln_findings(vuln_all, 'secreview_findings')
        findings_map['secreview_findings'] = secreview_findings
        false_positive_findings = parse_vuln_findings(vuln_all, 'false_positive')
        findings_map['false_positive_findings'] = false_positive_findings
        details_map = {}
        details_map = get_week_metadata(details_map, vuln_all)
        details_map = get_finding_age(details_map, vuln_all)
        details_map = get_finding_by_dow(details_map, vuln_all)
        details_map = get_finding_by_test_type(details_map, vuln_all)
        details_map = get_finding_by_cwe_type(details_map, vuln_all)
        metrics = get_kpi(vuln_all)
        return render_template('vulns/component_metrics.html',  entities=assets, app_data=app_data, user=user, NAV=NAV,
                               findings_map=findings_map, details_map=details_map, metrics=metrics)
    except RuntimeError:
        return render_template('500.html'), 500


def get_finding_by_cwe_type(details_map, all_vulns):
    cwe_types = {}
    for i in all_vulns:
        if i.CWEID and i.Status != 'Closed' and not i.Status.startswith('RiskAccept'):
            if i.CWEID not in cwe_types:
                cwe_types[i.CWEID] = 0
            cwe_types[i.CWEID] +=1
    details_map['cwe_types_open'] = cwe_types
    cwe_types = {}
    for i in all_vulns:
        if i.CWEID:
            if i.CWEID not in cwe_types:
                cwe_types[i.CWEID] = 0
            cwe_types[i.CWEID] += 1
    details_map['cwe_types_total'] = cwe_types
    details_map['cwe_types_open_cnt'] = 0
    for i in details_map['cwe_types_open']:
        eval = details_map['cwe_types_open'][i]
        details_map['cwe_types_open_cnt'] += eval
    details_map['cwe_types_total_cnt'] = 0
    for i in details_map['cwe_types_total']:
        eval = details_map['cwe_types_total'][i]
        details_map['cwe_types_total_cnt'] += eval
    return details_map


def get_finding_by_test_type(details_map, all_vulns):
    test_types = {}
    for i in all_vulns:
        class_type = i.Classification if '-' not in i.Classification else i.Classification.split('-')[0]
        if class_type not in test_types:
            test_types[class_type] = 0
        test_types[class_type] +=1
    details_map['test_types'] = test_types
    return details_map


def get_finding_by_dow(details_map, all_vulns):
    dow = {'Monday': 0, 'Tuesday': 0, 'Wednesday': 0, 'Thursday': 0, 'Friday': 0, 'Saturday': 0, 'Sunday': 0}
    for i in all_vulns:
        day_int = i.AddDate.weekday()
        if day_int == 0:
            dow['Monday'] += 1
        elif day_int == 1:
            dow['Tuesday'] += 1
        elif day_int == 2:
            dow['Wednesday'] += 1
        elif day_int == 3:
            dow['Thursday'] += 1
        elif day_int == 4:
            dow['Friday'] += 1
        elif day_int == 5:
            dow['Saturday'] += 1
        elif day_int == 6:
            dow['Sunday'] += 1
    details_map['dow'] = dow
    return details_map


def get_finding_age(details_map, all_vulns):
    now = datetime.datetime.utcnow()
    days_open = {}
    for i in all_vulns:
        if i.Status.startswith('Open-'):
            add_date = i.AddDate
            open_days = (now - add_date).days
            if open_days not in days_open:
                days_open[open_days] = 0
            days_open[open_days] +=1
    details_map['days_open'] = days_open
    return details_map


def get_week_metadata(details_map, all_vulns):
    all_weeks = {}
    try:
        for i in all_vulns:
            all_weeks = _get_vulns_per_week(i, all_weeks)
    except:
        pass
    details_map['all_weeks'] = all_weeks
    return details_map


def _get_vulns_per_week(i, all_weeks):
    monday_for_add = datetime.datetime.strftime(i.AddDate + datetime.timedelta(days=(0 - i.AddDate.weekday())),
                                                "%Y-%m-%d")
    if monday_for_add not in all_weeks:
        all_weeks[monday_for_add] = {'opened': 0, 'closed': 0, 'accepted': 0, 'new_critical': 0, 'new_high': 0,
                                     'new_medium': 0, 'new_low': 0, 'new_info': 0}
    monday_for_modified = datetime.datetime.strftime(
        i.LastModifiedDate + datetime.timedelta(days=(0 - i.LastModifiedDate.weekday())), "%Y-%m-%d")
    if monday_for_modified not in all_weeks:
        all_weeks[monday_for_modified] = {'opened': 0, 'closed': 0, 'accepted': 0, 'new_critical': 0, 'new_high': 0,
                                          'new_medium': 0, 'new_low': 0, 'new_info': 0}
    if i.Status != 'Closed' and not i.Status.startswith('RiskAccept'):
        all_weeks[monday_for_add]['opened'] += 1
    elif i.Status == 'Closed':
        all_weeks[monday_for_modified]['closed'] += 1
    else:  # means the status field must start with RiskAccept
        all_weeks[monday_for_modified]['accepted'] += 1
    if i.Severity == 'Informational':
        all_weeks[monday_for_add]['new_info'] += 1
    elif i.Severity == 'Low':
        all_weeks[monday_for_add]['new_low'] += 1
    elif i.Severity == 'Medium':
        all_weeks[monday_for_add]['new_medium'] += 1
    elif i.Severity == 'High':
        all_weeks[monday_for_add]['new_high'] += 1
    elif i.Severity == 'Critical':
        all_weeks[monday_for_add]['new_critical'] += 1
    return all_weeks


def parse_vuln_findings(all_vulns, filter_type):
    findings = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for vuln in all_vulns:
        dispo = vuln.Status
        if dispo.startswith('Open-Reviewed-'):
            dispo = 'reviewed'
        elif dispo.startswith('Open-RiskAccepted-'):
            dispo = 'risk_accepted'
        elif dispo.startswith('Closed-'):
            dispo = 'closed'
        elif dispo.startswith('Closed-Manual-'):
            dispo = 'closed_manually'
        elif dispo.startswith('Open-SecReview-'):
            dispo = 'secreview_findings'
        elif dispo.startswith('Closed-Auto-False Positive') or dispo == 'Closed-Manual-False Positive':
            dispo = 'false_positive'
        if dispo == filter_type or filter_type == 'total':
            findings = _set_vuln_findings(findings, vuln)
        elif filter_type == 'open' and dispo.startswith('Open-'):
            findings = _set_vuln_findings(findings, vuln)

    return findings


def _set_vuln_findings(findings, vuln):
    findings['total'] += 1
    findings = parse_vuln_severity(vuln, findings)
    return findings


def parse_vuln_severity(vuln, findings):
    if vuln.Severity == 'Informational':
        findings['info'] += 1
    elif vuln.Severity == 'Low':
        findings['low'] += 1
    elif vuln.Severity == 'Medium':
        findings['medium'] += 1
    elif vuln.Severity == 'High':
        findings['high'] += 1
    elif vuln.Severity == 'Critical':
        findings['critical'] += 1
    return findings


@vulns.route("/all_application_metrics")
@login_required
def all_application_metrics():
    try:
        NAV['curpage'] = {"name": "Metrics"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        vuln_all = Vulnerabilities.query.all()
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all)
        NAV['appbar'] = 'metrics'
        findings_map = {}
        reviewed_findings = parse_vuln_findings(vuln_all, 'reviewed')
        findings_map['reviewed_findings'] = reviewed_findings
        open_findings = parse_vuln_findings(vuln_all, 'open')
        findings_map['open_findings'] = open_findings
        risk_accepted_findings = parse_vuln_findings(vuln_all, 'risk_accepted')
        findings_map['risk_accepted_findings'] = risk_accepted_findings
        closed_findings = parse_vuln_findings(vuln_all, 'closed')
        findings_map['closed_findings'] = closed_findings
        closed_manually = parse_vuln_findings(vuln_all, 'closed_manually')
        findings_map['closed_manually'] = closed_manually
        total_findings = parse_vuln_findings(vuln_all, 'total')
        findings_map['total_findings'] = total_findings
        secreview_findings = parse_vuln_findings(vuln_all, 'secreview_findings')
        findings_map['secreview_findings'] = secreview_findings
        false_positive_findings = parse_vuln_findings(vuln_all, 'false_positive')
        findings_map['false_positive_findings'] = false_positive_findings
        details_map = {}
        details_map = get_week_metadata(details_map, vuln_all)
        details_map = get_finding_age(details_map, vuln_all)
        details_map = get_finding_by_dow(details_map, vuln_all)
        details_map = get_finding_by_test_type(details_map, vuln_all)
        details_map = get_finding_by_cwe_type(details_map, vuln_all)
        return render_template('vulns/all_application_metrics.html',  entities=assets, user=user, NAV=NAV,
                               findings_map=findings_map, details_map=details_map)
    except RuntimeError:
        return render_template('500.html'), 500


@vulns.route("/applevel_metrics/<app_name>")
@login_required
def applevel_metrics(app_name):
    try:
        NAV['curpage'] = {"name": "Metrics"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        key = 'BusinessApplications.ApplicationName'
        val = app_name
        filter_list = [f"{key} = '{val}'"]
        vuln_all = Vulnerabilities.query\
            .join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId)\
            .filter(BusinessApplications.ApplicationName == app_name).all()
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all)
        NAV['appbar'] = 'metrics'
        app = BusinessApplications.query.filter(BusinessApplications.ApplicationName == app_name).first()
        app_data = {'ID': app.ID, 'ApplicationName': app.ApplicationName}
        findings_map = {}
        reviewed_findings = parse_vuln_findings(vuln_all, 'reviewed')
        findings_map['reviewed_findings'] = reviewed_findings
        open_findings = parse_vuln_findings(vuln_all, 'open')
        findings_map['open_findings'] = open_findings
        risk_accepted_findings = parse_vuln_findings(vuln_all, 'risk_accepted')
        findings_map['risk_accepted_findings'] = risk_accepted_findings
        closed_findings = parse_vuln_findings(vuln_all, 'closed')
        findings_map['closed_findings'] = closed_findings
        closed_manually = parse_vuln_findings(vuln_all, 'closed_manually')
        findings_map['closed_manually'] = closed_manually
        total_findings = parse_vuln_findings(vuln_all, 'total')
        findings_map['total_findings'] = total_findings
        secreview_findings = parse_vuln_findings(vuln_all, 'secreview_findings')
        findings_map['secreview_findings'] = secreview_findings
        false_positive_findings = parse_vuln_findings(vuln_all, 'false_positive')
        findings_map['false_positive_findings'] = false_positive_findings
        details_map = {}
        details_map = get_week_metadata(details_map, vuln_all)
        details_map = get_finding_age(details_map, vuln_all)
        details_map = get_finding_by_dow(details_map, vuln_all)
        details_map = get_finding_by_test_type(details_map, vuln_all)
        details_map = get_finding_by_cwe_type(details_map, vuln_all)
        metrics = get_kpi(vuln_all)
        return render_template('vulns/application_metrics.html',  entities=assets, app_data=app_data, user=user, NAV=NAV,
                               findings_map=findings_map, details_map=details_map, metrics=metrics)
    except RuntimeError:
        return render_template('500.html'), 500


def get_kpi(vuln_data):
    total_time = 0
    total_eligible = 0
    total_finding_false_positive = 0
    total_findings = len(vuln_data)
    total_finding_false_negative = 0
    for vuln in vuln_data:
        if vuln.MitigationDate:
            remediation_time = (vuln.MitigationDate - vuln.AddDate).days
            total_time += remediation_time
            total_eligible += 1
        if vuln.Status == 'Closed-Manual-False Positive':
            total_finding_false_positive += 1
        if vuln.Source.startswith("Manual-"):
            total_finding_false_negative += 1
    if total_eligible:
        mttr = f"{total_time / total_eligible:.2f}"
    else:
        mttr = "N/A"
    if total_finding_false_positive:
        false_positive_rate = total_finding_false_positive / total_findings
    else:
        false_positive_rate = 0
    finding_accuracy = 100 - false_positive_rate
    if total_finding_false_negative:
        false_negative_rate = total_finding_false_negative / (total_findings + total_finding_false_negative)
    else:
        false_negative_rate = 0
    metrics = {
        'mttr': mttr,
        'false_positive_rate': f"{false_positive_rate:.2f}",
        'false_negative_rate': f"{false_negative_rate:.2f}",
        'finding_accuracy': f"{finding_accuracy:.2f}"
    }
    return metrics


@vulns.route("/application_KPIs/<app_name>", methods=['GET', 'POST'])
@login_required
def application_KPIs(app_name):
    try:
        NAV['curpage'] = {"name": "KPIs"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        key = 'BusinessApplications.ApplicationName'
        start_date = None
        end_date = None
        filter_conditions = [f"{key} = :app_name"]
        query_params = {'app_name': app_name}
        if request.method == 'POST':
            start_date = request.form.get('start_date').replace('T', ' ')
            end_date = request.form.get('end_date').replace('T', ' ')
            filter_conditions.append(
                "((AddDate BETWEEN :start_date AND :end_date) OR "
                "(MitigationDate BETWEEN :start_date AND :end_date) OR "
                "((LastModifiedDate BETWEEN :start_date AND :end_date) AND "
                "(Status LIKE 'Open-RiskAccepted-%' OR "
                "Status = 'Closed-Manual-Superseded or Deprecated Component' OR "
                "Status = 'Closed-Manual-Compensating Control')))"
            )
            query_params.update({'start_date': start_date, 'end_date': end_date})

        filter_query = " AND ".join(filter_conditions)
        vuln_all = Vulnerabilities.query\
            .join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId)\
            .filter(text(filter_query).params(**query_params)).all()
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all)
        NAV['appbar'] = 'metrics'
        app = BusinessApplications.query.filter(text('ApplicationName = :app_name')).params(app_name=app_name).first()
        app_data = {'ID': app.ID, 'ApplicationName': app.ApplicationName}

        kpi_tree = get_kpi_tree(app.ApplicationName, scope='Application', start_date=start_date, end_date=end_date)
        vuln_by_category = {}
        vuln_metrics = {
            'Secret': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                       'metrics': {}},
            'SCA': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                    'metrics': {}},
            'SAST': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                     'metrics': {}},
            'IaC': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                    'metrics': {}},
            'Container': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                          'metrics': {}},
            'Infrastructure': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0,
                               'riskaccepted_findings': 0, 'metrics': {}},
            'DAST': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                     'metrics': {}},
            'DASTAPI': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                        'metrics': {}}
        }
        for vuln in vuln_all:
            vuln_category = vuln.Classification
            if vuln_category not in vuln_by_category:
                vuln_by_category[vuln_category] = [vuln]
            else:
                vuln_by_category[vuln_category].append(vuln)
            vuln_metrics[vuln_category]['total_findings'] += 1
            vuln_status = vuln.Status
            if vuln_status.startswith('Open-') and not vuln_status.startswith('Open-RiskAccepted-'):
                vuln_metrics[vuln_category]['open_findings'] += 1
            if vuln_status == 'Closed-Manual-Mitigated' or vuln_status == 'Closed-Mitigated':
                vuln_metrics[vuln_category]['mitigated_findings'] += 1
            if vuln_status.startswith('Open-RiskAccepted-') or vuln_status == 'Closed-Manual-Superseded or Deprecated Component' or vuln_status == 'Closed-Manual-Compensating Control':
                vuln_metrics[vuln_category]['riskaccepted_findings'] += 1

        for cat in vuln_by_category:
            metrics = get_kpi(vuln_by_category[cat])
            vuln_metrics[cat]['metrics'] = metrics
        return render_template('vulns/application_KPIs.html',  entities=assets, app_data=app_data, user=user, NAV=NAV, metrics=kpi_tree,
                               vuln_metrics=vuln_metrics)
    except RuntimeError:
        return render_template('500.html'), 500


def get_kpi_tree(entity_id, scope='Component', start_date=None, end_date=None):
    stages_all = []
    time_filter = ' AND CICDPipelineBuilds.StartTime BETWEEN :start_date AND :end_date'
    if scope == 'Component':
        filter_str = 'CICDPipelines.ApplicationID = :entity_id'
        if start_date:
            filter_str = filter_str + time_filter
        stages_all = CICDPipelineStageData.query \
            .with_entities(
                CICDPipelineStageData.ID, CICDPipelineStageData.AddDate, CICDPipelineStageData.BuildNode,
                CICDPipelineStageData.DurationMillis.label("StageDuration"), CICDPipelineStageData.StageName, CICDPipelineStageData.StartTime,
                CICDPipelineStageData.Status.label("StageStatus"), CICDPipelineBuilds.Status.label("BuildStatus"),
                CICDPipelineBuilds.DurationMillis.label("BuildDuration"), CICDPipelineBuilds.ID.label("BuildID")
            )\
            .join(CICDPipelineBuilds, CICDPipelineBuilds.ID == CICDPipelineStageData.BuildID) \
            .join(CICDPipelines, CICDPipelines.ID == CICDPipelineBuilds.PipelineID)\
            .filter(text(filter_str)).params(entity_id=entity_id, start_date=start_date, end_date=end_date).all()
    elif scope == 'Application':
        filter_str = 'BusinessApplications.ApplicationName = :entity_id'
        if start_date:
            filter_str = filter_str + time_filter
        stages_all = CICDPipelineStageData.query \
            .with_entities(
            CICDPipelineStageData.ID, CICDPipelineStageData.AddDate, CICDPipelineStageData.BuildNode,
            CICDPipelineStageData.DurationMillis.label("StageDuration"), CICDPipelineStageData.StageName,
            CICDPipelineStageData.StartTime,
            CICDPipelineStageData.Status.label("StageStatus"), CICDPipelineBuilds.Status.label("BuildStatus"),
            CICDPipelineBuilds.DurationMillis.label("BuildDuration"), CICDPipelineBuilds.ID.label("BuildID")
        ) \
            .join(CICDPipelineBuilds, CICDPipelineBuilds.ID == CICDPipelineStageData.BuildID) \
            .join(CICDPipelines, CICDPipelines.ID == CICDPipelineBuilds.PipelineID) \
            .join(BusinessApplications, BusinessApplications.ID == CICDPipelines.ApplicationID) \
            .filter(text(filter_str)).params(entity_id=entity_id, start_date=start_date, end_date=end_date).all()
    elif scope == 'Global':
        if start_date:
            filter_str = 'CICDPipelineBuilds.StartTime BETWEEN :start_date AND :end_date'
            stages_all = CICDPipelineStageData.query \
                .with_entities(
                CICDPipelineStageData.ID, CICDPipelineStageData.AddDate, CICDPipelineStageData.BuildNode,
                CICDPipelineStageData.DurationMillis.label("StageDuration"), CICDPipelineStageData.StageName,
                CICDPipelineStageData.StartTime,
                CICDPipelineStageData.Status.label("StageStatus"), CICDPipelineBuilds.Status.label("BuildStatus"),
                CICDPipelineBuilds.DurationMillis.label("BuildDuration"), CICDPipelineBuilds.ID.label("BuildID")
            ) \
                .join(CICDPipelineBuilds, CICDPipelineBuilds.ID == CICDPipelineStageData.BuildID) \
                .join(CICDPipelines, CICDPipelines.ID == CICDPipelineBuilds.PipelineID) \
                .filter(text(filter_str)).params(start_date=start_date, end_date=end_date).all()
        else:
            stages_all = CICDPipelineStageData.query \
                .with_entities(
                CICDPipelineStageData.ID, CICDPipelineStageData.AddDate, CICDPipelineStageData.BuildNode,
                CICDPipelineStageData.DurationMillis.label("StageDuration"), CICDPipelineStageData.StageName,
                CICDPipelineStageData.StartTime,
                CICDPipelineStageData.Status.label("StageStatus"), CICDPipelineBuilds.Status.label("BuildStatus"),
                CICDPipelineBuilds.DurationMillis.label("BuildDuration"), CICDPipelineBuilds.ID.label("BuildID")
            ) \
                .join(CICDPipelineBuilds, CICDPipelineBuilds.ID == CICDPipelineStageData.BuildID) \
                .join(CICDPipelines, CICDPipelines.ID == CICDPipelineBuilds.PipelineID) \
                .all()
    # Ave time to complete scanning
    # Maximum time to complete scanning
    # Percentage of pipeline failures due to scanning
    # Build time impact due to scanning
    stage_data = {
        'secret': {
            'stage_name': 'Secret Scanning',
            'total_build_time': 0,
            'highest_build_time': 0,
            'ave_scan_time': 0,
            'total_responsible_failures': 0,
            'percent_of_all_pipeline_failures': 0,
            'total_build_time_percent': 0,
            'stages': [],
        },
        'sca': {
            'stage_name': 'Software Composition Analysis',
            'total_build_time': 0,
            'highest_build_time': 0,
            'ave_scan_time': 0,
            'total_responsible_failures': 0,
            'percent_of_all_pipeline_failures': 0,
            'total_build_time_percent': 0,
            'stages': [],
        },
        'sast': {
            'stage_name': 'Static Application Security Testing',
            'total_build_time': 0,
            'highest_build_time': 0,
            'ave_scan_time': 0,
            'total_responsible_failures': 0,
            'percent_of_all_pipeline_failures': 0,
            'total_build_time_percent': 0,
            'stages': [],
        },
        'iac': {
            'stage_name': 'Infrastructure-as-Code Security Testing',
            'total_build_time': 0,
            'highest_build_time': 0,
            'ave_scan_time': 0,
            'total_responsible_failures': 0,
            'percent_of_all_pipeline_failures': 0,
            'total_build_time_percent': 0,
            'stages': [],
        },
        'docker': {
            'stage_name': 'Docker Container Scanning',
            'total_build_time': 0,
            'highest_build_time': 0,
            'ave_scan_time': 0,
            'total_responsible_failures': 0,
            'percent_of_all_pipeline_failures': 0,
            'total_build_time_percent': 0,
            'stages': [],
        },
        'infrastructure': {
            'stage_name': 'Infrastructure Security Scanning',
            'total_build_time': 0,
            'highest_build_time': 0,
            'ave_scan_time': 0,
            'total_responsible_failures': 0,
            'percent_of_all_pipeline_failures': 0,
            'total_build_time_percent': 0,
            'stages': [],
        },
        'dast': {
            'stage_name': 'Test Release',
            'total_build_time': 0,
            'highest_build_time': 0,
            'ave_scan_time': 0,
            'total_responsible_failures': 0,
            'percent_of_all_pipeline_failures': 0,
            'total_build_time_percent': 0,
            'stages': [],
        }
    }
    prev_stage_status = ''
    unique_builds = []
    for stage in stages_all:
        build_id = stage[9]
        if build_id not in unique_builds:
            unique_builds.append(build_id)
        for key in stage_data:
            if stage_data[key]['stage_name'] == stage[4]:
                cur_status = stage[6]
                if cur_status == 'FAILED' and prev_stage_status == 'SUCCESS':
                    stage_data[key]['total_responsible_failures'] += 1
                stage_data[key]['stages'].append(stage)
        prev_stage_status = stage[6]

    for cat in stage_data:
        total_build_time = 0
        total_stage_time = 0
        highest_build_time = 0
        for stage in stage_data[cat]['stages']:
            new_stage_time = stage[3]
            new_build_time = stage[8]
            if new_stage_time > highest_build_time:
                highest_build_time = new_stage_time
            total_build_time += new_build_time
            total_stage_time += new_stage_time
        percent_of_all_pipeline_failures = (stage_data[cat]['total_responsible_failures'] / len(unique_builds)) * 100 if unique_builds else 0
        total_build_time_percent = (total_stage_time / total_build_time if (total_build_time != 0 and total_stage_time != 0) else 0)  * 100
        stage_data[cat]['highest_build_time'] = convert_milliseconds(highest_build_time)
        stage_data[cat]['ave_scan_time'] = convert_milliseconds(total_stage_time / len(stage_data[cat]['stages']) if (stage_data[cat]['stages'] != 0 and total_stage_time) else 0)
        stage_data[cat]['percent_of_all_pipeline_failures'] = f"{percent_of_all_pipeline_failures:.2f}"
        stage_data[cat]['total_build_time_percent'] = f"{total_build_time_percent:.2f}"
        stage_data[cat]['total_build_time'] = total_build_time
    return stage_data


def convert_milliseconds(ms):
    # Convert milliseconds to seconds
    seconds = ms / 1000

    # Convert seconds to minutes and remaining seconds
    minutes = seconds // 60
    seconds = seconds % 60

    return int(minutes), f"{seconds:.2f}"


@vulns.route("/component_KPIs/<app_id>", methods=['GET', 'POST'])
@login_required
def component_KPIs(app_id):
    try:
        NAV['curpage'] = {"name": "KPIs"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)
        key = 'BusinessApplications.ID'
        start_date = None
        end_date = None
        filter_conditions = [f"{key} = :app_id"]
        filter_params = {"app_id": app_id}
        if request.method == 'POST':
            start_date = request.form.get('start_date').replace('T', ' ')
            end_date = request.form.get('end_date').replace('T', ' ')
            filter_conditions.append("((AddDate BETWEEN :start_date AND :end_date) OR "
                                      "(MitigationDate BETWEEN :start_date AND :end_date) OR "
                                      "((LastModifiedDate BETWEEN :start_date AND :end_date) AND "
                                      "(Status LIKE 'Open-RiskAccepted-*' OR "
                                      "Status = 'Closed-Manual-Superseded or Deprecated Component' OR "
                                      "Status = 'Closed-Manual-Compensating Control')))")
            filter_params.update({"start_date": start_date, "end_date": end_date})
        filter_list = " AND ".join(filter_conditions)
        vuln_all = Vulnerabilities.query\
            .join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId)\
            .filter(text(filter_list).params(**filter_params)).all()
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all)
        NAV['appbar'] = 'metrics'
        app = BusinessApplications.query.filter(text('ID = :app_id').params(app_id=app_id)).first()
        app_data = {'ID': app_id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}

        kpi_tree = get_kpi_tree(app.ID, start_date=start_date, end_date=end_date)
        vuln_by_category = {}
        vuln_metrics = {
            'Secret': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                       'metrics': {}},
            'SCA': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                    'metrics': {}},
            'SAST': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                     'metrics': {}},
            'IaC': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                    'metrics': {}},
            'Container': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                          'metrics': {}},
            'Infrastructure': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0,
                               'riskaccepted_findings': 0, 'metrics': {}},
            'DAST': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                     'metrics': {}},
            'DASTAPI': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                        'metrics': {}}
        }
        for vuln in vuln_all:
            vuln_category = vuln.Classification
            if vuln_category not in vuln_by_category:
                vuln_by_category[vuln_category] = [vuln]
            else:
                vuln_by_category[vuln_category].append(vuln)
            vuln_metrics[vuln_category]['total_findings'] += 1
            vuln_status = vuln.Status
            if vuln_status.startswith('Open-') and not vuln_status.startswith('Open-RiskAccepted-'):
                vuln_metrics[vuln_category]['open_findings'] += 1
            if vuln_status == 'Closed-Manual-Mitigated' or vuln_status == 'Closed-Mitigated':
                vuln_metrics[vuln_category]['mitigated_findings'] += 1
            if vuln_status.startswith('Open-RiskAccepted-') or vuln_status == 'Closed-Manual-Superseded or Deprecated Component' or vuln_status == 'Closed-Manual-Compensating Control':
                vuln_metrics[vuln_category]['riskaccepted_findings'] += 1

        for cat in vuln_by_category:
            metrics = get_kpi(vuln_by_category[cat])
            vuln_metrics[cat]['metrics'] = metrics
        return render_template('vulns/component_KPIs.html',  entities=assets, app_data=app_data, user=user, NAV=NAV, metrics=kpi_tree,
                               vuln_metrics=vuln_metrics)
    except RuntimeError:
        return render_template('500.html'), 500


@vulns.route("/global_KPIs", methods=['GET', 'POST'])
@login_required
def global_KPIs():
    try:
        NAV['curpage'] = {"name": "KPIs"}
        admin_role = 'Application Admin'
        role_req = ['Application Admin', 'Application Viewer']
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        start_date = None
        end_date = None
        if request.method == 'POST':
            start_date = request.form.get('start_date').replace('T', ' ')
            end_date = request.form.get('end_date').replace('T', ' ')
            filter_list = text('((AddDate BETWEEN :start_date AND :end_date) OR '
                               '(MitigationDate BETWEEN :start_date AND :end_date) OR '
                               '((LastModifiedDate BETWEEN :start_date AND :end_date) AND (Status LIKE "Open-RiskAccepted-*" OR Status="Closed-Manual-Superseded or Deprecated Component" OR Status="Closed-Manual-Compensating Control")))')
            vuln_all = Vulnerabilities.query\
                .join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId)\
                .filter(filter_list.params(start_date=start_date, end_date=end_date)).all()
        else:
            vuln_all = Vulnerabilities.query \
                .join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
                .all()
        schema = VulnerabilitiesSchema(many=True)
        assets = schema.dump(vuln_all)

        kpi_tree = get_kpi_tree('All', scope='Global', start_date=start_date, end_date=end_date)
        vuln_by_category = {}
        vuln_metrics = {
            'Secret': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                       'metrics': {}},
            'SCA': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                    'metrics': {}},
            'SAST': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                     'metrics': {}},
            'IaC': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                    'metrics': {}},
            'Container': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                          'metrics': {}},
            'Infrastructure': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0,
                               'riskaccepted_findings': 0, 'metrics': {}},
            'DAST': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                     'metrics': {}},
            'DASTAPI': {'total_findings': 0, 'open_findings': 0, 'mitigated_findings': 0, 'riskaccepted_findings': 0,
                        'metrics': {}}
        }
        for vuln in vuln_all:
            vuln_category = vuln.Classification
            if vuln_category not in vuln_by_category:
                vuln_by_category[vuln_category] = [vuln]
            else:
                vuln_by_category[vuln_category].append(vuln)
            vuln_metrics[vuln_category]['total_findings'] += 1
            vuln_status = vuln.Status
            if vuln_status.startswith('Open-') and not vuln_status.startswith('Open-RiskAccepted-'):
                vuln_metrics[vuln_category]['open_findings'] += 1
            if vuln_status == 'Closed-Manual-Mitigated' or vuln_status == 'Closed-Mitigated':
                vuln_metrics[vuln_category]['mitigated_findings'] += 1
            if vuln_status.startswith('Open-RiskAccepted-') or vuln_status == 'Closed-Manual-Superseded or Deprecated Component' or vuln_status == 'Closed-Manual-Compensating Control':
                vuln_metrics[vuln_category]['riskaccepted_findings'] += 1

        for cat in vuln_by_category:
            metrics = get_kpi(vuln_by_category[cat])
            vuln_metrics[cat]['metrics'] = metrics
        return render_template('vulns/global_KPIs.html',  entities=assets, user=user, NAV=NAV, metrics=kpi_tree,
                               vuln_metrics=vuln_metrics)
    except RuntimeError:
        return render_template('500.html'), 500

