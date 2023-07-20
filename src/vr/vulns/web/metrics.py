import datetime
from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from sqlalchemy import text
from flask import render_template, session, redirect, url_for
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema


NAV = {
    'CAT': { "name": "Vulnerabilities", "url": "sourcecode.dashboard"}
}

@vulns.route("/metrics/<id>")
@login_required
def application_metrics(id):
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
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName}
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
        return render_template('application_metrics.html',  entities=assets, app_data=app_data, user=user, NAV=NAV,
                               findings_map=findings_map, details_map=details_map)
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
    for i in all_vulns:
        all_weeks = _get_vulns_per_week(i, all_weeks)
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
        if dispo == 'Open-Reviewed':
            dispo = 'reviewed'
        elif dispo == 'Open-RiskAccepted':
            dispo = 'risk_accepted'
        elif dispo.startswith('Closed-'):
            dispo = 'closed'
        elif dispo == 'Closed-Manual':
            dispo = 'closed_manually'
        elif dispo == 'Open-SecReview':
            dispo = 'secreview_findings'
        elif dispo == 'Closed-FP':
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
        key = 'ApplicationId'
        val = id
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
        return render_template('all_application_metrics.html',  entities=assets, user=user, NAV=NAV,
                               findings_map=findings_map, details_map=details_map)
    except RuntimeError:
        return render_template('500.html'), 500


