import datetime
from vr import db, app
from flask import jsonify, request
from sqlalchemy import desc, text
from vr.api import api
from vr.admin.functions import db_connection_handler
from vr.admin.oauth2 import require_oauth
from authlib.integrations.flask_oauth2 import current_token
from vr.admin.auth_functions import verify_api_key, get_token_auth_header
from vr.functions.routing_functions import check_entity_permissions
from vr.assets.model.applicationprofiles import ApplicationProfiles, ApplicationProfilesSchema
from vr.assets.model.businessapplications import BusinessApplications
from vr.vulns.model.vulnerabilities import Vulnerabilities, MakeVulnerabilitiesSchema, VulnerabilitiesSchema
from vr.vulns.model.vulnerabilityscans import VulnerabilityScans
from vr.assessments.model.assessmentbenchmarkassessments import AssessmentBenchmarkAssessments
from vr.assessments.model.assessmentbenchmarkrules import AssessmentBenchmarkRules
from vr.assessments.model.assessmentbenchmarkruleaudits import AssessmentBenchmarkRuleAudits


ERROR_RESP = "Error: Invalid API Request"

@api.route("/api/get_dora_grade/<app_id>", methods=['POST', 'GET'])
@require_oauth('read:vulnerabilities')
def get_dora_grade(app_id):
    token = current_token
    auth, user_id, is_admin = verify_api_key(token)
    response = jsonify({'response': ERROR_RESP}), 403
    if auth == 'valid':
        permitted = check_entity_permissions(is_admin)
        if permitted:
            if request.method == 'POST':
                form = request.get_json()
                time_start = datetime.datetime.strptime(form['timeStart'], '%Y-%m-%d %H:%M:%S')
                time_end = datetime.datetime.strptime(form['timeEnd'], '%Y-%m-%d %H:%M:%S')
            else:
                time_start = datetime.datetime.strptime('1990-01-01 12:00:00', '%Y-%m-%d %H:%M:%S')
                time_end = datetime.datetime.utcnow()
            time_dict = {'timeStart': time_start, 'timeEnd':time_end}
            total_score = 0
            applicable_metrics = 0
            if verify_app_id(app_id):
                # calculate vulnerability resolution time
                vr_score, total_score, applicable_metrics = calculate_vulnerability_resolution_time(time_dict, app_id, total_score, applicable_metrics)
                # calculate frequency of security scans
                scan_score, total_score, applicable_metrics = calculate_frequency_of_security_scans(time_dict, app_id, total_score, applicable_metrics)
                # calculate mean time to detect (MTTD) security issues
                all_vulns, detection_score, total_score, applicable_metrics = calculate_mean_time_to_detect(time_dict, app_id, total_score, applicable_metrics)
                # calculate percentage of critical/high risk issues addressed
                high_severity_score, total_score, applicable_metrics = calculate_percentage_of_high_risk_issues_addressed(all_vulns, total_score, applicable_metrics)
                # calculate compliance with security standards
                compliance_score, total_score, applicable_metrics = calculate_compliance_with_security_standards(time_dict, app_id, total_score, applicable_metrics)
                # calculate risk profile adherence
                risk_score, total_score, applicable_metrics = calculate_risk_profile_adherence(app_id, total_score, applicable_metrics)

                # calculate grade and final score
                max_score, percent_score, grade = _calculate_grade(applicable_metrics, total_score)
                score = {
                    'grade': grade,
                    'total_score': total_score,
                    'percent_score': (percent_score * 100),
                    'max_score': max_score,
                    'vulnerability_remediation_score': vr_score,
                    'scan_frequency_score': scan_score,
                    'time_to_detect_issues_score': detection_score,
                    'critical_and_high_risk_mitigation_score': high_severity_score,
                    'compliance_with_security_standards_score': compliance_score,
                    'risk_profile_adherence_score': risk_score
                }
            else:
                score = {
                    'grade': "I",
                    'total_score': 0,
                    'percent_score': 0,
                    'max_score': 0,
                    'vulnerability_remediation_score': 0,
                    'scan_frequency_score': 0,
                    'time_to_detect_issues_score': 0,
                    'critical_and_high_risk_mitigation_score': 0,
                    'compliance_with_security_standards_score': 0,
                    'risk_profile_adherence_score': 0
                }


            response = jsonify(score), 200
    return response

def verify_app_id(app_id):
    if '--' in app_id:
        app_name = app_id.split('--')[0]
        app_component = app_id.split('--')[1]
        valid = BusinessApplications.query.filter(BusinessApplications.ApplicationName == app_name).filter(BusinessApplications.ApplicationAcronym == app_component).first()
    else:
        valid = BusinessApplications.query.filter(BusinessApplications.ApplicationName == app_id).first()
    return valid

def calculate_vulnerability_resolution_time(time_dict, app_id, total_score, applicable_metrics):
    if '--' in app_id:
        app_name = app_id.split('--')[0]
        app_component = app_id.split('--')[1]
        resolved_vulns = Vulnerabilities.query \
            .join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
            .filter(BusinessApplications.ApplicationName == app_name) \
            .filter(BusinessApplications.ApplicationAcronym == app_component) \
            .filter(Vulnerabilities.Status == 'Closed-Mitigated') \
            .filter(Vulnerabilities.MitigationDate >= time_dict['timeStart']) \
            .filter(Vulnerabilities.MitigationDate <= time_dict['timeEnd']) \
            .all()
    else:
        resolved_vulns = Vulnerabilities.query \
            .join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
            .filter(BusinessApplications.ApplicationName == app_id) \
            .filter(Vulnerabilities.Status == 'Closed-Mitigated') \
            .filter(Vulnerabilities.MitigationDate >= time_dict['timeStart']) \
            .filter(Vulnerabilities.MitigationDate <= time_dict['timeEnd']) \
            .all()
    total_time = 0
    for i in resolved_vulns:
        add_date = i.AddDate
        resolve_date = i.MitigationDate
        total = resolve_date - add_date
        total_time += total.seconds / 60 / 60
    ave_resolved_hours = total_time / len(resolved_vulns)
    vr_score = _calculate_dora_metric_score('resolved_vulns', ave_resolved_hours)
    total_score += vr_score
    applicable_metrics += 1
    return vr_score, total_score, applicable_metrics


def calculate_frequency_of_security_scans(time_dict, app_id, total_score, applicable_metrics):
    if '--' in app_id:
        app_name = app_id.split('--')[0]
        app_component = app_id.split('--')[1]
        all_scans = VulnerabilityScans.query \
            .join(BusinessApplications, BusinessApplications.ID == VulnerabilityScans.ApplicationId) \
            .filter(BusinessApplications.ApplicationName == app_name) \
            .filter(BusinessApplications.ApplicationAcronym == app_component) \
            .filter(VulnerabilityScans.ScanStartDate >= time_dict['timeStart']) \
            .filter(VulnerabilityScans.ScanStartDate <= time_dict['timeEnd']) \
            .all()
    else:
        all_scans = VulnerabilityScans.query \
            .join(BusinessApplications, BusinessApplications.ID == VulnerabilityScans.ApplicationId) \
            .filter(BusinessApplications.ApplicationName == app_id) \
            .filter(VulnerabilityScans.ScanStartDate >= time_dict['timeStart']) \
            .filter(VulnerabilityScans.ScanStartDate <= time_dict['timeEnd']) \
            .all()
    if '--' in app_id:
        app_name = app_id.split('--')[0]
        app_component = app_id.split('--')[1]
        reg_date = BusinessApplications\
            .query\
            .with_entities(BusinessApplications.RegDate)\
            .filter(BusinessApplications.ApplicationName == app_name) \
            .filter(BusinessApplications.ApplicationAcronym == app_component) \
            .first()[0]
    else:
        reg_date = BusinessApplications.query.with_entities(BusinessApplications.RegDate).filter(
            BusinessApplications.ApplicationName == app_id).first()[0]
    now = datetime.datetime.utcnow()
    total_duration = (now - reg_date).days
    unique_scan_dates = set()
    for scan in all_scans:
        unique_scan_dates.add(scan.ScanStartDate.date())
    unique_scan_count = len(unique_scan_dates)
    if total_duration > 0:
        frequency_of_scans = unique_scan_count / total_duration
    else:
        frequency_of_scans = 0
    scan_score = _calculate_dora_metric_score('scan_frequency', frequency_of_scans)
    total_score += scan_score
    applicable_metrics += 1
    return scan_score, total_score, applicable_metrics


def calculate_mean_time_to_detect(time_dict, app_id, total_score, applicable_metrics):
    if '--' in app_id:
        app_name = app_id.split('--')[0]
        app_component = app_id.split('--')[1]
        all_vulns = Vulnerabilities.query \
            .join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
            .filter(BusinessApplications.ApplicationName == app_name) \
            .filter(BusinessApplications.ApplicationAcronym == app_component) \
            .filter(Vulnerabilities.AddDate >= time_dict['timeStart']) \
            .filter(Vulnerabilities.AddDate <= time_dict['timeEnd']) \
            .all()
    else:
        all_vulns = Vulnerabilities.query \
            .join(BusinessApplications, BusinessApplications.ID == Vulnerabilities.ApplicationId) \
            .filter(BusinessApplications.ApplicationName == app_id) \
            .filter(Vulnerabilities.AddDate >= time_dict['timeStart']) \
            .filter(Vulnerabilities.AddDate <= time_dict['timeEnd']) \
            .all()
    total_duration = 0
    for i in all_vulns:
        detection_date = i.ReleaseDate
        identification_date = i.AddDate
        detection_time = detection_date - identification_date
        total_duration += detection_time.seconds
    if total_duration > 0:
        detection_time_ave = total_duration / len(all_vulns)
    else:
        detection_time_ave = 0
    detection_score = _calculate_dora_metric_score('detection_time', detection_time_ave)
    total_score += detection_score
    applicable_metrics += 1
    return all_vulns, detection_score, total_score, applicable_metrics


def calculate_percentage_of_high_risk_issues_addressed(all_vulns, total_score, applicable_metrics):
    total_issues = 0
    addressed_issues = 0
    for i in all_vulns:
        if i.Severity == 'Critical' or i.Severity == 'High':
            total_issues += 1
            if i.Status == 'Closed-Mitigated':
                addressed_issues += 1
    if addressed_issues:
        percent_addressed = (addressed_issues / total_issues) * 100
    else:
        percent_addressed = 0
    high_severity_score = _calculate_dora_metric_score('high_severity', percent_addressed)
    total_score += high_severity_score
    applicable_metrics += 1
    return high_severity_score, total_score, applicable_metrics


def calculate_compliance_with_security_standards(time_dict, app_id, total_score, applicable_metrics):
    if '--' in app_id:
        app_name = app_id.split('--')[0]
        app_component = app_id.split('--')[1]
        latest_assessments = AssessmentBenchmarkAssessments.query \
            .join(BusinessApplications, BusinessApplications.ID == AssessmentBenchmarkAssessments.ApplicationID) \
            .filter(BusinessApplications.ApplicationName == app_name) \
            .filter(BusinessApplications.ApplicationAcronym == app_component) \
            .order_by(AssessmentBenchmarkAssessments.BenchmarkID,
                      desc(AssessmentBenchmarkAssessments.AddDate)) \
            .distinct(AssessmentBenchmarkAssessments.BenchmarkID) \
            .filter(AssessmentBenchmarkAssessments.AddDate >= time_dict['timeStart']) \
            .filter(AssessmentBenchmarkAssessments.AddDate <= time_dict['timeEnd']) \
            .all()
    else:
        latest_assessments = AssessmentBenchmarkAssessments.query \
            .join(BusinessApplications, BusinessApplications.ID == AssessmentBenchmarkAssessments.ApplicationID) \
            .filter(BusinessApplications.ApplicationName == app_id) \
            .order_by(AssessmentBenchmarkAssessments.BenchmarkID,
                      desc(AssessmentBenchmarkAssessments.AddDate)) \
            .distinct(AssessmentBenchmarkAssessments.BenchmarkID) \
            .filter(AssessmentBenchmarkAssessments.AddDate >= time_dict['timeStart']) \
            .filter(AssessmentBenchmarkAssessments.AddDate <= time_dict['timeEnd']) \
            .all()
    all_rules = 0
    all_passed = 0
    for i in latest_assessments:
        assessment_rules = AssessmentBenchmarkRules \
            .query \
            .filter(AssessmentBenchmarkRules.BenchmarkID == i.BenchmarkID) \
            .filter(text('AssessmentBenchmarkRules.ImplementationLevels LIKE "%1%"')) \
            .all()
        assessment_rules_passed = AssessmentBenchmarkRuleAudits \
            .query \
            .filter(AssessmentBenchmarkRuleAudits.AssessmentID == i.ID) \
            .filter(text('AssessmentBenchmarkRuleAudits.PassingLevels LIKE "%1%"')) \
            .all()
        all_rules += len(assessment_rules)
        all_passed += len(assessment_rules_passed)
    if all_passed > 0:
        benchmark_pass_percent = all_passed / all_rules
    else:
        benchmark_pass_percent = 0
    compliance_score = _calculate_dora_metric_score('compliance', benchmark_pass_percent)
    total_score += compliance_score
    applicable_metrics += 1
    return compliance_score, total_score, applicable_metrics


def calculate_risk_profile_adherence(app_id, total_score, applicable_metrics):
    if '--' in app_id:
        app_name = app_id.split('--')[0]
        app_component = app_id.split('--')[1]
        score_query = BusinessApplications \
            .query \
            .with_entities(BusinessApplications.Criticality) \
            .filter(BusinessApplications.ApplicationName == app_name) \
            .filter(BusinessApplications.ApplicationAcronym == app_component) \
            .filter(text('BusinessApplications.Criticality LIKE "%(%"')) \
            .first()
    else:
        score_query = BusinessApplications \
            .query \
            .with_entities(BusinessApplications.Criticality) \
            .filter(BusinessApplications.ApplicationName == app_id) \
            .filter(text('BusinessApplications.Criticality LIKE "%(%"')) \
            .first()
    if score_query is not None:
        score = score_query.Criticality.split()[0]
    else:
        score = 0
    risk_score = _calculate_dora_metric_score('risk', score)
    total_score += risk_score
    applicable_metrics += 1
    return risk_score, total_score, applicable_metrics


def _calculate_grade(applicable_metrics, total_score):
    max_score = applicable_metrics * 5
    percent_score = total_score / max_score
    if percent_score >= 0.97:
        grade = 'A+'
    elif percent_score >= 0.93 and percent_score < 0.97:
        grade = 'A'
    elif percent_score >= 0.90 and percent_score < 0.93:
        grade = 'A-'
    elif percent_score >= 0.87 and percent_score < 0.90:
        grade = 'B+'
    elif percent_score >= 0.83 and percent_score < 0.87:
        grade = 'B'
    elif percent_score >= 0.80 and percent_score < 0.83:
        grade = 'B-'
    elif percent_score >= 0.77 and percent_score < 0.80:
        grade = 'C+'
    elif percent_score >= 0.73 and percent_score < 0.77:
        grade = 'C'
    elif percent_score >= 0.70 and percent_score < 0.73:
        grade = 'C-'
    elif percent_score >= 0.67 and percent_score < 0.70:
        grade = 'D+'
    elif percent_score >= 0.63 and percent_score < 0.67:
        grade = 'D'
    elif percent_score >= 0.60 and percent_score < 0.63:
        grade = 'D-'
    else:
        grade = 'F'
    return max_score, percent_score, grade

def _calculate_dora_metric_score(metric_type, metric_data):
    if metric_type == 'resolved_vulns':
        if metric_data < 24:
            points = 5
        elif metric_data >= 24 and metric_data < 72:
            points = 4
        elif metric_data >= 72 and metric_data < 168:
            points = 3
        elif metric_data:
            points = 1
        else:
            points = 0
    elif metric_type == 'scan_frequency':
        if metric_data == 1:  # means the scans occurred daily
            points = 5
        elif metric_data > 0.1428571428571429:  # means scans occurred at least weekly
            points = 4
        elif metric_data > 0.07142857142857143:  # means scans occurred at least monthly
            points = 3
        elif metric_data:  # means scans occurred less than monthly
            points = 1
        else:  # means no scans have be conducted
            points = 0
    elif metric_type == 'detection_time':
        if metric_data < 3600:  # means less than 1 hour
            points = 5
        elif metric_data < 21600:  # means less than 6 hours
            points = 4
        elif metric_data < 86400:  # means less than 24 hours
            points = 3
        elif metric_data:  # means more than 24 hours
            points = 1
        else:  # means no scans have be conducted
            points = 0
    elif metric_type == 'high_severity':
        if metric_data > 95:
            points = 5
        elif metric_data >= 80 and metric_data <= 95:
            points = 4
        elif metric_data >= 60 and metric_data < 80:
            points = 3
        elif metric_data:
            points = 1
        else:  # means no scans have be conducted
            points = 0
    elif metric_type == 'compliance':
        if metric_data > 95:
            points = 5
        elif metric_data >= 80 and metric_data <= 95:
            points = 4
        elif metric_data >= 60 and metric_data < 80:
            points = 3
        elif metric_data:
            points = 1
        else:  # means no scans have be conducted
            points = 0
    elif metric_type == 'risk':
        if metric_data == 'low':
            points = 5
        elif metric_data == 'medium':
            points = 4
        elif metric_data == 'high':
            points = 3
        else:  # means no scans have be conducted
            points = 0
    return points

