import datetime

from vr import db
from vr.assessments import assessments
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, _add_page_permissions_filter
from vr.admin.functions import db_connection_handler
from sqlalchemy import text, desc, and_, func
from flask import render_template, session, redirect, url_for, request, jsonify
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.assessments.model.assessmentbenchmarks import AssessmentBenchmarks, AssessmentBenchmarksSchema
from vr.assessments.model.assessmentbenchmarkrules import AssessmentBenchmarkRules
from vr.assessments.model.assessmentbenchmarkruleaudits import AssessmentBenchmarkRuleAudits
from vr.assessments.model.assessmentbenchmarkruleauditnotes import AssessmentBenchmarkRuleAuditNotes
from vr.assessments.model.fileuploads import FileUploads
from vr.assessments.model.riskprofile import RiskProfile
from vr.assessments.model.assessmentbenchmarkassessments import AssessmentBenchmarkAssessments, AssessmentBenchmarkAssessmentsSchema
from vr.admin.models import User
from math import ceil
from vr.functions.table_functions import load_table, update_table
from werkzeug.utils import secure_filename
from flask import send_file
import os


NAV = {
    'CAT': { "name": "Applications", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"
APP_VIEWER = "Application Viewer"
ADMIN_LOGIN = "admin.login"
UNAUTH_STATUS = "403.html"
SERVER_ERR_STATUS = "500.html"
ISO_FORMAT = '%Y-%m-%d %H:%M:%S'


@assessments.route("/all_application_benchmarks/<id>", methods=['GET', 'POST'])
@login_required
def all_application_benchmarks(id):
    try:
        NAV['curpage'] = {"name": "Application Benchmarks"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)

        new_dict = {
            'db_name': 'AssessmentBenchmarks',
            "sort_field": "ID"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict)
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict)

        components = AssessmentBenchmarks.query \
            .with_entities(
            AssessmentBenchmarks.ID,
            AssessmentBenchmarks.Name,
            AssessmentBenchmarks.Description,
            AssessmentBenchmarks.Version
        ) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((components.total / per_page))
        schema = AssessmentBenchmarksSchema(many=True)
        assets = schema.dump(components.items)


        NAV['appbar'] = 'benchmarks'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": components.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < components.total else components.total
        }
        return render_template('assessments/all_application_benchmarks.html', app_data=app_data, entities=assets, user=user, NAV=NAV,
                               table_details= table_details)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@assessments.route("/benchmark_assessments/<id>", methods=['GET', 'POST'])
@login_required
def benchmark_assessments(id):
    try:
        NAV['curpage'] = {"name": "Benchmark Assessments"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        key = 'AssessmentBenchmarkAssessments.ApplicationID'
        val = id
        filter_list = [f"{key} = '{val}'"]

        new_dict = {
            'db_name': 'AssessmentBenchmarkAssessments',
            "sort_field": "ID"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict, direction="desc")
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict, direction="desc")

        components = AssessmentBenchmarkAssessments.query \
            .with_entities(
            AssessmentBenchmarks.Name,
            AssessmentBenchmarks.Version,
            AssessmentBenchmarkAssessments.ID,
            AssessmentBenchmarkAssessments.AddDate,
            AssessmentBenchmarkAssessments.Type,
            User.username,
            func.count(AssessmentBenchmarkRuleAudits.ID).label('findings_cnt')
        ) \
            .join(AssessmentBenchmarks, AssessmentBenchmarkAssessments.BenchmarkID == AssessmentBenchmarks.ID, isouter=True) \
            .join(User, AssessmentBenchmarkAssessments.UserID == User.id, isouter=True) \
            .join(AssessmentBenchmarkRuleAudits, and_(AssessmentBenchmarkRuleAudits.AssessmentID == AssessmentBenchmarkAssessments.ID, AssessmentBenchmarkRuleAudits.PassingLevels != ""), isouter=True) \
            .group_by(AssessmentBenchmarkAssessments.ID) \
            .filter(text("".join(filter_list))) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((components.total / per_page))
        schema = AssessmentBenchmarkAssessmentsSchema(many=True)
        assets = schema.dump(components.items)

        NAV['appbar'] = 'benchmarks'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": components.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < components.total else components.total
        }

        return render_template('assessments/benchmark_assessments.html', app_data=app_data, entities=assets, user=user,
                               NAV=NAV, table_details=table_details)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@assessments.route("/application_benchmarks/<app_id>/<id>", methods=['GET', 'POST'])
@login_required
def application_benchmarks(app_id, id):
    try:
        NAV['curpage'] = {"name": "New Assessment"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(app_id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        if request.method == 'POST':
            new_assessment, quick_note_str, update_map = _set_rule_list(app_id, user, id)
            db.session.add(new_assessment)
            db_connection_handler(db)
            _add_rule_eval(update_map, app_id, new_assessment)
            _add_quick_notes(quick_note_str, app_id, user)
            return "success", 200
        else:
            benchmark_dict, benchmark_id = _get_benchmark_details(app_id, id)
            for i in benchmark_dict:
                benchmark_dict = _parse_levels(benchmark_dict, i)
            default_benchmark = 'OWASP ASVS v. 3.1'
            NAV['appbar'] = 'benchmarks'
            app = BusinessApplications.query.filter(text(f'ID={app_id}')).first()
            app_data = {'ID': app_id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
            return render_template('assessments/application_benchmarks.html', benchmarks=benchmark_dict[benchmark_id],
                                   default_benchmark=default_benchmark,
                                   app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


def _parse_levels(benchmark_dict, i):
    audits = benchmark_dict[i]['audits']
    for j in audits:
        if '1' in j[4] and j.RuleID not in benchmark_dict[i]['L1_pass']:
            benchmark_dict[i]['L1_pass'].append(j.RuleID)
    return benchmark_dict


def _get_benchmark_details(app_id, id):
    benchmark_dict = {}
    benchmarks = AssessmentBenchmarks.query.filter(text(f"ID = '{id}'")).all()
    for i in benchmarks:
        benchmark_id = i.ID
        benchmark_dict[i.ID] = {"ID": i.ID, "Name": i.Name, "L1_pass": [], "L2_pass": [], "L3_pass": []}
        benchmark_dict[i.ID]['rules'] = AssessmentBenchmarkRules.query.filter(text(f"BenchmarkID = '{i.ID}'")).all()
        rules_notes = AssessmentBenchmarkRuleAuditNotes.query \
            .with_entities(AssessmentBenchmarkRuleAuditNotes.ID, AssessmentBenchmarkRuleAuditNotes.AddDate,
                           AssessmentBenchmarkRuleAuditNotes.ApplicationID, AssessmentBenchmarkRuleAuditNotes.Note,
                           AssessmentBenchmarkRuleAuditNotes.RuleID, AssessmentBenchmarkRuleAuditNotes.Type,
                           User.username) \
            .join(User, User.id == AssessmentBenchmarkRuleAuditNotes.UserID) \
            .filter(text(f"ApplicationID = '{app_id}'")).all()
        benchmark_dict[i.ID]['rules_notes'] = {}
        for n in rules_notes:
            match = False
            for r in benchmark_dict[i.ID]['rules']:
                if r.ID == n.RuleID:
                    match = True
            if match:
                benchmark_dict, n = _set_rule_match(benchmark_dict, n, i)
        # Rule attachments section
        rules_attachments = FileUploads.query \
            .with_entities(FileUploads.ID, FileUploads.FileName,
                           FileUploads.FileSize, FileUploads.FileType,
                           FileUploads.UploadDate, FileUploads.BenchmarkingID,
                           FileUploads.FilePath, FileUploads.Status, FileUploads.FileDescription,
                           FileUploads.ApplicationID,
                           User.username) \
            .join(User, User.id == FileUploads.UploadedByUserID) \
            .filter(text(f"ApplicationID = '{app_id}'")).all()
        benchmark_dict[i.ID]['rules_attachments'] = _get_rule_attachments(rules_attachments)
        #
        benchmark_dict[i.ID]['modal_rules'] = {}
        for r in benchmark_dict[i.ID]['rules']:
            benchmark_dict, r = _set_benchmark_rule(benchmark_dict, r, i)
        benchmark_dict[i.ID]['audits'] = AssessmentBenchmarkRuleAudits.query.with_entities(
            AssessmentBenchmarkRuleAudits.ID, AssessmentBenchmarkRuleAudits.AddDate,
            AssessmentBenchmarkRuleAudits.ApplicationID, AssessmentBenchmarkRuleAudits.RuleID,
            AssessmentBenchmarkRuleAudits.PassingLevels
        ) \
            .join(AssessmentBenchmarkRules, AssessmentBenchmarkRules.ID == AssessmentBenchmarkRuleAudits.RuleID) \
            .filter(text(f"AssessmentBenchmarkRules.BenchmarkID = '{i.ID}'")) \
            .filter(text(f"AssessmentBenchmarkRuleAudits.ApplicationID = '{app_id}'")) \
            .order_by(desc(AssessmentBenchmarkRuleAudits.AssessmentID)) \
            .all()
    return benchmark_dict, benchmark_id


def _get_rule_attachments(rule_attachment_list):
    attachment_dict = {}
    for i in rule_attachment_list:
        if not i[5] in attachment_dict:
            attachment_dict[i[5]] = []
        attachment_dict[i[5]].append({
            "ID": i[0],
            "FileName": i[1],
            "FileSize": i[2] if i[2] else 0,
            "FileType": i[3],
            "UploadDate": i[4].strftime("%Y-%m-%d %H:%M:%S"),
            "RuleID": i[5],
            "FilePath": i[6],
            "Status": i[7],
            "FileDescription": i[8],
            "ApplicationID": i[9],
            "username": i[10]
        })
    return attachment_dict


def _set_rule_match(benchmark_dict, n, i):
    if n.RuleID not in benchmark_dict[i.ID]['rules_notes']:
        benchmark_dict[i.ID]['rules_notes'][n.RuleID] = []
    benchmark_dict[i.ID]['rules_notes'][n.RuleID].append(
        {"ID": n.ID, "AddDate": n.AddDate.strftime(ISO_FORMAT), "ApplicationID": n.ApplicationID,
         "Note": n.Note, "RuleID": n.RuleID, "Type": n.Type,
         "username": n.username})
    return benchmark_dict, n


def _set_benchmark_rule(benchmark_dict, r, i):
    benchmark_dict[i.ID]['modal_rules'][r.ID] = {
        "AddDate": r.AddDate.strftime(ISO_FORMAT),
        "BenchmarkID": r.BenchmarkID,
        "Description": r.Description, "ID": r.ID,
        "ImplementationLevels": r.ImplementationLevels,
        "Number": r.Number,
        "Notes": benchmark_dict[i.ID]['rules_notes'][r.ID] if r.ID in benchmark_dict[i.ID]['rules_notes'] else [],
        "Files": benchmark_dict[i.ID]['rules_attachments'][r.ID] if r.ID in benchmark_dict[i.ID]['rules_attachments'] else []
    }
    return benchmark_dict, r


def _add_quick_notes(quick_note_str, app_id, user):
    quick_notes = quick_note_str.split(';;')
    for note in quick_notes:
        if note:
            rule_id = note.split(':')[0]
            note_val = note.split(':')[1]
            new_note = AssessmentBenchmarkRuleAuditNotes(
                ApplicationID=app_id,
                RuleID=rule_id,
                UserID=user.id,
                Note=note_val,
                Type="User"
            )
            db.session.add(new_note)
            db_connection_handler(db)


def _add_rule_eval(update_map, app_id, new_assessment):
    rules = update_map.split(';;')[1]
    rule_list = rules.split(';')
    for i in rule_list:
        if i:
            rule_id = i.split('_')[0]
            passed = i.split('_')[2]
            if passed == 'true':
                new_rule = AssessmentBenchmarkRuleAudits(
                    ApplicationID=app_id,
                    RuleID=rule_id,
                    AssessmentID=new_assessment.ID,
                    PassingLevels=1
                )
                db.session.add(new_rule)
                db_connection_handler(db)


def _set_rule_list(app_id, user, id):
    update_map = request.form.get('update_map')
    quick_note_str = request.form.get('quick_note_str')
    metadata = update_map.split(';;')[0]
    target_level = metadata.split('_')[1]
    new_assessment = AssessmentBenchmarkAssessments(
        ApplicationID=app_id,
        BenchmarkID=id,
        UserID=user.id,
        Notes="",
        Type="Manual",
        TargetLevel=target_level,
        Status="Submitted For Approval"
    )
    return new_assessment, quick_note_str, update_map


@assessments.route("/assessment_results/<app_id>/<id>", methods=['GET'])
@login_required
def assessment_results(app_id, id):
    try:
        NAV['curpage'] = {"name": "Assessment Results"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(app_id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)

        benchmark_dict = {}
        benchmarks = AssessmentBenchmarks.query\
            .with_entities(
            AssessmentBenchmarks.ID, AssessmentBenchmarkAssessments.AddDate, AssessmentBenchmarks.Name,
            AssessmentBenchmarks.Description, AssessmentBenchmarks.Version, User.username
        )\
            .join(AssessmentBenchmarkAssessments, AssessmentBenchmarkAssessments.BenchmarkID== AssessmentBenchmarks.ID) \
            .join(User, AssessmentBenchmarkAssessments.UserID == User.id) \
            .filter(text(f"AssessmentBenchmarkAssessments.ID = '{id}'")).all()
        for i in benchmarks:
            benchmark_dict, benchmark_id = _set_assessment_benchmarks(i, benchmark_dict, app_id, id)
        for i in benchmark_dict:
            benchmark_dict = _handle_level_pass(benchmark_dict, i)
        default_benchmark = 'OWASP ASVS v. 3.1'
        NAV['appbar'] = 'benchmarks'
        app = BusinessApplications.query.filter(text(f'ID={app_id}')).first()
        app_data = {'ID': app_id, 'ApplicationName': app.ApplicationName}
        return render_template('assessments/assessment_results.html', benchmarks=benchmark_dict[benchmark_id], default_benchmark=default_benchmark,
                               app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


def _handle_level_pass(benchmark_dict, i):
    audits = benchmark_dict[i]['audits']
    for j in audits:
        if '1' in j[4]:
            benchmark_dict[i]['L1_pass'].append(j.RuleID)
    return benchmark_dict


def _set_assessment_benchmarks(i, benchmark_dict, app_id, assessment_id):
    benchmark_id = i.ID
    benchmark_dict[i.ID] = {"ID": i.ID, "Name": i.Name, "AddDate": i.AddDate, "Description": i.Description,
                            "Version": i.Version, "username": i.username,
                            "L1_pass": [], "L2_pass": [], "L3_pass": []}
    benchmark_dict[i.ID]['rules'] = AssessmentBenchmarkRules.query.filter(text(f"BenchmarkID = '{i.ID}'")).all()

    rules_notes = AssessmentBenchmarkRuleAuditNotes.query \
        .with_entities(AssessmentBenchmarkRuleAuditNotes.ID, AssessmentBenchmarkRuleAuditNotes.AddDate,
                       AssessmentBenchmarkRuleAuditNotes.ApplicationID, AssessmentBenchmarkRuleAuditNotes.Note,
                       AssessmentBenchmarkRuleAuditNotes.RuleID, AssessmentBenchmarkRuleAuditNotes.Type,
                       User.username) \
        .join(User, User.id == AssessmentBenchmarkRuleAuditNotes.UserID) \
        .filter(text(f"ApplicationID = '{app_id}'")).all()
    benchmark_dict[i.ID]['rules_notes'] = {}
    for n in rules_notes:
        match = False
        for r in benchmark_dict[i.ID]['rules']:
            if r.ID == n.RuleID:
                match = True
        if match:
            if n.RuleID not in benchmark_dict[i.ID]['rules_notes']:
                benchmark_dict[i.ID]['rules_notes'][n.RuleID] = []
            benchmark_dict[i.ID]['rules_notes'][n.RuleID].append(
                {"ID": n.ID, "AddDate": n.AddDate.strftime(ISO_FORMAT), "ApplicationID": n.ApplicationID,
                 "Note": n.Note, "RuleID": n.RuleID, "Type": n.Type,
                 "username": n.username})

    # Rule attachments section
    rules_attachments = FileUploads.query \
        .with_entities(FileUploads.ID, FileUploads.FileName,
                       FileUploads.FileSize, FileUploads.FileType,
                       FileUploads.UploadDate, FileUploads.UploadedByUserID,
                       FileUploads.AuditID, FileUploads.BenchmarkingID,
                       FileUploads.FilePath, FileUploads.Status, FileUploads.FileDescription,
                       FileUploads.ApplicationID,
                       User.username) \
        .join(User, User.id == FileUploads.UploadedByUserID) \
        .filter(text(f"ApplicationID = '{app_id}'")).all()
    benchmark_dict[i.ID]['rules_attachments'] = {}
    for n in rules_attachments:
        match = False
        for r in benchmark_dict[i.ID]['rules']:
            if r.ID == n.BenchmarkingID:
                match = True
        if match:
            if n.BenchmarkingID not in benchmark_dict[i.ID]['rules_attachments']:
                benchmark_dict[i.ID]['rules_attachments'][n.BenchmarkingID] = []
            benchmark_dict[i.ID]['rules_attachments'][n.BenchmarkingID].append(
                {
                    "ID": n.ID,
                    "FileName": n.FileName,
                    "FileSize": n.FileSize if n.FileSize else 0,
                    "FileType": n.FileType,
                    "UploadDate": n.UploadDate.strftime("%Y-%m-%d %H:%M:%S"),
                    "UploadedByUserID": n.UploadedByUserID,
                    "AuditID": n.AuditID if n.AuditID else 0,
                    "BenchmarkingID": n.BenchmarkingID,
                    "FilePath": n.FilePath,
                    "Status": n.Status,
                    "FileDescription": n.FileDescription,
                    "ApplicationID": n.ApplicationID,
                    "username": n.username
                }
            )
    #

    benchmark_dict[i.ID]['modal_rules'] = {}
    for r in benchmark_dict[i.ID]['rules']:
        _set_modal_rules(r, benchmark_dict, i)
    benchmark_dict[i.ID]['audits'] = AssessmentBenchmarkRuleAudits.query.with_entities(
        AssessmentBenchmarkRuleAudits.ID, AssessmentBenchmarkRuleAudits.AddDate,
        AssessmentBenchmarkRuleAudits.ApplicationID, AssessmentBenchmarkRuleAudits.RuleID,
        AssessmentBenchmarkRuleAudits.PassingLevels
    ) \
        .join(AssessmentBenchmarkRules, AssessmentBenchmarkRules.ID == AssessmentBenchmarkRuleAudits.RuleID) \
        .filter(text(f"AssessmentBenchmarkRules.BenchmarkID = '{i.ID}'")) \
        .filter(text(f"AssessmentBenchmarkRuleAudits.ApplicationID = '{app_id}'")) \
        .filter(text(f"AssessmentBenchmarkRuleAudits.AssessmentID = '{assessment_id}'")) \
        .order_by(desc(AssessmentBenchmarkRuleAudits.AssessmentID)) \
        .all()
    return benchmark_dict, benchmark_id


def _set_modal_rules(r, benchmark_dict, i):
    benchmark_dict[i.ID]['modal_rules'][r.ID] = {
        "AddDate": r.AddDate.strftime(ISO_FORMAT),
        "BenchmarkID": r.BenchmarkID,
        "Description": r.Description, "ID": r.ID,
        "ImplementationLevels": r.ImplementationLevels,
        "Number": r.Number,
        "Notes": benchmark_dict[i.ID]['rules_notes'][r.ID] if r.ID in benchmark_dict[i.ID]['rules_notes'] else [],
        "Files": benchmark_dict[i.ID]['rules_attachments'][r.ID] if r.ID in benchmark_dict[i.ID]['rules_attachments'] else []}
    return benchmark_dict


@assessments.route("/add_benchmark_note", methods=['POST'])
@login_required
def add_benchmark_note():
    try:
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        app_id = request.form.get('app_id')
        status = _entity_page_permissions_filter(app_id, user_roles, session, admin_role)
        if status == 200:
            rule_id = request.form.get('rule_id')
            note = request.form.get('note')
            add_date = request.form.get('add_date')
            note_type = "User"
            new_note = AssessmentBenchmarkRuleAuditNotes(
                ApplicationID = int(app_id),
                RuleID = rule_id,
                UserID = user.id,
                Note = note,
                Type = note_type
            )
            db.session.add(new_note)
            db.session.commit()
            return jsonify({'response': new_note.ID}), 200
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@assessments.route("/delete_benchmark_note", methods=['POST'])
@login_required
def delete_benchmark_note():
    try:
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'])
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        if request.method == 'POST':
            note_id = request.form.get('note_id')
            del_note = AssessmentBenchmarkRuleAuditNotes.query.filter(text(f"ID={note_id} AND UserID={user.id}")).first()
            db.session.delete(del_note)
            db_connection_handler(db)
            return str(200)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@assessments.route("/add_benchmark_attachment", methods=['POST'])
@login_required
def add_benchmark_attachment():
    try:
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        app_id = request.form.get('app_id')
        status = _entity_page_permissions_filter(app_id, user_roles, session, admin_role)
        if status == 200:
            file = request.files['file']
            filename = secure_filename(file.filename)
            upload_folder = 'file_uploads'
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            file_size = file.content_length  # Get file size
            file_type = file.mimetype  # Get file MIME type
            rule_id = request.form.get('rule_id')
            note = request.form.get('note')
            add_date = request.form.get('add_date')
            new_attachment = FileUploads(
                 FileName  = filename,
                 FileSize = file_size if file_size else 0,
                 FileType = file_type,
                 UploadDate = datetime.datetime.utcnow(),
                 UploadedByUserID = user.id,
                 AuditID = None,
                 BenchmarkingID = rule_id,
                 FilePath = filepath,
                 Status = "Available",
                 FileDescription = note,
                 ApplicationID = app_id
            )
            db.session.add(new_attachment)
            db.session.commit()
            return jsonify({'response': new_attachment.ID}), 200
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500

@assessments.route("/delete_benchmark_attachment", methods=['POST'])
@login_required
def delete_benchmark_attachment():
    try:
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'])
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        if request.method == 'POST':
            file_id = request.form.get('file_id')
            del_note = FileUploads.query.filter(text(f"ID={file_id} AND UploadedByUserID={user.id}")).first()
            db.session.delete(del_note)
            db_connection_handler(db)
            current_working_directory = os.getcwd()
            file_path = os.path.join(current_working_directory, del_note.FilePath)
            if os.path.exists(file_path):
                os.remove(file_path)
            return str(200)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@assessments.route("/download_benchmark_attachment/<file_id>", methods=['GET'])
@login_required
def download_benchmark_attachment(file_id):
    try:
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'])
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)

        dl_file = FileUploads.query.filter(text(f"ID={file_id} AND UploadedByUserID={user.id}")).first()
        if dl_file is None:
            # Handle case where file is not found
            return "File not found", 404

        current_working_directory = os.getcwd()

        file_path = os.path.join(current_working_directory, dl_file.FilePath)
        return send_file(file_path)  # Send the file to the client
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@assessments.route("/submit_risk_profile", methods=['POST'])
@login_required
def submit_risk_profile():
    try:
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'])
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)

        referrer = request.referrer
        all_answers = request.form
        app_id = all_answers['app_id']
        score, formatted_answers, criticality = _score_risk_profile(all_answers)
        new_profile = RiskProfile(
            AddDate=datetime.datetime.utcnow(),
            CompletedByUserID=user.id,
            Answers=formatted_answers,
            Status='Completed',
            Scores=score,
            ApplicationID=app_id
        )
        db.session.add(new_profile)
        db.session.commit()

        db.session.query(BusinessApplications).filter(BusinessApplications.ID == app_id)\
            .update({BusinessApplications.Criticality: criticality}, synchronize_session=False)
        db_connection_handler(db)
        return redirect(referrer)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


def _score_risk_profile(answers):
    score = 0
    formatted_answers = ''
    criticality = ''
    formatted_scores = ''

    score_map = {
        1: {"on_premise": 2, "cloud": 3, "hybrid": 4},
        2: {"yes": 5, "no": 1},
        3: {"yes": 4, "no": 2},
        4: {"personal": 5, "financial": 5, "health": 5, "none": 1},
        5: {"high": 5, "medium": 3, "low": 2, "none": 1},
        6: {"gdpr": 4, "hipaa": 4, "others": 3, "none": 1},
        7: {"critical": 5, "important": 3, "non_critical": 1},
        8: {"high": 5, "medium": 3, "low": 1},
        9: {"yes": 1, "no": 4},
        10: {"yes": 4, "no": 2},
        11: {"regularly": 1, "occasionally": 3, "never": 5},
        12: {"high": 4, "medium": 2, "low": 1},
        13: {"yes": 4, "no": 1},
        14: {"large": 3, "limited": 2, "few": 1},
        15: {"yes": 1, "no": 3},
        16: {"regularly": 1, "occasionally": 3, "rarely": 5},
        17: {"yes": 1, "no": 4}
    }

    # 1: on_premise-2, cloud-3, hybrid-4
    formatted_answers += f'1::hosting::{answers["hosting"]};;'
    score += score_map[1][answers["hosting"]]
    formatted_scores += f'1::{score_map[1][answers["hosting"]]};;'
    # 2: yes-5, no-1
    formatted_answers += f'2::public_exposure::{answers["public_exposure"]};;'
    score += score_map[2][answers["public_exposure"]]
    formatted_scores += f'2::{score_map[2][answers["public_exposure"]]};;'
    # 3: yes-4, no-2
    formatted_answers += f'3::third_party::{answers["third_party"]};;'
    score += score_map[3][answers["third_party"]]
    formatted_scores += f'3::{score_map[3][answers["third_party"]]};;'
    # 4: personal-5, financial-5, health-5, none-1
    formatted_answers += f'4::data_type::{answers["data_type"]};;'
    score += score_map[4][answers["data_type"]]
    formatted_scores += f'4::{score_map[4][answers["data_type"]]};;'
    # 5: high-5, medium-3, low-2, none-1
    formatted_answers += f'5::data_volume::{answers["data_volume"]};;'
    score += score_map[5][answers["data_volume"]]
    formatted_scores += f'5::{score_map[5][answers["data_volume"]]};;'
    # 6: gdpr-4, hipaa-4, others-3, none-1
    formatted_answers += f'6::regulatory_requirements::{answers["regulatory_requirements"]};;'
    score += score_map[6][answers["regulatory_requirements"]]
    formatted_scores += f'6::{score_map[6][answers["regulatory_requirements"]]};;'
    # 7: critical-5, important-3, non_critical-1
    formatted_answers += f'7::business_role::{answers["business_role"]};;'
    score += score_map[7][answers["business_role"]]
    formatted_scores += f'7::{score_map[7][answers["business_role"]]};;'
    # 8: high-5, medium-3, low-1
    formatted_answers += f'8::downtime_impact::{answers["downtime_impact"]};;'
    score += score_map[8][answers["downtime_impact"]]
    formatted_scores += f'8::{score_map[8][answers["downtime_impact"]]};;'
    # 9: yes-1, no-4
    formatted_answers += f'9::disaster_recovery::{answers["disaster_recovery"]};;'
    score += score_map[9][answers["disaster_recovery"]]
    formatted_scores += f'9::{score_map[9][answers["disaster_recovery"]]};;'
    # 10: yes-4, no-2
    formatted_answers += f'10::compliance_requirements::{answers["compliance_requirements"]};;'
    score += score_map[10][answers["compliance_requirements"]]
    formatted_scores += f'10::{score_map[10][answers["compliance_requirements"]]};;'
    # 11: regularly-1, occasionally-3, never-5
    formatted_answers += f'11::compliance_audits::{answers["compliance_audits"]};;'
    score += score_map[11][answers["compliance_audits"]]
    formatted_scores += f'11::{score_map[11][answers["compliance_audits"]]};;'
    # 12: high-4, medium-2, low-1
    formatted_answers += f'12::architecture_complexity::{answers["architecture_complexity"]};;'
    score += score_map[12][answers["architecture_complexity"]]
    formatted_scores += f'12::{score_map[12][answers["architecture_complexity"]]};;'
    # 13: yes-4, no-1
    formatted_answers += f'13::legacy_technologies::{answers["legacy_technologies"]};;'
    score += score_map[13][answers["legacy_technologies"]]
    formatted_scores += f'13::{score_map[13][answers["legacy_technologies"]]};;'
    # 14: large-3, limited-2, few-1
    formatted_answers += f'14::user_access::{answers["user_access"]};;'
    score += score_map[14][answers["user_access"]]
    formatted_scores += f'14::{score_map[14][answers["user_access"]]};;'
    # 15: yes-1, no-3
    formatted_answers += f'15::multi_level_access::{answers["multi_level_access"]};;'
    score += score_map[15][answers["multi_level_access"]]
    formatted_scores += f'15::{score_map[15][answers["multi_level_access"]]};;'
    # 16: regularly-1, occasionally-3, rarely-5
    formatted_answers += f'16::update_frequency::{answers["update_frequency"]};;'
    score += score_map[16][answers["update_frequency"]]
    formatted_scores += f'16::{score_map[16][answers["update_frequency"]]};;'
    # 17: yes-1, no-4
    formatted_answers += f'17::change_management::{answers["change_management"]};;'
    score += score_map[17][answers["change_management"]]
    formatted_scores += f'17::{score_map[17][answers["change_management"]]};;'
    returned_store = f'{score}:::{formatted_scores}'
    # Determine Risk Category (criticality), Low Risk: 17-35, Medium Risk: 36-53, High Risk: 54-71
    if score < 36:
        criticality = f'low ({score})'
    elif score < 54:
        criticality = f'medium ({score})'
    else:
        criticality = f'high ({score})'
    return returned_store, formatted_answers, criticality
