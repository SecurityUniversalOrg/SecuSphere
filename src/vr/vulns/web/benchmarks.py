from vr import db
from vr.vulns import vulns
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, _add_page_permissions_filter
from vr.admin.functions import db_connection_handler
from sqlalchemy import text, desc, and_, func
from flask import render_template, session, redirect, url_for, request, jsonify
from flask_login import login_required
from vr.assets.model.businessapplications import BusinessApplications, MakeBusinessApplicationsSchema, BusinessApplicationsSchema
from vr.vulns.model.assessmentbenchmarks import AssessmentBenchmarks, AssessmentBenchmarksSchema
from vr.vulns.model.assessmentbenchmarkrules import AssessmentBenchmarkRules
from vr.vulns.model.assessmentbenchmarkruleaudits import AssessmentBenchmarkRuleAudits
from vr.vulns.model.assessmentbenchmarkruleauditnotes import AssessmentBenchmarkRuleAuditNotes
from vr.vulns.model.appassessmentbenchmarkassignments import AppAssessmentBenchmarkAssignments
from vr.vulns.model.assessmentbenchmarkassessments import AssessmentBenchmarkAssessments, AssessmentBenchmarkAssessmentsSchema
from vr.admin.models import User
from math import ceil
from vr.functions.table_functions import load_table, update_table


NAV = {
    'CAT': { "name": "Applications", "url": "sourcecode.dashboard"}
}
APP_ADMIN = "Application Admin"
APP_VIEWER = "Application Viewer"
ADMIN_LOGIN = "admin.login"
UNAUTH_STATUS = "403.html"
SERVER_ERR_STATUS = "500.html"
ISO_FORMAT = '%Y-%m-%d %H:%M:%S'


@vulns.route("/all_application_benchmarks/<id>", methods=['GET', 'POST'])
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
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName}
        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": components.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < components.total else components.total
        }
        return render_template('all_application_benchmarks.html', app_data=app_data, entities=assets, user=user, NAV=NAV,
                               table_details= table_details)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@vulns.route("/benchmark_assessments/<id>", methods=['GET', 'POST'])
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
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName}

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": components.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < components.total else components.total
        }

        return render_template('benchmark_assessments.html', app_data=app_data, entities=assets, user=user,
                               NAV=NAV, table_details=table_details)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@vulns.route("/application_benchmarks/<app_id>/<id>", methods=['GET', 'POST'])
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
            app_data = {'ID': app_id, 'ApplicationName': app.ApplicationName}
            return render_template('application_benchmarks.html', benchmarks=benchmark_dict[benchmark_id], default_benchmark=default_benchmark,
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
        "Notes": benchmark_dict[i.ID]['rules_notes'][r.ID] if r.ID in benchmark_dict[i.ID]['rules_notes'] else []}
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


@vulns.route("/assessment_results/<app_id>/<id>", methods=['GET', 'POST'])
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
        if request.method == 'POST':
            update_map = request.form.get('update_map')
            metadata = update_map.split(';;')[0]
            benchmark_id = metadata.split('_')[0]
            target_level = metadata.split('_')[1]
            rules = update_map.split(';;')[1]
            rule_list = rules.split(';')
            for i in rule_list:
                rule_id = i.split('_')[0]
                applicable = i.split('_')[1]
                passed = i.split('_')[2]
                print(benchmark_id, target_level, rule_id, applicable, passed)
        else:
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
            return render_template('assessment_results.html', benchmarks=benchmark_dict[benchmark_id], default_benchmark=default_benchmark,
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
        "Notes": benchmark_dict[i.ID]['rules_notes'][r.ID] if r.ID in benchmark_dict[i.ID]['rules_notes'] else []}
    return benchmark_dict


@vulns.route("/add_benchmark_note", methods=['POST'])
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
                AddDate=add_date,
                ApplicationID = app_id,
                RuleID = rule_id,
                UserID = user.id,
                Note = note,
                Type = note_type
            )
            db.session.add(new_note)
            db_connection_handler(db)
            return jsonify({'response': new_note.ID}), 200
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500

@vulns.route("/delete_benchmark_note", methods=['POST'])
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

@vulns.route("/add_assessment_benchmark", methods=['GET', 'POST'])
@login_required
def add_assessment_benchmark():
    try:
        NAV['curpage'] = {"name": "Add Assessment Benchmark"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _add_page_permissions_filter(session, admin_role)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        if request.method == 'POST':
            app_id = request.form.get('app_id')
            print(app_id)

        return render_template('add_assessment_benchmark.html', user=user, NAV=NAV)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500
