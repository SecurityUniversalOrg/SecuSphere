from flask import request, render_template, session, redirect, url_for, escape
from flask_login import login_required
from vr import db
from vr.threat_modeling import threat_modeling
from vr.threat_modeling.main import ThreatModeler
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter
from sqlalchemy import text, func
from math import ceil
from vr.functions.table_functions import load_table, update_table
from vr.assets.model.businessapplications import BusinessApplications
from vr.admin.functions import db_connection_handler
from vr.admin.models import User
from vr.threat_modeling.model.tmthreatassessments import TmThreatAssessments, TmThreatAssessmentsSchema
from vr.threat_modeling.model.tmidentifiedthreats import TmIdentifiedThreats
from vr.threat_modeling.model.tmidentifiedsolutions import TmIdentifiedSolutions
from vr.threat_modeling.model.tmthreats import TmThreats


THREAT_MODELER = "Threat Modeler"
APP_ADMIN = "Application Admin"
APP_VIEWER = "Application Viewer"
ADMIN_LOGIN = "admin.login"
UNAUTH_STATUS = "403.html"
SERVER_ERR_STATUS = "500.html"


NAV = {
    'CAT': { "name": THREAT_MODELER, "url": "threat_modeling.threat_modeler"}
}


@threat_modeling.route('/threat_modeler/<id>', methods=['GET', 'POST'])
@login_required
def threat_modeler(id):
    try:
        NAV['curpage'] = { "name": THREAT_MODELER }
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(id, user_roles, session, admin_role)
        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, nav_cat={}, nav_subcat='', \
                                   nav_subsubcat='', nav_curpage={"name": "Unauthorized"})
        if request.method == 'POST':
            form = request.form
            threats, controls, applied_solutions, threats_mitigated = ThreatModeler().run(form)
            new_assessment = TmThreatAssessments(
                ApplicationID=id,
                SubmitUserID=user.id,
                Status='Submitted'
            )
            db.session.add(new_assessment)
            db_connection_handler(db)
            for i in threats:
                new_threat = TmIdentifiedThreats(
                    ApplicationID=id,
                    ThreatAssessmentID=new_assessment.ID,
                    ThreatID=i['SID']
                )
                db.session.add(new_threat)
                db_connection_handler(db)
            for i in applied_solutions:
                new_solution = TmIdentifiedSolutions(
                    ApplicationID=id,
                    ThreatAssessmentID=new_assessment.ID,
                    SolutionID=list(i.keys())[0]
                )
                db.session.add(new_solution)
                db_connection_handler(db)
                NAV['appbar'] = 'threat_models'
                app = BusinessApplications.query.filter(text(f'ID={id}')).first()
                app_data = {'ID': id, 'ApplicationName': app.ApplicationName}
            return render_template('threat_modeling/threat_report.html', user=user, NAV=NAV, threats=threats,
                                   controls=controls, num_threats_mitigated=len(threats_mitigated), app_data=app_data)
        else:
            questions = ThreatModeler().read_questions_csv()
            application_questions = {
                "workflow_one": {
                    "Test Question":[
                        "Answer 1",
                        "Answer 2",
                    ]
                }
            }
            NAV['appbar'] = 'threat_models'
            app = BusinessApplications.query.filter(text(f'ID={id}')).first()
            app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}
            return render_template('threat_modeling/threat_modeler.html', app_data=app_data, user=user, NAV=NAV, questions=questions, application_questions=application_questions)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@threat_modeling.route("/threat_assessments/<id>", methods=['GET', 'POST'])
@login_required
def threat_assessments(id):
    try:
        NAV['curpage'] = {"name": THREAT_MODELER}
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

        key = 'BusinessApplications.ID'
        val = id
        filter_list = [f"{key} = '{val}'"]

        new_dict = {
            'db_name': 'TmThreatAssessments',
            "sort_field": "ID"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict, direction="desc")
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict, direction="desc")

        assessments = TmThreatAssessments.query\
            .with_entities(
            TmThreatAssessments.ID,
            TmThreatAssessments.AddDate,
            User.username,
            TmThreatAssessments.Status,
            func.count(TmIdentifiedThreats.ThreatID).label('findings_cnt'),
            BusinessApplications.ApplicationName
        ) \
            .join(BusinessApplications, TmThreatAssessments.ApplicationID == BusinessApplications.ID, isouter=True) \
            .join(TmIdentifiedThreats, TmIdentifiedThreats.ThreatAssessmentID == TmThreatAssessments.ID, isouter=True) \
            .join(User, User.id == TmThreatAssessments.SubmitUserID, isouter=True) \
            .group_by(TmThreatAssessments.ID) \
            .filter(text("".join(filter_list))) \
            .order_by(text(orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((assessments.total / per_page))
        schema = TmThreatAssessmentsSchema(many=True)
        assets = schema.dump(assessments.items)


        NAV['appbar'] = 'threat_models'
        app = BusinessApplications.query.filter(text(f'ID={id}')).first()
        app_data = {'ID': id, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}

        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": assessments.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < assessments.total else assessments.total
        }

        return render_template('threat_modeling/threat_assessments.html', app_data=app_data, entities=assets, user=user, NAV=NAV,
                               table_details=table_details)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500



@threat_modeling.route("/threat_assessment/<appid>/<id>")
@login_required
def threat_assessment(appid, id):
    try:
        NAV['curpage'] = {"name": "Threat Assessment"}
        admin_role = APP_ADMIN
        role_req = [APP_ADMIN, APP_VIEWER]
        perm_entity = 'Application'
        user, status, user_roles = _auth_user(session, NAV['CAT']['name'], role_requirements=role_req,
                                              permissions_entity=perm_entity)
        status = _entity_page_permissions_filter(appid, user_roles, session, admin_role)

        if status == 401:
            return redirect(url_for(ADMIN_LOGIN))
        elif status == 403:
            return render_template(UNAUTH_STATUS, user=user, NAV=NAV)
        details = {}
        endpoints_all = TmThreatAssessments.query.with_entities(
            TmThreatAssessments.ID, TmThreatAssessments.AddDate, TmThreatAssessments.ApplicationID,
            TmThreatAssessments.SubmitUserID, TmThreatAssessments.Status,
            User.username
        ) \
            .join(User, User.id == TmThreatAssessments.SubmitUserID) \
            .filter(TmThreatAssessments.ID == id).all()
        details['details'] = endpoints_all[0]
        vulns_all = TmIdentifiedThreats.query \
            .with_entities(TmIdentifiedThreats.ID, TmIdentifiedThreats.AddDate,
                           TmThreats.Description, TmThreats.Details, TmThreats.LikelihoodOfAttack, TmThreats.Severity,
                           TmThreats.Mitigations, TmThreats.Example, TmThreats.rReferences)\
            .join(TmThreatAssessments, TmIdentifiedThreats.ThreatAssessmentID == TmThreatAssessments.ID) \
            .join(TmThreats, TmThreats.ID==TmIdentifiedThreats.ThreatID, isouter=True) \
            .filter(TmThreatAssessments.ID==id) \
            .all()
        threats = []
        threats_dict = {}
        for i in vulns_all:
            add_date = i.AddDate.strftime("%Y-%m-%d %H:%M:%S")
            new_dict = {
                "ID": i.ID,
                "AddDate": add_date,
                "Description": i.Description,
                "Details": i.Details.replace(';', ''),
                "LikelihoodOfAttack": i.LikelihoodOfAttack,
                "Severity": i.Severity,
                "Mitigations": i.Mitigations,
                "Example": i.Example.translate(str.maketrans({"-":  r"\-",
                                              "]":  r"\]",
                                              "\\": r"\\",
                                              "^":  r"\^",
                                              "$":  r"\$",
                                              "*":  r"\*",
                                              "<": r"\<",
                                              ">": r"\>",
                                              ".":  r"\."})),
                "rReferences": i.rReferences
            }
            threats.append(new_dict)
            threats_dict[i.ID] = new_dict
        details['vulns_all'] = threats
        details['threats_all'] = threats_dict
        NAV['appbar'] = 'threat_models'
        app = BusinessApplications.query.filter(BusinessApplications.ID == appid).first()
        app_data = {'ID': appid, 'ApplicationName': app.ApplicationName, 'Component': app.ApplicationAcronym}

        return render_template('threat_modeling/threat_assessment.html', details=details, app_data=app_data, user=user, NAV=NAV)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500
