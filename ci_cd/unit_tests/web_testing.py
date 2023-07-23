import unittest
import base64
import os
from flask import current_app
from datetime import datetime
from vr import app, db
from vr.admin.models import User, Messages
from vr.assets.model.businessapplications import BusinessApplications
from vr.vulns.model.vulnerabilities import Vulnerabilities
from vr.vulns.model.vulnerabilityscans import VulnerabilityScans
from vr.vulns.model.vulnerabilityslaapppair import VulnerabilitySLAAppPair

ADMIN_USER_FIRST_NAME = 'testadmin'
ADMIN_USER_LAST_NAME = 'user'
ADMIN_USER_USERNAME = f"{ADMIN_USER_FIRST_NAME}.{ADMIN_USER_LAST_NAME}"
ADMIN_USER_EMAIL = f"{ADMIN_USER_USERNAME}@acme.com"
ADMIN_USER_PW = '!nS3CuRe'
TEST_USER_FIRST_NAME = 'test'
TEST_USER_LAST_NAME = 'user'
TEST_USER_USERNAME = f"{TEST_USER_FIRST_NAME}.{TEST_USER_LAST_NAME}"
TEST_USER_EMAIL = f"{TEST_USER_USERNAME}@acme.com"
TEST_USER_PW = '!nS3CuRe'
TEST_EMAIL = 'Brian@jbfinegoods.com'
TEST_APP_NAME = 'TestApp'


class TestWebApp(unittest.TestCase):
    def setUp(self):
        os.environ['RUNTIME_ENV'] = 'unit_test'
        db_path = os.path.join(os.path.dirname(__file__), 'instance', 'database.db')
        app.secret_key = 'secret_key'
        self.app = app
        self.app.config['WTF_CSRF_ENABLED'] = False  # no CSRF during tests
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
        self.appctx = self.app.app_context()
        self.appctx.push()
        self.client = self.app.test_client()
        self.db = db

    def tearDown(self):
        self.appctx.pop()
        self.app = None
        self.appctx = None
        self.client = None
        self.db = None

    def _login(self):
        response = self.client.post('/login', data={
            'login[username]': ADMIN_USER_USERNAME,
            'login[password]': ADMIN_USER_PW,
        })
        return response

    def _logout(self):
        response = self.client.get('/logout')
        return response

    def test_1_app(self):
        assert self.app is not None
        assert current_app == self.app

    def test_2_register_get(self):
        route = "/register"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_3_register_submit_post(self):
        route = "/register_submit"
        data_dict = {
            'firstname': ADMIN_USER_FIRST_NAME,
            'lastname': ADMIN_USER_LAST_NAME,
            'psw': ADMIN_USER_PW,
            'email': ADMIN_USER_EMAIL,
        }
        response = self._post_test_no_login_handler(route, data_dict)
        assert response.status_code == 200

    def test_4_create_app(self):
        now = datetime.utcnow()
        new_app = BusinessApplications(
            ApplicationName=TEST_APP_NAME,
            ApplicationAcronym='Test Component',
            RegDate=now,
            AssignmentChangedDate=now,
            MalListingAddDate=now
        )
        self.db.session.add(new_app)
        self.db.session.commit()
        vsap = VulnerabilitySLAAppPair(
            ApplicationID=new_app.ID,
            SlaID=1
        )
        self.db.session.add(vsap)
        self.db.session.commit()
        assert 1 == 1

    def test_5_create_app_finding(self):
        now = datetime.utcnow()
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        new_vuln = Vulnerabilities(
            VulnerabilityName='Test for Unit Test',
            AddDate=now,
            ApplicationId=app.ID,
            Severity='High',
            Classification='SAST',
            ReleaseDate=now
        )
        self.db.session.add(new_vuln)
        self.db.session.commit()
        assert 1 == 1

    def test_6_threat_modeler_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/threat_modeler/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_7_threat_modeler_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/threat_modeler/{app.ID}"
        data_dict = {
            'Review Type': 'Application',
            'Is data stored?': 'Yes',
            'Is data processed?': 'Yes',
            'Are environment variables used?': 'Yes',
            'Are session tokens used?': 'Yes',
            'Is an API Implemented?': 'Yes',
            'Which Web Protocols are Implemented?_HTTP': 'on',
            'Which Web Protocols are Implemented?_HTTPS': 'on',
            'Is client-side scripting allowed?': 'Yes',
            'Is data stored on shared server?': 'Yes',
            'What types of data are stored?_XML': 'on',
            'What types of data are stored?_JSON': 'on',
            'What types of data are stored?_HTML': 'on',
            'What types of data are processed?_XML': 'on',
            'What types of data are processed?_JSON': 'on',
            'What types of data are processed?_HTML': 'on',
            'What types of data are processed?_SQL': 'on',
            'Is a VPN used for HTTP Traffic?': 'Yes',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_8_threat_assessments_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/threat_assessments/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_9_threat_assessments_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/threat_assessments/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'TmThreatAssessments.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_A_threat_assessment_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/threat_assessment/{app.ID}/1"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_A1_application_benchmarks_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/application_benchmarks/{app.ID}/1"
        data_dict = {
            'update_map': '1_Level 1;;1_true_true;2_true_true;3_true_false;',
            'quick_note_str': '1:This is a note for rule 1;;2:This is a note for rule 2',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_A2_open_findings_for_scan_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        scan = VulnerabilityScans(
            ScanName='Unit Test',
            ScanType='Unit Test',
            ScanStartDate=datetime.utcnow(),
            ApplicationId=1,
            Branch='main'
        )
        self.db.session.add(scan)
        self.db.session.commit()
        route = f"/open_findings_for_scan/{app.ID}/{scan.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_A3_add_integration_post(self):
        route = f"/add_integration"
        data_dict = {
            'name': 'Test Integration',
            'description': 'This is a test integration',
            'url': 'http://acme.com',
            'tool_type': 'Jenkins',
            'authentication_type': 'Password',
            'extras': '',
            'username': 'TestUser',
            'password': 'TestPW',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 302
        assert response.headers['Location'].startswith('/all_integrations')

    def test_A4_create_client_post(self):
        route = "/create_client"
        data_dict = {
            'client_name': 'Test',
            'read:vulnerabilities': 'on',
            'write:vulnerabilities': 'on',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_A5_all_application_metrics_get(self):
        route = f"/all_application_metrics"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_login(self):
        response = self._login()
        self._logout()
        assert response.status_code == 302

    def test_logout(self):
        self._login()
        response = self._logout()
        assert response.status_code == 302
        assert response.location.replace('http://localhost', '').startswith('/login')

    def test_redirect_root_no_auth(self):
        route = '/'
        response = self.client.get(route)
        print(f'Testing: {route}.....Response: {response.request.path}', flush=True)
        assert response.status_code == 302
        assert response.location.replace('http://localhost', '') == '/login'

    def test_forgot_username(self):
        email = ADMIN_USER_EMAIL
        response = self.client.post('/forgotun', data={
            'email': email,
        }, follow_redirects=True)
        print(f'Testing: /forgotun.....Response: {response.status_code}   Path: {response.request.path}', flush=True)
        assert response.status_code == 200
        user = User.query.filter_by(email=email).first()
        response = self.client.get(f'/displayun/{user.get_id()}/{user.get_username_token()}')
        assert response.status_code == 200

    def test_pw_reset(self):
        email = ADMIN_USER_EMAIL
        new_pw = ADMIN_USER_PW
        response = self.client.post('/forgotpw', data={
            'email': email,
        }, follow_redirects=True)
        print(f'Testing: /forgotpw.....Response: {response.status_code}   Path: {response.request.path}', flush=True)
        assert response.status_code == 200
        user = User.query.filter_by(email=email).first()
        response = self.client.get(f'/resetpw/{user.get_id()}/{user.get_pwreset_token()}')
        assert response.status_code == 200
        response = self.client.post(f'/resetpw/{user.get_id()}/{user.get_pwreset_token()}', data={
            'psw': new_pw,
            'psw-repeat': new_pw,
        }, follow_redirects=True)
        assert response.status_code == 200
        self.client.post('/login', data={
            'login[username]': ADMIN_USER_USERNAME,
            'login[password]': new_pw,
        })
        response = self.client.get('/profile')
        assert response.status_code == 200

    # All Routes Section #
    def _get_test_handler(self, route):
        self._login()
        response = self.client.get(route)
        self._logout()
        print(f'Testing: {route}.....Response: {response.status_code}')
        return response

    def _post_test_handler(self, route, data_dict):
        self._login()
        response = self.client.post(route, data=data_dict)
        self._logout()
        return response

    def _get_test_no_login_handler(self, route):
        response = self.client.get(route)
        print(f'Testing: {route}.....Response: {response.status_code}')
        return response

    def _post_test_no_login_handler(self, route, data_dict):
        response = self.client.post(route, data=data_dict)
        return response

    def test_edit_profile_get(self):
        route = "/edit_profile"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_edit_profile_post(self):
        route = "/edit_profile"
        data_dict = {
            'first_name': ADMIN_USER_FIRST_NAME,
            'last_name': ADMIN_USER_LAST_NAME,
            'jobtitle': 'Tester',
            'dept': 'QA',
            'about_me': 'I love unit testing.',
            'city': 'New York',
            'state': 'NY',
            'zip': '10000',
            'web_tz': 'America/New_York',
            'email_updates': 'y',
            'app_updates': 'y',
            'text_updates': 'y',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_update_mfa_status_post(self):
        route = "/update_mfa_status"
        data_dict = {
            'mfa_enabled': 0
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_display_mfa_qr_get(self):
        route = "/display_mfa_qr"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_mobile_sync_get(self):
        route = "/mobile_sync"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_profile_get(self):
        route = "/profile"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_mfa_qrcode_get(self):
        route = "/mfa_qrcode"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_create_client_get(self):
        route = "/create_client"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_api_documentation_get(self):
        route = "/api/documentation"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_messages_get(self):
        route = "/messages"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_messages_post(self):
        route = "/messages"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Messages.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_suppress_msg_post(self):
        msg = Messages(
            SenderUserId=1,
            ReceiverUserId=1,
            MessageType='Test',
            EntityType='Application',
            EntityID=1,
            Message='This is a test message for Unit Testing'
        )
        self.db.session.add(msg)
        self.db.session.commit()
        route = "/suppress_msg"
        data_dict = {
            'msg_id': msg.ID
        }
        response = self._post_test_handler(route, data_dict)
        self.db.session.delete(msg)
        self.db.session.commit()
        assert response.status_code == 200

    def test_onboarding_get(self):
        route = "/onboarding"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_onboarding_suppress_get(self):
        route = "/onboarding_suppress"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_register_user_get(self):
        otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        new_user = User(
            username=TEST_USER_USERNAME,
            email=TEST_USER_EMAIL,
            first_name=TEST_USER_FIRST_NAME,
            last_name=TEST_USER_LAST_NAME,
            is_active=False,
            auth_type='local',
            otp_secret=otp_secret,
            user_type='system',
            avatar_path='/static/images/default_profile_avatar.jpg'
        )
        self.db.session.add(new_user)
        self.db.session.commit()
        token = new_user.get_delegated_registration_token(new_user.id)
        self.db.session.query(User).filter(User.id == int(new_user.id)).update(
            {User.auth_token: token},
            synchronize_session=False)
        self.db.session.commit()
        self._logout()
        route = f"/register_user/{token}"
        response = self._get_test_no_login_handler(route)
        assert response.status_code == 200

    def test_register_user_submit_post(self):
        route = "/register_user_submit"
        data_dict = {
            'psw': TEST_USER_PW,
            'email': TEST_USER_EMAIL,
        }
        response = self._post_test_no_login_handler(route, data_dict)
        match = _three_o_two_handler(response.headers, '/all_applications')
        assert response.status_code == 302
        assert match

    def test_qrcode_get(self):
        route = "/qrcode"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_unauth_403_get(self):
        route = "/unauth_403"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_users_get(self):
        route = "/users"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_users_post(self):
        route = "/users"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'User.id desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_add_user_role_post(self):
        route = "/add_user_role"
        data_dict = {
            'user_id': 2,
            'new_grp': 'Security',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_remove_user_role_post(self):
        route = "/remove_user_role"
        data_dict = {
            'user_id': 2,
            'role': 'Security',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_remove_user_appview_role_post(self):
        route = "/remove_user_appview_role"
        data_dict = {
            'user_id': 2,
            'app_id': 1,
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_add_new_user_post(self):
        route = "/add_new_user"
        data_dict = {
            'firstname': 'new',
            'lastname': 'user',
            'email': TEST_EMAIL,
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_remove_user_post(self):
        route = "/remove_user"
        user = User.query.filter_by(email=TEST_EMAIL).first()
        data_dict = {
            'user_id': user.id,
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_dockerimages_get(self):
        route = "/all_dockerimages"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_dockerimages_post(self):
        route = "/all_dockerimages"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'DockerImages.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_dockerimages_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/dockerimages/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_dockerimages_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/dockerimages/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'DockerImages.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_branches_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/branches/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_branches_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/branches/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'VulnerabilityScans.Branch desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_cheatsheets_get(self):
        route = "/all_cheatsheets"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_cheatsheets_get(self):
        sheet_name = 'IndexTopTen'
        route = f"/cheatsheets/{sheet_name}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_git_repos_get(self):
        route = "/all_git_repos"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_components_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()

        route = f"/components/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_components_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/components/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_service_tickets_get(self):
        route = "/all_service_tickets"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_service_tickets_post(self):
        route = "/all_service_tickets"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'ServiceTickets.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_issue_get(self):
        # TODO: finish
        assert 1 == 1

    def test_add_service_ticket_get(self):
        # TODO: finish
        assert 1 == 1

    def test_sourcecode_files_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/sourcecode_files/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_sourcecode_files_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/sourcecode_files/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.VulnerableFileName desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_applications_get(self):
        route = f"/all_applications"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_applications_post(self):
        route = f"/all_applications"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'BusinessApplications.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_application_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/application/{app.ID}/App/{TEST_APP_NAME }"
        response = self._get_test_handler(route)
        assert response.status_code == 200
        route = f"/application/{app.ID}/Component/main"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_application_export_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/application/{app.ID}/export"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_application_csv_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/application/{app.ID}/csv"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_add_application_get(self):
        route = f"/add_application"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_add_application_post(self):
        route = f"/add_application"
        data_dict = {
            'name': 'New App',
            'description': 'This is a new app created for Unit Testing',
            'business_criticality': 'High',
            'initial_version': '1',
            'data_types': 'PHI',
            'platform': 'Web',
            'internet_accessible': 'on',
            'repo_url': 'https://github.com/NewApp',
            'prod_type': 'Marketing',
            'lifecycle': 'Pre-Prod',
            'origin': 'Developed In-House',
            'user_records': 25,
            'revenue': 100,
            'sla_configuration': 1,
            'regulations': 1,
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_application_issues_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/application_issues/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_application_issues_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/application_issues/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'ServiceTickets.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_delete_application_get(self):
        now = datetime.utcnow()
        new_app = BusinessApplications(
            ApplicationName='New App 2',
            ApplicationAcronym='Test Component',
            RegDate=now,
            AssignmentChangedDate=now,
            MalListingAddDate=now
        )
        self.db.session.add(new_app)
        self.db.session.commit()
        route = f"/delete_application/{new_app.ID}"
        response = self._get_test_handler(route)
        match = _three_o_two_handler(response.headers, '/all_applications')
        assert response.status_code == 302
        assert match

    def test_all_application_benchmarks_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/all_application_benchmarks/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_application_benchmarks_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/all_application_benchmarks/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'AssessmentBenchmarks.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_benchmark_assessments_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/benchmark_assessments/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_benchmark_assessments_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/benchmark_assessments/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'AssessmentBenchmarkAssessments.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_assessment_results_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/assessment_results/{app.ID}/1"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_add_benchmark_note_post(self):
        route = "/add_benchmark_note"
        data_dict = {
            'app_id': 1,
            'rule_id': 1,
            'note': 'This is a sample benchmark note',
            'add_date': datetime.utcnow(),
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_delete_benchmark_note_post(self):
        route = "/delete_benchmark_note"
        data_dict = {
            'note_id': 1,
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_pipelines_get(self):
        route = "/all_pipelines"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_open_findings_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/open_findings/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_open_findings_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/open_findings/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.VulnerabilityID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_open_findings_export_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/open_findings/{app.ID}/export"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_open_findings_csv_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/open_findings/{app.ID}/csv"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_open_findings_for_scan_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        scan = VulnerabilityScans.query.filter_by(ScanName='Unit Test').first()
        route = f"/open_findings_for_scan/{app.ID}/{scan.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.VulnerabilityID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_open_findings_for_scan_export_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        scan = VulnerabilityScans.query.filter_by(ScanName='Unit Test').first()
        route = f"/open_findings_for_scan/{app.ID}/{scan.ID}/export"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_open_findings_for_scan_csv_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        scan = VulnerabilityScans.query.filter_by(ScanName='Unit Test').first()
        route = f"/open_findings_for_scan/{app.ID}/{scan.ID}/csv"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_finding_request_review_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        finding = Vulnerabilities.query.filter_by(VulnerabilityName='Test for Unit Test').first()
        route = f"/finding/{app.ID}/{finding.VulnerabilityID}/request_review"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_finding_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        finding = Vulnerabilities.query.filter_by(VulnerabilityName='Test for Unit Test').first()
        route = f"/finding/{app.ID}/{finding.VulnerabilityID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_filtered_findings_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/filtered_findings/{app.ID}/Severity/High"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_filtered_findings_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/filtered_findings/{app.ID}/Severity/High"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.VulnerabilityID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_filtered_findings_export_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/filtered_findings/{app.ID}/Severity/High/export"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_filtered_findings_csv_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/filtered_findings/{app.ID}/Severity/High/csv"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_add_issue_dispo_post(self):
        route = "/add_issue_dispo"
        data_dict = {
            'dispo': 'Open-SecReview',
            'issue_id': 1,
            'peerReviewOption': 'Need Help',
            'peerReviewNote': 'This is a test note'
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_add_issue_note_post(self):
        route = "/add_issue_note"
        data_dict = {
            'note_val': 'This is a test note',
            'issue_id': 1,
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_delete_issue_note_post(self):
        route = "/delete_issue_note"
        data_dict = {
            'issue_id': 1,
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_application_endpoints_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/application_endpoints/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_application_endpoints_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/application_endpoints/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.VulnerabilityID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_add_integration_get(self):
        route = f"/add_integration"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_add_integration_post(self):
        route = f"/add_integration"
        data_dict = {
            'name': 'Test Integration',
            'description': 'This is a test integration',
            'url': 'http://acme.com',
            'tool_type': 'Jenkins',
            'authentication_type': 'Password',
            'extras': '',
            'username': 'TestUser',
            'password': 'TestPW',
        }
        response = self._post_test_handler(route, data_dict)
        match = _three_o_two_handler(response.headers, '/all_integrations')
        assert response.status_code == 302
        assert response.headers['Location'].startswith('/all_integrations')

    def test_all_integrations_get(self):
        route = f"/all_integrations"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_validate_integration_post(self):
        route = f"/validate_integration"
        data_dict = {
            'tool_type': 'Jenkins',
            'project_key': 'TEST',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_add_app_integration_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/add_app_integration/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_submit_app_integration_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/submit_app_integration/{app.ID}"
        data_dict = {
            'tool_type': '1',
            'project_key': 'TEST',
        }
        response = self._post_test_handler(route, data_dict)
        match = _three_o_two_handler(response.headers, '/all_app_integrations/1')
        assert response.status_code == 302
        assert match

    def test_all_app_integrations_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/all_app_integrations/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_application_metrics_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/metrics/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_pipeline_jobs_get(self):
        route = f"/all_pipeline_jobs"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_pipeline_jobs_post(self):
        route = f"/all_pipeline_jobs"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'PipelineJobs.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_pipeline_jobs_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/pipeline_jobs/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_pipeline_jobs_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/pipeline_jobs/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'PipelineJobs.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_add_cicd_pipeline_stage_get(self):
        route = f"/add_cicd_pipeline_stage"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_get_cicd_pipeline_stage_data_post(self):
        route = f"/get_cicd_pipeline_stage_data"
        data_dict = {
            'platform': 'Jenkins',
            'stage': 'Secret Scanning',
            'vendor': 'Trufflehog',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_regulations_get(self):
        route = f"/all_regulations"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_securitygatescorecard_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/securitygatescorecard/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_edit_application_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/edit_application/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_edit_application_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName='New App').first()
        route = f"/edit_application/{app.ID}"
        data_dict = {
            'name': 'New App',
            'description': 'This is a new app created for Unit Testing',
            'business_criticality': 'High',
            'initial_version': '1',
            'data_types': 'PHI',
            'platform': 'Web',
            'internet_accessible': 'on',
            'repo_url': 'https://github.com/NewApp',
            'prod_type': 'Marketing',
            'lifecycle': 'Pre-Prod',
            'origin': 'Developed In-House',
            'user_records': 25,
            'revenue': 100,
            'sla_configuration': 1,
            'regulations': 1,
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_contacts_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/contacts/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_add_contact_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/add_contact/{app.ID}"
        data_dict = {
            'role': 'Dev Manager',
            'name': 'John Doe',
            'uniqueid': '1',
            'email': 'john.doe@acme.com',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_delete_contact_post(self):
        route = f"/delete_contact"
        data_dict = {
            'contact_id': 1,
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_vulnerability_scans_get(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/vulnerability_scans/{app.ID}"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_vulnerability_scans_post(self):
        app = BusinessApplications.query.filter_by(ApplicationName=TEST_APP_NAME).first()
        route = f"/vulnerability_scans/{app.ID}"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'VulnerabilityScans.ID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_vulnerabilities_get(self):
        route = f"/all_vulnerabilities"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_vulnerabilities_post(self):
        route = f"/all_vulnerabilities"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.VulnerabilityID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_vulnerabilities_export_get(self):
        route = f"/all_vulnerabilities/export"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_vulnerabilities_export_post(self):
        route = f"/all_vulnerabilities/export"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.VulnerabilityID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_vulnerabilities_csv_get(self):
        route = f"/all_vulnerabilities/csv"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_vulnerabilities_csv_post(self):
        route = f"/all_vulnerabilities/csv"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.VulnerabilityID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_vulnerabilities_filtered_get(self):
        route = f"/all_vulnerabilities_filtered/Severity/High"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_vulnerabilities_filtered_post(self):
        route = f"/all_vulnerabilities_filtered/Severity/High"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.VulnerabilityID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_vulnerabilities_filtered_export_get(self):
        route = f"/all_vulnerabilities_filtered/Severity/High/export"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_vulnerabilities_filtered_export_post(self):
        route = f"/all_vulnerabilities_filtered/Severity/High/export"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.VulnerabilityID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_vulnerabilities_filtered_csv_get(self):
        route = f"/all_vulnerabilities_filtered/Severity/High/csv"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_vulnerabilities_filtered_csv_post(self):
        route = f"/all_vulnerabilities_filtered/Severity/High/csv"
        data_dict = {
            'field_name': None,
            'new_dir': 'desc',
            'cur_page': '1',
            'new_page': '1',
            'cur_per_page': '25',
            'new_per_page': '25',
            'cur_orderby': 'Vulnerabilities.VulnerabilityID desc',
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_add_application_environment_post(self):
        route = f"/add_application_environment/1"
        data_dict = {
            'AppID': 1,
            'EnvironmentName': "Test",
            'EnvironmentClassification': "Test",
            'Status': "Active",
            'ImplementsWebApp': "Yes",
            'ImplementsAPI': "Yes",
            'PublicFacingWebApp': "Yes",
            'PublicFacingAPI': "Yes",
            'WebURL': "https://www.acme.com",
            'OpenAPISpecURL': "https://www.acme.com/openapi.yaml",
            'AuthType': "Basic",
            'TestUsername': "JohnDoe",
            'TestPasswordReference': "AzureKeyVaultRef",
        }
        response = self._post_test_handler(route, data_dict)
        match = _three_o_two_handler(response.headers, '/all_application_environments')
        assert response.status_code == 302
        assert response.headers['Location'].startswith('/all_application_environments')

    def test_add_application_environment_get(self):
        route = f"/add_application_environment/1"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_all_application_environments_get(self):
        route = f"/all_application_environments/1"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_remove_application_environment_post(self):
        route = f"/remove_application_environment"
        data_dict = {
            'env_id': 1
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_edit_application_environment_get(self):
        route = f"/edit_application_environment/1/1"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_edit_application_environment_post(self):
        route = f"/edit_application_environment/1/1"
        data_dict = {
            'AppID': 1,
            'EnvironmentName': "Staging",
            'EnvironmentClassification': "Staging",
            'Status': "Active",
            'ImplementsWebApp': "Yes",
            'ImplementsAPI': "Yes",
            'PublicFacingWebApp': "Yes",
            'PublicFacingAPI': "Yes",
            'WebURL': "https://www.acme.com",
            'OpenAPISpecURL': "https://www.acme.com/openapi.yaml",
            'AuthType': "Basic",
            'TestUsername': "JohnDoe",
            'TestPasswordReference': "AzureKeyVaultRef",
        }
        response = self._post_test_handler(route, data_dict)
        assert response.status_code == 200

    def test_all_application_metrics_get(self):
        route = f"/all_application_metrics"
        response = self._get_test_handler(route)
        assert response.status_code == 200

    def test_application_profile_get(self):
        route = f"/application_profile/1"
        response = self._get_test_handler(route)
        assert response.status_code == 200


def _three_o_two_handler(headers, target):
    match = False
    cur_page = headers['Location']
    if cur_page == target:
        match = True
    return match
