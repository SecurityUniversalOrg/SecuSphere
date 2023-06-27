import unittest
import base64
import os
from flask import current_app
from flask_login import current_user
from vr import app, db
from vr.admin.models import User, Messages


ADMIN_USER =

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


    def _login(self):
        response = self.client.post('/login', data={
            'login[username]': 'brian.kaiser',
            'login[password]': 'Nbal!ve1!',
        })
        return response

    def _logout(self):
        response = self.client.get('/logout')
        return response

    def test_app(self):
        assert self.app is not None
        assert current_app == self.app

    def test_register_submit_post(self):
        route = "/register_submit"
        data_dict = {
            'firstname': 'testadmin',
            'lastname': 'user',
            'psw': 'Test1234!',
            'email': 'testadmin.user@acme.com',
        }
        response = self._post_test_no_login_handler(route, data_dict)
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
        email = 'Brian@jbfinegoods.com'
        response = self.client.post('/forgotun', data={
            'email': email,
        }, follow_redirects=True)
        print(f'Testing: /forgotun.....Response: {response.status_code}   Path: {response.request.path}', flush=True)
        assert response.status_code == 200
        user = User.query.filter_by(email=email).first()
        response = self.client.get(f'/displayun/{user.get_id()}/{user.get_username_token()}')
        assert response.status_code == 200

    def test_pw_reset(self):
        email = 'Brian@jbfinegoods.com'
        new_pw = 'Nbal!ve1!'
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
            'login[username]': 'brian.kaiser',
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
            'first_name': 'brian',
            'last_name': 'kaiser',
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

    def test_create_client_post(self):
        route = "/create_client"
        data_dict = {
            'client_name': 'Test',
            'read:vulnerabilities': 'on',
            'write:vulnerabilities': 'on',
        }
        response = self._post_test_handler(route, data_dict)
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
            SenderUserId = 1,
            ReceiverUserId = 1,
            MessageType = 'Test',
            EntityType = 'Application',
            EntityID = 1,
            Message = 'This is a test message for Unit Testing'
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

    def test_register_get(self):
        route = "/register"
        response = self._get_test_handler(route)
        match = _three_o_two_handler(response.headers, '/all_applications')
        assert response.status_code == 302
        assert match




    def test_register_user_get(self):
        otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        new_user = User(
            username='test.user',
            email='test.user@acme.com',
            first_name='test',
            last_name='user',
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
        self.db.session.delete(new_user)
        self.db.session.commit()
        assert response.status_code == 200

    def test_register_user_submit_post(self):
        route = "/register_user_submit"
        data_dict = {
            'psw': 'Test1234!',
            'email': 'test.user@acme.com',
        }
        response = self._post_test_no_login_handler(route, data_dict)
        assert response.status_code == 200

    def test_qrcode_get(self):
        route = "/qrcode"
        response = self._get_test_handler(route)
        assert response.status_code == 200




def _three_o_two_handler(headers, target):
    match = False
    cur_page = headers['Location']
    if cur_page == target:
        match = True
    return match
