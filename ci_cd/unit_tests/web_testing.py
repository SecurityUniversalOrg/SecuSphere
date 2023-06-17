import unittest
from flask import current_app
from vr import app


class TestWebApp(unittest.TestCase):
    def setUp(self):
        # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
        app.secret_key = 'secret_key'
        self.app = app
        self.app.config['WTF_CSRF_ENABLED'] = False  # no CSRF during tests
        self.appctx = self.app.app_context()
        self.appctx.push()
        self.client = self.app.test_client()


    def tearDown(self):
        self.appctx.pop()
        self.app = None
        self.appctx = None
        self.client = None


    def login(self):
        self.client.post('/login', data={
            'login[username]': 'brian.kaiser',
            'login[password]': 'Nbal!ve1!',
        })


    def test_app(self):
        assert self.app is not None
        assert current_app == self.app





    def test_logout(self):
        self.login()
        response = self.client.get('/logout')
        assert response.status_code == 302
        assert response.location.replace('http://localhost', '').startswith('/login')