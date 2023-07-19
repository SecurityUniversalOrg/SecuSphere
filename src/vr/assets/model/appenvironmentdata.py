from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class AppEnvironmentData(db.Model):
    __tablename__ = 'AppEnvironmentData'
    __table_args__ = {'extend_existing': True}
    ID = db.Column(db.Integer, primary_key=True)
    AppID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    EnvironmentName = db.Column(db.String(100))
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    EnvironmentClassification = db.Column(db.String(100))
    Status = db.Column(db.String(20))
    ImplementsWebApp = db.Column(db.String(1))
    ImplementsAPI = db.Column(db.String(1))
    PublicFacingWebApp = db.Column(db.String(1))
    PublicFacingAPI = db.Column(db.String(1))
    WebURL = db.Column(db.String(500))
    OpenAPISpecURL = db.Column(db.String(500))
    AuthType = db.Column(db.String(100))
    TestUsername = db.Column(db.String(200))
    TestPasswordReference = db.Column(db.String(200))

    def __init__(self, AppID=None, EnvironmentName=None, AddDate=None, EnvironmentClassification=None, Status=None,
                 ImplementsWebApp=None, ImplementsAPI=None, PublicFacingWebApp=None, PublicFacingAPI=None,
                 WebURL=None, OpenAPISpecURL=None, AuthType=None, TestUsername=None, TestPasswordReference=None,
                 ID=None):
        if ID:
            self.ID = ID
        if AppID:
            self.AppID = AppID
        if EnvironmentName:
            self.EnvironmentName = EnvironmentName
        if AddDate:
            self.AddDate = AddDate
        if EnvironmentClassification:
            self.EnvironmentClassification = EnvironmentClassification
        if ImplementsWebApp:
            self.ImplementsWebApp = ImplementsWebApp
        if ImplementsAPI:
            self.ImplementsAPI = ImplementsAPI
        if PublicFacingWebApp:
            self.PublicFacingWebApp = PublicFacingWebApp
        if PublicFacingAPI:
            self.PublicFacingAPI = PublicFacingAPI
        if Status:
            self.Status = Status
        if WebURL:
            self.WebURL = WebURL
        if OpenAPISpecURL:
            self.OpenAPISpecURL = OpenAPISpecURL
        if AuthType:
            self.AuthType = AuthType
        if TestUsername:
            self.TestUsername = TestUsername
        if TestPasswordReference:
            self.TestPasswordReference = TestPasswordReference

    def __repr__(self):
        return '<AppEnvironmentData(name={self.AppID!r})>'.format(self=self)

class AppEnvironmentDataSchema(Schema):
    ID = fields.Int()
    AppID = fields.Int()
    EnvironmentName = fields.Str()
    AddDate = fields.Date()
    EnvironmentClassification = fields.Str()
    Status = fields.Str()
    ImplementsWebApp = fields.Str()
    ImplementsAPI = fields.Str()
    PublicFacingWebApp = fields.Str()
    PublicFacingAPI = fields.Str()
    WebURL = fields.Str()
    OpenAPISpecURL = fields.Str()
    AuthType = fields.Str()
    TestUsername = fields.Str()
    TestPasswordReference = fields.Str()

class MakeAppEnvironmentDataSchema(AppEnvironmentDataSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AppEnvironmentData(**data)


