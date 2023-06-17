import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class AppIntegrations(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AppIntegrations'
    ID = db.Column(db.Integer, primary_key=True)
    AppID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    IntegrationID = db.Column(db.Integer, db.ForeignKey('Integrations.ID', ondelete='CASCADE'))
    Type = db.Column(db.String(100))
    AppEntity = db.Column(db.String(100))

    def __init__(self, AppID=None, IntegrationID=None, Type=None, AppEntity=None, ID=None):
        if ID:
            self.ID = ID
        if AppID:
            self.AppID = AppID
        if IntegrationID:
            self.IntegrationID = IntegrationID
        if Type:
            self.Type = Type
        if AppEntity:
            self.AppEntity = AppEntity

    def __repr__(self):
        return '<AppIntegrations(name={self.AppID!r})>'.format(self=self)

class AppIntegrationsSchema(Schema):
    ID = fields.Int()
    AppID = fields.Int()
    IntegrationID = fields.Int()
    Type = fields.String()
    AppEntity = fields.String()

class MakeAppIntegrationsSchema(AppIntegrationsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AppIntegrations(**data)


