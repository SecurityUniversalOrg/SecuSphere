import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class Integrations(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'Integrations'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    Name = db.Column(db.String(500))
    Description = db.Column(LONGTEXT)
    Url = db.Column(db.String(500))
    ToolType = db.Column(db.String(100))
    AuthenticationType = db.Column(db.String(100))
    Extras = db.Column(db.String(5000))
    Username = db.Column(db.String(2000))
    Password = db.Column(db.String(1000))
    KeyName = db.Column(db.String(100))
    SSHKey = db.Column(LONGTEXT)
    APIKey = db.Column(LONGTEXT)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<Integrations(name={self.AddDate!r})>'.format(self=self)


class IntegrationsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    Name = fields.Str()
    Description = fields.Str()
    Url = fields.Str()
    ToolType = fields.Str()
    AuthenticationType = fields.Str()
    Extras = fields.Str()
    Username = fields.Str()
    Password = fields.Str()
    KeyName = fields.Str()
    SSHKey = fields.Str()
    APIKey = fields.Str()


class MakeIntegrationsSchema(IntegrationsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return Integrations(**data)



