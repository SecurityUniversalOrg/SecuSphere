import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class CICDPipelines(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'CICDPipelines'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    IntegrationID = db.Column(db.Integer, db.ForeignKey('Integrations.ID', ondelete='CASCADE'))
    Name = db.Column(db.String(500))
    Description = db.Column(LONGTEXT)
    Url = db.Column(db.String(500))
    Source = db.Column(db.String(100))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<CICDPipelines(name={self.AddDate!r})>'.format(self=self)


class CICDPipelinesSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    ApplicationID = fields.Int()
    IntegrationID = fields.Int()
    Name = fields.Str()
    Description = fields.Str()
    Url = fields.Str()
    Source = fields.Str()


class MakeCICDPipelinesSchema(CICDPipelinesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return CICDPipelines(**data)



