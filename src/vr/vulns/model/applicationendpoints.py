import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class ApplicationEndpoints(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'ApplicationEndpoints'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    AssetID = db.Column(db.Integer, db.ForeignKey('IPAssets.ID', ondelete='CASCADE'))
    Endpoint = db.Column(db.String(5000))
    Type = db.Column(db.String(30))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<ApplicationEndpoints(name={self.AddDate!r})>'.format(self=self)


class ApplicationEndpointsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    ApplicationID = fields.Int()
    AssetID = fields.Int()
    Endpoint = fields.Str()
    Type = fields.Str()


class MakeApplicationEndpointsSchema(ApplicationEndpointsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return ApplicationEndpoints(**data)



