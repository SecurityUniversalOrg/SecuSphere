from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class AppToServersAndClusters(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AppToServersAndClusters'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    SoxCriticalDependency = db.Column(db.Integer)
    DrCriticalDependency = db.Column(db.Integer)
    EnvAssociation = db.Column(db.String(30))
    ServerID = db.Column(db.Integer, db.ForeignKey('IPAssets.ID', ondelete='CASCADE'))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AppToServersAndClusters(name={self.AddDate!r})>'.format(self=self)


class AppToServersAndClustersSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    ApplicationID = fields.Int()
    SoxCriticalDependency = fields.Int()
    DrCriticalDependency = fields.Int()
    EnvAssociation = fields.Str()
    ServerID = fields.Int()


class MakeAppToServersAndClustersSchema(AppToServersAndClustersSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AppToServersAndClusters(**data)



